"""
server.py - Encrypted Chat Server

Architecture:
  - One thread per connected client
  - RSA-2048 key exchange on connect (RSA_AES mode)
  - OR shared Fernet key via passphrase (FERNET mode)
  - bcrypt username/password authentication
  - Broadcasts encrypted messages to all other connected clients
  - Routes FILE_HEADER and FILE_CHUNK packets directly to named recipients
  - Logs all session events

Usage:
  python server.py                         # RSA+AES mode, port 9999
  python server.py --mode fernet           # Fernet mode
  python server.py --port 8888             # custom port
  python server.py --passphrase secret123  # Fernet shared passphrase
"""

import socket
import threading
import argparse
import base64
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console

from models import Packet, MsgType, CryptoMode, read_packet
from auth.auth_manager import AuthManager
from utils.logger import ChatLogger

console = Console()


class ClientSession:
    """Represents one connected client."""

    def __init__(self, conn: socket.socket, addr, username: str,
                 cipher, session_id: str):
        self.conn       = conn
        self.addr       = addr
        self.username   = username
        self.cipher     = cipher
        self.session_id = session_id
        self.logger     = ChatLogger(f"server_{session_id}", cipher)

    def send(self, pkt: Packet):
        try:
            self.conn.sendall(pkt.to_bytes())
        except Exception:
            pass

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
        self.logger.close()


class ChatServer:
    """Multi-client encrypted chat server."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999,
                 mode: CryptoMode = CryptoMode.RSA_AES,
                 passphrase: str = None):
        self.host       = host
        self.port       = port
        self.mode       = mode
        self.passphrase = passphrase

        self.auth       = AuthManager()
        self._clients: dict = {}   # username → ClientSession
        self._lock      = threading.Lock()

        # Server RSA keys (RSA_AES mode)
        self._private_key = None
        self._public_key  = None

        if mode == CryptoMode.RSA_AES:
            from crypto.rsa_aes_crypto import generate_rsa_keypair
            self._private_key, self._public_key = generate_rsa_keypair()
            console.print("[bold green]RSA-2048 keypair generated.[/bold green]")

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # ── Server lifecycle ──────────────────────────────────────────────

    def start(self):
        self._sock.bind((self.host, self.port))
        self._sock.listen(10)

        console.print(f"\n[bold cyan]Encrypted Chat Server[/bold cyan]")
        console.print(f"  [bold]Mode:[/bold]    {self.mode.value.upper()}")
        console.print(f"  [bold]Listening:[/bold] {self.host}:{self.port}")
        console.print(f"  [bold]Auth DB:[/bold]   {self.auth.db_path}")
        console.print(f"  [bold]Users:[/bold]     {', '.join(self.auth.list_users())}")
        console.print("\n[dim]Waiting for connections... (Ctrl+C to stop)[/dim]\n")

        try:
            while True:
                conn, addr = self._sock.accept()
                thread = threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Server shutting down.[/bold yellow]")
        finally:
            self._sock.close()

    # ── Client handler (runs in its own thread) ───────────────────────

    def _handle_client(self, conn: socket.socket, addr):
        console.print(f"[dim]Connection from {addr}[/dim]")
        cipher   = None
        session  = None

        try:
            # ── Step 1: Key exchange ──────────────────────────────────
            cipher = self._handshake(conn, addr)
            if cipher is None:
                conn.close()
                return

            # ── Step 2: Authentication ────────────────────────────────
            username = self._authenticate(conn, cipher)
            if username is None:
                conn.close()
                return

            # ── Step 3: Register session ──────────────────────────────
            session_id = f"{username}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            session    = ClientSession(conn, addr, username, cipher, session_id)

            with self._lock:
                # Kick any existing session for this user
                if username in self._clients:
                    old = self._clients[username]
                    old.send(Packet(MsgType.SYSTEM.value, "SERVER",
                                    payload="Your account connected from another location."))
                    old.close()
                self._clients[username] = session

            console.print(f"[bold green]+[/bold green] {username} joined ({addr})")
            self._broadcast_system(f"{username} has joined the chat.", exclude=username)

            # ── Step 4: Message loop ──────────────────────────────────
            self._message_loop(session)

        except Exception as e:
            console.print(f"[red]Client error ({addr}): {e}[/red]")
        finally:
            if session:
                with self._lock:
                    self._clients.pop(session.username, None)
                console.print(f"[bold red]-[/bold red] {session.username} left")
                self._broadcast_system(f"{session.username} has left the chat.")
                session.close()
            else:
                conn.close()

    # ── Handshake (key exchange) ──────────────────────────────────────

    def _handshake(self, conn, addr):
        """
        RSA_AES: Exchange RSA public keys → server sends AES session key (RSA-encrypted)
        FERNET:  Server sends Fernet key encrypted (or passphrase-derived, no exchange needed)
        """
        if self.mode == CryptoMode.FERNET:
            return self._handshake_fernet(conn)
        else:
            return self._handshake_rsa_aes(conn)

    def _handshake_fernet(self, conn):
        from crypto.fernet_crypto import FernetCrypto

        if self.passphrase:
            cipher = FernetCrypto(passphrase=self.passphrase)
            # Send a signal so client uses same passphrase
            pkt = Packet(MsgType.KEY_EXCHANGE.value, "SERVER",
                         extra={"mode": "passphrase"})
        else:
            cipher = FernetCrypto()
            key_b64 = base64.b64encode(cipher.key).decode()
            pkt = Packet(MsgType.KEY_EXCHANGE.value, "SERVER",
                         payload=key_b64, extra={"mode": "key"})

        conn.sendall(pkt.to_bytes())
        return cipher

    def _handshake_rsa_aes(self, conn):
        from crypto.rsa_aes_crypto import (
            serialize_public_key, deserialize_public_key,
            generate_aes_key, rsa_encrypt, AESCipher
        )

        # Send server public key
        server_pub_pem = serialize_public_key(self._public_key)
        conn.sendall(Packet(
            MsgType.KEY_EXCHANGE.value, "SERVER",
            payload=server_pub_pem, extra={"mode": "rsa_aes"}
        ).to_bytes())

        # Receive client public key
        pkt = read_packet(conn)
        if not pkt or pkt.type != MsgType.KEY_EXCHANGE.value:
            return None
        client_pub = deserialize_public_key(pkt.payload)

        # Generate AES session key, encrypt with client's RSA public key
        aes_key = generate_aes_key()
        enc_key = rsa_encrypt(client_pub, aes_key)
        enc_b64 = base64.b64encode(enc_key).decode()

        conn.sendall(Packet(
            MsgType.SESSION_KEY.value, "SERVER",
            payload=enc_b64
        ).to_bytes())

        return AESCipher(aes_key)

    # ── Authentication ────────────────────────────────────────────────

    def _authenticate(self, conn, cipher) -> str:
        """Return username on success, None on failure."""
        for attempt in range(3):
            pkt = read_packet(conn)
            if not pkt or pkt.type != MsgType.AUTH_REQUEST.value:
                return None

            try:
                decrypted = cipher.decrypt(pkt.payload)
                creds     = json.loads(decrypted)
                username  = creds["username"]
                password  = creds["password"]
            except Exception:
                conn.sendall(Packet(
                    MsgType.AUTH_RESPONSE.value, "SERVER",
                    extra={"ok": False, "msg": "Malformed credentials."}
                ).to_bytes())
                continue

            ok, msg = self.auth.authenticate(username, password)
            conn.sendall(Packet(
                MsgType.AUTH_RESPONSE.value, "SERVER",
                extra={"ok": ok, "msg": msg}
            ).to_bytes())

            if ok:
                return username

        return None

    # ── Message loop ──────────────────────────────────────────────────

    def _message_loop(self, session: ClientSession):
        file_receiver_map = {}   # sender → (expecting_chunks, header_pkt)

        while True:
            pkt = read_packet(session.conn)
            if pkt is None:
                break

            if pkt.type == MsgType.DISCONNECT.value:
                break

            elif pkt.type == MsgType.PING.value:
                session.send(Packet(MsgType.PONG.value, "SERVER"))

            elif pkt.type == MsgType.MESSAGE.value:
                # Decrypt, log, re-encrypt for each recipient and broadcast
                try:
                    plaintext = session.cipher.decrypt(pkt.payload)
                    session.logger.log(session.username, plaintext)
                    console.print(
                        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim] "
                        f"[cyan]{session.username}:[/cyan] {plaintext[:80]}"
                    )
                except Exception:
                    plaintext = "[decryption error]"

                # Forward encrypted message to all other clients
                with self._lock:
                    others = {u: s for u, s in self._clients.items()
                              if u != session.username}

                for other_session in others.values():
                    try:
                        re_enc = other_session.cipher.encrypt(
                            f"{session.username}: {plaintext}"
                        )
                        other_session.send(Packet(
                            MsgType.MESSAGE.value,
                            session.username,
                            payload=re_enc,
                        ))
                    except Exception:
                        pass

            elif pkt.type == MsgType.FILE_HEADER.value:
                # Forward file header to all other clients
                self._broadcast_packet(pkt, exclude=session.username)

            elif pkt.type == MsgType.FILE_CHUNK.value:
                # Forward file chunks to all other clients
                self._broadcast_packet(pkt, exclude=session.username)
                console.print(
                    f"[dim]File chunk {pkt.extra.get('index',0)+1}/"
                    f"{pkt.extra.get('total',1)} from {session.username}[/dim]"
                )

            elif pkt.type == MsgType.SYSTEM.value:
                # Client requesting user list
                if pkt.extra.get("cmd") == "list_users":
                    with self._lock:
                        users = list(self._clients.keys())
                    session.send(Packet(
                        MsgType.SYSTEM.value, "SERVER",
                        extra={"users": users}
                    ))

    # ── Broadcast helpers ─────────────────────────────────────────────

    def _broadcast_system(self, message: str, exclude: str = None):
        with self._lock:
            targets = list(self._clients.values())
        for s in targets:
            if s.username != exclude:
                s.send(Packet(MsgType.SYSTEM.value, "SERVER", payload=message))

    def _broadcast_packet(self, pkt: Packet, exclude: str = None):
        with self._lock:
            targets = list(self._clients.values())
        for s in targets:
            if s.username != exclude:
                s.send(pkt)


# ── Entry point ───────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Encrypted Chat Server")
    p.add_argument("--host",       default="0.0.0.0")
    p.add_argument("--port",       type=int, default=9999)
    p.add_argument("--mode",       choices=["rsa_aes", "fernet"], default="rsa_aes")
    p.add_argument("--passphrase", default=None,
                   help="Shared passphrase for Fernet mode")
    args = p.parse_args()

    mode = CryptoMode.RSA_AES if args.mode == "rsa_aes" else CryptoMode.FERNET

    server = ChatServer(
        host=args.host, port=args.port,
        mode=mode, passphrase=args.passphrase
    )
    server.start()


if __name__ == "__main__":
    main()
