"""
client.py - Encrypted Chat Client

Handles:
  - RSA-2048 key exchange with server
  - bcrypt-authenticated login (credentials encrypted before sending)
  - Sending/receiving encrypted messages
  - Encrypted file transfer (/send <path>)
  - Key fingerprint display (/fingerprint)
  - Chat history (/history)
  - Live message receiving in a background thread

Usage:
  python client.py                              # connect to localhost:9999
  python client.py --host 192.168.1.10          # remote server
  python client.py --mode fernet --passphrase x # Fernet demo mode
"""

import socket
import threading
import argparse
import base64
import json
import sys
from pathlib import Path
from getpass import getpass

from rich.console import Console
from rich.prompt import Prompt

from models import Packet, MsgType, CryptoMode, read_packet
from utils.display import (
    print_banner, print_session_info, print_help,
    fmt_message, fmt_file_event, print_error, print_info
)
from utils.logger import ChatLogger, read_log
from transfer.file_transfer import send_file, FileReceiver

console = Console()


class ChatClient:
    """Encrypted terminal chat client."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9999,
                 mode: CryptoMode = CryptoMode.RSA_AES,
                 passphrase: str = None):
        self.host       = host
        self.port       = port
        self.mode       = mode
        self.passphrase = passphrase

        self.username   = None
        self.cipher     = None
        self.sock       = None
        self.logger     = None
        self._running   = False
        self._file_recv = None   # FileReceiver instance when transfer in progress

        # Client RSA keys (RSA_AES mode only)
        self._private_key = None
        self._public_key  = None

        if mode == CryptoMode.RSA_AES:
            from crypto.rsa_aes_crypto import generate_rsa_keypair
            self._private_key, self._public_key = generate_rsa_keypair()

    # ── Connection ────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Connect, perform key exchange, and authenticate. Returns True on success."""
        print_banner()

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(None)
            console.print(f"[bold green]Connected to[/bold green] {self.host}:{self.port}\n")
        except Exception as e:
            print_error(f"Could not connect: {e}")
            return False

        # Key exchange
        self.cipher = self._handshake()
        if self.cipher is None:
            print_error("Key exchange failed.")
            return False

        # Login
        self.username = self._login()
        if self.username is None:
            return False

        # Setup logger and display session info
        session_id  = f"{self.username}_{self.host}"
        self.logger = ChatLogger(session_id, self.cipher)

        print_session_info(
            username=self.username,
            mode=self.mode.value,
            fingerprint=self.cipher.fingerprint,
            host=self.host,
            port=self.port,
            role="CLIENT",
        )
        print_help()
        return True

    # ── Key exchange ──────────────────────────────────────────────────

    def _handshake(self):
        """Perform key exchange matching the server's mode."""
        pkt = read_packet(self.sock)
        if not pkt or pkt.type != MsgType.KEY_EXCHANGE.value:
            return None

        server_mode = pkt.extra.get("mode", "rsa_aes")

        if server_mode == "passphrase":
            from crypto.fernet_crypto import FernetCrypto
            pp = self.passphrase or Prompt.ask("[bold]Enter shared passphrase[/bold]",
                                               password=True)
            return FernetCrypto(passphrase=pp)

        elif server_mode == "key":
            from crypto.fernet_crypto import FernetCrypto
            key = base64.b64decode(pkt.payload)
            return FernetCrypto(key=key)

        else:  # rsa_aes
            return self._handshake_rsa_aes(pkt)

    def _handshake_rsa_aes(self, server_key_pkt):
        from crypto.rsa_aes_crypto import (
            deserialize_public_key, serialize_public_key,
            rsa_decrypt, AESCipher
        )

        # Receive server public key
        server_pub = deserialize_public_key(server_key_pkt.payload)

        # Send our public key
        my_pub_pem = serialize_public_key(self._public_key)
        self.sock.sendall(Packet(
            MsgType.KEY_EXCHANGE.value, "CLIENT",
            payload=my_pub_pem
        ).to_bytes())

        # Receive AES session key (encrypted with our RSA public key)
        pkt = read_packet(self.sock)
        if not pkt or pkt.type != MsgType.SESSION_KEY.value:
            return None

        enc_aes_key = base64.b64decode(pkt.payload)
        aes_key     = rsa_decrypt(self._private_key, enc_aes_key)
        return AESCipher(aes_key)

    # ── Authentication ────────────────────────────────────────────────

    def _login(self) -> str:
        """Prompt for credentials, send encrypted to server. Returns username or None."""
        console.print("[bold]Login to Encrypted Chat[/bold]")

        for attempt in range(3):
            username = Prompt.ask("  Username").strip().lower()
            password = getpass("  Password: ")

            creds_json = json.dumps({"username": username, "password": password})
            encrypted  = self.cipher.encrypt(creds_json)

            self.sock.sendall(Packet(
                MsgType.AUTH_REQUEST.value, username,
                payload=encrypted
            ).to_bytes())

            resp = read_packet(self.sock)
            if not resp:
                print_error("No response from server.")
                return None

            ok  = resp.extra.get("ok", False)
            msg = resp.extra.get("msg", "")

            if ok:
                console.print(f"[bold green]{msg}[/bold green]\n")
                return username
            else:
                print_error(msg)
                if attempt < 2:
                    console.print("[dim]Try again...[/dim]")

        print_error("Authentication failed after 3 attempts.")
        return None

    # ── Main session ──────────────────────────────────────────────────

    def run(self):
        """Start the receive thread and enter the input loop."""
        self._running = True

        recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        recv_thread.start()

        console.print("[dim]Type a message and press Enter. Type /help for commands.[/dim]\n")

        try:
            self._input_loop()
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self._disconnect()

    def _input_loop(self):
        while self._running:
            try:
                line = input()
            except EOFError:
                break

            if not line.strip():
                continue

            if line.startswith("/"):
                self._handle_command(line.strip())
            else:
                self._send_message(line.strip())

    def _send_message(self, text: str):
        try:
            encrypted = self.cipher.encrypt(text)
            self.sock.sendall(Packet(
                MsgType.MESSAGE.value, self.username,
                payload=encrypted
            ).to_bytes())
            # Echo own message locally
            fmt_message(self.username, text, is_self=True)
            if self.logger:
                self.logger.log(self.username, text)
        except Exception as e:
            print_error(f"Send failed: {e}")

    # ── Commands ──────────────────────────────────────────────────────

    def _handle_command(self, cmd: str):
        parts = cmd.split(maxsplit=1)
        verb  = parts[0].lower()
        arg   = parts[1] if len(parts) > 1 else ""

        if verb == "/quit":
            self._running = False

        elif verb == "/help":
            print_help()

        elif verb == "/fingerprint":
            console.print(
                f"\n[bold]Key Fingerprint:[/bold] "
                f"[bold green]{self.cipher.fingerprint}[/bold green]\n"
                f"[dim]Share verbally with the other party to verify E2E encryption.[/dim]\n"
            )

        elif verb == "/whoami":
            print_session_info(
                self.username, self.mode.value,
                self.cipher.fingerprint, self.host, self.port, "CLIENT"
            )

        elif verb == "/users":
            self.sock.sendall(Packet(
                MsgType.SYSTEM.value, self.username,
                extra={"cmd": "list_users"}
            ).to_bytes())

        elif verb == "/history":
            self._show_history()

        elif verb == "/send":
            if not arg:
                print_error("Usage: /send <filepath>")
            else:
                self._send_file(arg.strip())

        else:
            print_error(f"Unknown command: {verb}. Type /help for commands.")

    def _send_file(self, filepath: str):
        path = Path(filepath)
        if not path.exists():
            print_error(f"File not found: {filepath}")
            return

        size_kb = path.stat().st_size / 1024
        console.print(f"[bold]Sending:[/bold] {path.name} ({size_kb:.1f} KB)...")

        try:
            def progress(pct):
                if pct % 25 == 0:
                    console.print(f"  [dim]Upload: {pct}%[/dim]")

            file_hash = send_file(
                self.sock, path, self.username, self.cipher, progress
            )
            fmt_file_event(self.username, path.name,
                           path.stat().st_size, received=False)
            console.print(f"[dim]SHA-256: {file_hash}[/dim]")

        except Exception as e:
            print_error(f"File send failed: {e}")

    def _show_history(self):
        if not self.logger:
            print_info("No session log available.")
            return

        from utils.logger import read_log
        try:
            entries = read_log(self.logger.path, self.cipher)
            console.print(f"\n[bold]--- Chat History ({len(entries)} entries) ---[/bold]")
            for e in entries[-30:]:   # show last 30
                ts  = e.get("ts", "")[:19].replace("T", " ")
                frm = e.get("from", "?")
                msg = e.get("msg", e.get("raw", ""))
                console.print(f"  [dim]{ts}[/dim] [cyan]{frm}:[/cyan] {msg}")
            console.print("[bold]--- End of History ---[/bold]\n")
        except Exception as e:
            print_error(f"Could not read history: {e}")

    # ── Receive loop (background thread) ─────────────────────────────

    def _receive_loop(self):
        while self._running:
            try:
                pkt = read_packet(self.sock)
                if pkt is None:
                    if self._running:
                        console.print("\n[bold red]Disconnected from server.[/bold red]")
                        self._running = False
                    break

                self._handle_incoming(pkt)

            except Exception as e:
                if self._running:
                    console.print(f"\n[red]Receive error: {e}[/red]")
                break

    def _handle_incoming(self, pkt: Packet):
        if pkt.type == MsgType.MESSAGE.value:
            try:
                text = self.cipher.decrypt(pkt.payload)
                # Strip "sender: " prefix added by server
                if ": " in text:
                    sender, _, message = text.partition(": ")
                else:
                    sender, message = pkt.sender, text
                fmt_message(sender, message, is_self=False)
                if self.logger:
                    self.logger.log(sender, message)
            except Exception:
                fmt_message(pkt.sender, "[encrypted - could not decrypt]")

        elif pkt.type == MsgType.SYSTEM.value:
            if "users" in pkt.extra:
                users = pkt.extra["users"]
                console.print(f"\n[bold]Online users ({len(users)}):[/bold] "
                               f"{', '.join(users)}\n")
            else:
                fmt_message("SERVER", pkt.payload, is_system=True)

        elif pkt.type == MsgType.FILE_HEADER.value:
            self._file_recv = FileReceiver(self.cipher)
            self._file_recv.handle_header(pkt)
            console.print(
                f"\n[bold cyan]Incoming file:[/bold cyan] "
                f"{pkt.extra['filename']} "
                f"({pkt.extra['size']/1024:.1f} KB, "
                f"{pkt.extra['total_chunks']} chunks)"
            )

        elif pkt.type == MsgType.FILE_CHUNK.value:
            if self._file_recv is None:
                return
            try:
                saved = self._file_recv.handle_chunk(pkt)
                if saved:
                    fmt_file_event(
                        pkt.sender,
                        self._file_recv.filename,
                        self._file_recv.expected_size,
                        received=True,
                        saved_path=str(saved),
                    )
                    self._file_recv = None
            except ValueError as e:
                print_error(str(e))
                self._file_recv = None

        elif pkt.type == MsgType.PONG.value:
            pass   # heartbeat response

    # ── Cleanup ───────────────────────────────────────────────────────

    def _disconnect(self):
        self._running = False
        try:
            self.sock.sendall(Packet(MsgType.DISCONNECT.value, self.username).to_bytes())
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        if self.logger:
            self.logger.close()
        console.print("\n[bold yellow]Disconnected. Goodbye![/bold yellow]")


# ── Entry point ───────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Encrypted Chat Client")
    p.add_argument("--host",       default="127.0.0.1")
    p.add_argument("--port",       type=int, default=9999)
    p.add_argument("--mode",       choices=["rsa_aes", "fernet"], default="rsa_aes")
    p.add_argument("--passphrase", default=None)
    args = p.parse_args()

    mode = CryptoMode.RSA_AES if args.mode == "rsa_aes" else CryptoMode.FERNET

    client = ChatClient(
        host=args.host, port=args.port,
        mode=mode, passphrase=args.passphrase
    )

    if client.connect():
        client.run()


if __name__ == "__main__":
    main()
