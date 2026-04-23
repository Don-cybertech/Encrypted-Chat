# 🔐 Encrypted Chat Application

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-RSA--2048%20%2B%20AES--256--GCM-green)
![Auth](https://img.shields.io/badge/Auth-bcrypt-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A production-grade, end-to-end encrypted terminal chat application demonstrating real-world applied cryptography: RSA-2048 key exchange, AES-256-GCM message encryption, bcrypt authentication, and encrypted file transfer — all over raw TCP sockets.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔑 **RSA + AES Hybrid Encryption** | RSA-2048 key exchange → AES-256-GCM session encryption (industry standard) |
| 🧂 **Fernet Demo Mode** | AES-128-CBC + HMAC-SHA256 via shared passphrase (great for demos) |
| 🛡️ **bcrypt Authentication** | Passwords hashed with bcrypt (cost factor 12) — never stored in plain text |
| 📎 **Encrypted File Transfer** | Files chunked, AES-encrypted per chunk, SHA-256 verified on receipt |
| 🔍 **Key Fingerprints** | SSH-style fingerprint display — verify no man-in-the-middle attack |
| 📜 **Encrypted Chat History** | Session logs stored encrypted; readable only with session key |
| 👥 **Multi-Client Server** | Concurrent clients supported via threading |
| 🖥️ **Rich CLI Output** | Color-coded terminal interface with timestamps |

---

## 🏗️ Architecture

```
encrypted-chat/
├── server.py               # Multi-client TCP server
├── client.py               # Interactive CLI client
├── models.py               # Wire protocol (length-prefixed JSON packets)
├── crypto/
│   ├── fernet_crypto.py    # AES-128-CBC (Fernet) — demo mode
│   └── rsa_aes_crypto.py   # RSA-2048 + AES-256-GCM — full mode
├── auth/
│   └── auth_manager.py     # bcrypt user authentication
├── transfer/
│   └── file_transfer.py    # Chunked encrypted file transfer
├── utils/
│   ├── display.py          # Rich terminal UI
│   └── logger.py           # Encrypted session logging
├── keys/                   # Runtime: user DB, generated keys
├── chat_logs/              # Runtime: encrypted session logs
└── received_files/         # Runtime: files received from peers
```

### Connection Handshake (RSA+AES Mode)

```
Client                          Server
  |                               |
  |<-- KEY_EXCHANGE (RSA pub) ---|   Server sends its RSA public key
  |--- KEY_EXCHANGE (RSA pub) -->|   Client sends its RSA public key
  |<-- SESSION_KEY (RSA-enc) ----|   Server generates AES-256 key, encrypts with client's RSA key
  |                               |   Both sides now share the AES session key
  |--- AUTH_REQUEST (AES-enc) -->|   Credentials encrypted with AES session key
  |<-- AUTH_RESPONSE ------------|
  |=== Encrypted Chat Begins ====|
```

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server (Terminal 1)

```bash
python server.py
```

### 3. Connect as Alice (Terminal 2)

```bash
python client.py
# Username: alice  Password: alice123
```

### 4. Connect as Bob (Terminal 3)

```bash
python client.py
# Username: bob  Password: bob123
```

**Default demo accounts:** `alice / alice123` · `bob / bob123` · `admin / admin123`

---

## 🔧 Usage

### Server options

```bash
python server.py --mode rsa_aes              # RSA-2048 + AES-256-GCM (default)
python server.py --mode fernet               # Fernet AES-128 (demo)
python server.py --port 8888                 # Custom port
python server.py --mode fernet --passphrase mysecret  # Shared passphrase
```

### Client options

```bash
python client.py --host 192.168.1.10         # Remote server
python client.py --mode fernet --passphrase mysecret
```

### In-chat commands

| Command | Description |
|---|---|
| `/send <filepath>` | Send an encrypted file to all users |
| `/fingerprint` | Display key fingerprint (verify E2E with partner) |
| `/users` | List connected users |
| `/whoami` | Show your session details |
| `/history` | View this session's decrypted chat log |
| `/help` | Show all commands |
| `/quit` | Disconnect |

---

## 🔐 Cryptography Deep Dive

### Why RSA + AES (Hybrid Encryption)?

| Algorithm | Role | Why |
|---|---|---|
| RSA-2048 | Key exchange | Asymmetric — no need to pre-share secrets |
| AES-256-GCM | Message encryption | Fast + authenticated (prevents tampering) |
| bcrypt | Password hashing | Slow by design (resists brute force) |
| SHA-256 | File integrity | Detects corruption or tampering |

**AES-GCM Authenticated Encryption:** Every message is both encrypted *and* authenticated. Any modification to the ciphertext causes decryption to fail — this prevents bit-flipping and replay attacks.

**Key Fingerprints:** After connection, both parties see a SHA-256 fingerprint of the session key. Verbally comparing these fingerprints ensures no man-in-the-middle has intercepted the key exchange.

### Fernet Mode (Demo)

Fernet uses AES-128-CBC + HMAC-SHA256. The key is derived from a shared passphrase via SHA-256. This is simpler but requires the passphrase to be communicated securely out-of-band.

---

## 🛡️ Security Notes

- Passwords are **never logged or stored in plain text** — bcrypt hashes only
- Each session uses a **fresh AES key** — compromise of one session does not affect others
- File transfer includes **SHA-256 integrity verification** — corrupted or tampered files are rejected
- Chat logs are stored **encrypted** — unreadable without the session key

> **Learning project disclaimer:** This demonstrates core cryptographic concepts for portfolio/educational purposes. Production chat systems (Signal, WhatsApp) use more advanced protocols (Double Ratchet, X3DH) for perfect forward secrecy.

---

## 📋 Requirements

- Python 3.8+
- `cryptography` — RSA, AES-GCM, Fernet
- `bcrypt` — password hashing
- `rich` — terminal UI

---

## 👤 Author

**Egwu Donatus Achema**  
Cybersecurity Student | Python Developer  
[GitHub @Don-cybertech](https://github.com/Don-cybertech) · [LinkedIn](https://linkedin.com/in/egwu-donatus-achema-8a9251378/)

---

*Part of my Python Cybersecurity Portfolio — demonstrating hands-on applied cryptography skills.*
