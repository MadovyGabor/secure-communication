# Secure Chat (Zabezpečená komunikace)

A small group-chat program used as a cryptography playground: clients connect to a server and chat,
and a built-in man-in-the-middle (MITM) proxy shows what the protection does and does not stop.

Authors: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384).
Course project for BPC-AKR (Applied Cryptography), FEKT VUT, 2025/2026.

## How the protocol works

| Layer | What the code does |
|---|---|
| Transport | TCP. Every message is sent as a frame with a 4-byte big-endian length prefix (`networkstack.py`). |
| Authentication (secure mode only) | RSA "hash and sign": the SHA-256 digest of a message is signed with the raw RSA private key (`RSA/`). There is no padding scheme (no PSS or PKCS#1). Keys are 1024-bit (`RSA/RSA_Main.py`), with e = 65537. |
| Key exchange | Ephemeral Diffie-Hellman with the fixed RFC 3526 MODP Group 14 (2048-bit prime, g = 2). Public keys must lie in (1, p-1), and a `DH_INIT` with any other group is rejected (`diffieHellman/`). |
| Key derivation | HKDF-SHA256 turns the shared secret into a 32-byte AES-256 key. |
| Encryption | AES-GCM implemented in `GCM/` (GCTR + GHASH on top of AES-ECB from `cryptography`), with a random 12-byte nonce and a 16-byte tag. No associated data is authenticated. |

In **secure mode** (the default) the client and server first exchange RSA public keys (`rsa`), and both
Diffie-Hellman messages are signed. The client rejects an unsigned `DH_ACCEPT` and does not send chat
text until a session key exists.
In **unsecure mode** (`--unsecure`) there is no RSA step, the Diffie-Hellman exchange is not
authenticated, and the MITM proxy can take over the session. That is the point of the demo.

Packet formats (`protocol.py`):

```
RSA_INIT:<e>:<n>                 public RSA key
RSA_AUTH:<message>|<signature>   message signed with the sender's RSA key
DH_INIT:<p>:<g>:<A>              Diffie-Hellman offer
DH_ACCEPT:<B>                    Diffie-Hellman answer
<length:4><nonce:12><tag:16><ciphertext>   encrypted chat message
```

## Requirements

- Python 3.13 (the version the tests were run with)
- the packages in `requirements.txt` (`cryptography`, `sympy`)

```bash
python -m venv .venv
```

Activate it (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on Linux/macOS), then:

```bash
pip install -r requirements.txt
```

## Running the demo

Start each role in its own terminal, from the repository root.

Server (listens on the given address and port):

```bash
python main.py server 127.0.0.1 8000
```

MITM proxy (relays to the server and listens on `127.0.0.1` at the server port + 1, here 8001):

```bash
python main.py attack 127.0.0.1 8000
```

Client connecting directly to the server, or through the proxy. The last argument is an instance
name (default `default`) that selects the client's key files:

```bash
python main.py client 127.0.0.1 8000 alice
```

```bash
python main.py client 127.0.0.1 8001 bob
```

Add `--unsecure` to the server, proxy and client commands for unsecure mode (it may appear anywhere
on the command line). Run `python main.py -h` for the full usage.

### Client commands

| Command | Effect |
|---|---|
| `rsa` | Exchange RSA public keys with the server (secure mode only) |
| `dh` | Run the Diffie-Hellman exchange and derive the AES session key |
| any other text | Send it as a chat message (encrypted once a session key exists) |
| `help` | List the commands |
| `exit` | Disconnect and quit |

### MITM proxy commands

| Command | Effect |
|---|---|
| `attack` | Toggle the active attack: replace both Diffie-Hellman public keys and decrypt, print and re-encrypt all traffic |
| `tamper <text>` | Replace the next intercepted and decrypted message with `<text>` |
| `spoof` | Toggle replacing every relayed message with a fake one |
| `help` | List the commands |
| `exit` | Stop the proxy |

Stop the server with Ctrl+C. Ctrl+C also stops a client or the proxy.

### The four demo scenarios

| Scenario | Steps | Expected outcome |
|---|---|---|
| Secure chat | server; two clients on port 8000; each runs `rsa`, then `dh`; one sends a message | The other client prints `[Message from Server]: <port>: <message>` |
| Unsecure chat | as above with `--unsecure` everywhere and without `rsa` | The message is delivered |
| MITM, unsecure | server and proxy with `--unsecure`; proxy `attack`; two clients on port 8001 with `--unsecure` run `dh` and chat | The message is delivered, and the proxy prints `[MITM] Extracted Plaintext: <message>` |
| MITM, secure | server and proxy in secure mode; proxy `attack`; two clients on port 8001 run `rsa`, then `dh` | The server prints `[Security] HACKER DETECTED! Signature invalid. Dropping packet.`, no session key is derived, and no chat message gets through |

Console output of the program is partly in Czech.

## Key files

Keys are stored as JSON in the **current working directory**:

| File | Content |
|---|---|
| `server_key.json` | The server's RSA key pair, created on first start |
| `<instance>_client_key.json` | The client's RSA key pair, created on the first `rsa` |
| `<instance>_server_key.json` | The server public key the client saw first. A different key later is reported as a possible attack and rejected (trust on first use). |

Private keys are stored unencrypted. The `.gitignore` excludes `*.json`, so never commit them.

## Tests

```bash
python -m unittest discover -s Test -t .
```

The suite has 70 tests: unit tests for framing, packet formats, AES-GCM (including known-answer
vectors), RSA keys, Diffie-Hellman, the CLI, error handling and the secure-mode rules, plus end-to-end
tests that start the server, proxy and clients as subprocesses and run the four demo scenarios on
localhost. A full run takes about 30 seconds.

## Project layout

```
main.py               command-line entry point
client.py             chat client
server.py             chat server
attacker.py           MITM proxy
networkservice.py     shared base class and AES-GCM message helpers
networkstack.py       length-prefixed TCP framing
protocol.py           packet formats
RSA/                  RSA key generation, signing and key files
diffieHellman/        Diffie-Hellman and HKDF
GCM/                  AES-GCM implementation
Test/                 unit and end-to-end tests
```

## Known limitations

- Textbook RSA signatures with 1024-bit keys, and no replay protection. Fine for teaching, not for
  real use.
- The MITM proxy always listens on `127.0.0.1`.
- Key files depend on the working directory: starting from another directory creates a new identity.
