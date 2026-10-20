# Secure Communication

[![CI](https://github.com/MadovyGabor/secure-comunication/actions/workflows/ci.yml/badge.svg)](https://github.com/MadovyGabor/secure-comunication/actions/workflows/ci.yml)

## About the Project

A small terminal-based group-chat program used as a cryptography playground: clients connect to a
server and chat with end-to-end encryption (E2EE), and a built-in man-in-the-middle (MITM) proxy
shows what the protection does and does not stop.

Course project for BPC-AKR (Applied Cryptography), FEKT VUT, 2025/2026.

## Team Roles

This project started as a four-person university assignment where every team member built a
specific part of the system:

- **Gabriel Madový:** Diffie-Hellman key exchange and HKDF key derivation (`diffieHellman/`).
- **Petr Věříš:** TCP network stack, length-prefixed framing, and the client, server and MITM proxy
  architecture (`networkstack.py`, `networkservice.py`).
- **Donát Szabó:** RSA key generation, signing, verification and JSON key storage (`RSA/`).
- **Oliver Synak:** Symmetric encryption with a custom AES-GCM implementation (`GCM/`).

## How It Works

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

**Usernames.** The chat shows who wrote a message as `[Alice]: Hello!`. A client's TCP port is never
shown. The client's name is also the prefix of its key files. Right after the key exchange the client
sends its name as the first encrypted frame (`NAME:<name>`), so the name never appears in the
plaintext handshake. A client started without a name is shown as `Anonymous#1`, `Anonymous#2`, and
so on, and uses the `default_*` key files. A name is 1 to 32 letters, digits, `_` or `-`; anything
else (spaces, `/`, `.`, `#`, brackets) is refused at startup, which also keeps key files inside the
working directory. If a connected client already uses the name (case-insensitive), the server assigns
`Anonymous#N` instead. The server tells each client which name it got
(`[Server]: You are chatting as Alice.`), and a client keeps its name when it re-keys with `dh`.

Packet formats (`protocol.py`):

```
RSA_INIT:<e>:<n>                 public RSA key
RSA_AUTH:<message>|<signature>   message signed with the sender's RSA key
DH_INIT:<p>:<g>:<A>              Diffie-Hellman offer
DH_ACCEPT:<B>                    Diffie-Hellman answer
<length:4><nonce:12><tag:16><ciphertext>   encrypted chat message
NAME:<username>                  first encrypted message after each DH exchange (empty = anonymous)
```

### Project layout

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
Dockerfile            container image for all three roles
docker-compose.yml    server, attacker and two client services
.github/workflows/ci.yml   GitHub Actions workflow that runs the tests
requirements.txt      Python dependencies
```

## My Post-Project Refactoring & Bug Fixes

After our team finished the university course, I (Gabriel Madový) took the codebase to clean it up and
turn it into a reliable project. With the help of AI tools, I reviewed the entire repository,
refactored its structure, and fixed more than 20 bugs across the networking and cryptography layers.
I built a suite of more than 100 unit and end-to-end tests that run all four demo scenarios
automatically, added a GitHub Actions CI pipeline, and created the Docker and Docker Compose setup so
anyone can run the server, the MITM proxy and two clients in isolated containers. Later I added
usernames instead of TCP ports in the chat, and a structured audit log on the server.

The three most critical bugs I fixed:

- **The server used 100% CPU while idle.** On every loop the server handed every client socket to
  `select` as "writable", even when it had nothing to send. A connected socket is almost always
  writable, so `select` returned immediately and the loop spun without ever waiting. The server now
  asks for writability only when a client has queued data, so an idle server sleeps in `select`.
- **In secure mode the client accepted an unsigned `DH_ACCEPT`.** The client processed the server's
  Diffie-Hellman answer whether or not it arrived inside a valid RSA signature. A MITM attacker could
  send its own unsigned `DH_ACCEPT` and silently take over the session, defeating the whole point of
  secure mode. The client now rejects any `DH_ACCEPT` in secure mode that is not signed by the
  server's key.
- **Chat messages were sent in plaintext before the session key existed.** If the user typed a message
  before finishing the key exchange, the client fell back to sending it unencrypted, so anyone on the
  network could read it. In secure mode the client now refuses to send chat until the AES session key
  is established.

The remaining fixes cover framing errors, locks that were never released, network threads that
crashed on malformed or tampered packets, keys and relays left behind after disconnects, a weak
Diffie-Hellman group an attacker could force, and flaky tests.

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

## Running Manually (Local)

Start each role in its own terminal, from the repository root.

Server (listens on the given address and port):

```bash
python main.py server 127.0.0.1 8000
```

MITM proxy (relays to the server and listens on `127.0.0.1` at the server port + 1, here 8001):

```bash
python main.py attack 127.0.0.1 8000
```

Client connecting directly to the server, or through the proxy. The last argument is the username
shown in the chat, and it also names the client's key files. Without it the server assigns
`Anonymous#N`:

```bash
python main.py client 127.0.0.1 8000 Alice
```

```bash
python main.py client 127.0.0.1 8001 Bob
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

Stop the server with Ctrl+C. Ctrl+C also stops a client or the proxy. Console output of the program
is partly in Czech.

### Key files

Keys are stored as JSON in the **current working directory**:

| File | Content |
|---|---|
| `server_key.json` | The server's RSA key pair, created on first start |
| `<name>_client_key.json` | The client's RSA key pair, created on the first `rsa` (`default_` for an anonymous client) |
| `<name>_server_key.json` | The server public key the client saw first. A different key later is reported as a possible attack and rejected (trust on first use). |

Private keys are stored unencrypted. The `.gitignore` excludes `*.json`, so never commit them.

## Docker & Demo Scenarios

`Dockerfile` and `docker-compose.yml` start the whole demo (server, MITM proxy and two clients) with
one command:

```bash
docker compose up -d --build
```

The compose file defines four services, each taking the same arguments as `python main.py`:

| Service | Command | Notes |
|---|---|---|
| `server` | `server 0.0.0.0 8000` | Keys in the `server-keys` volume. A healthcheck waits until port 8000 is listening. |
| `attacker` | `attack server 8000` | The MITM proxy. It listens on `127.0.0.1:8001` inside its own network namespace. A healthcheck waits until it listens, so the clients never connect too early. |
| `client-alice` | `client 127.0.0.1 8001 Alice` | Shares the attacker's network namespace and chats through the proxy as `Alice`. Keys in the `alice-keys` volume. |
| `client-bob` | `client 127.0.0.1 8001 Bob` | The same as `Alice`, as `Bob`, with keys in the `bob-keys` volume. |

`server` and `attacker` are on an internal network named `chat`, with no ports published to the host.
Because both clients go through the proxy, the server log shows the proxy's IP for both of them.

Watch the server audit log:

```bash
docker compose logs -f server
```

Chat: attach to each client in its own terminal, then type `rsa`, `dh` and a message. Detach with
Ctrl+P, Ctrl+Q; Ctrl+C quits the client. The client prints its prompt when it starts, before you
attach, so type `help` to see the commands.

```bash
docker attach secure-chat-client-alice-1
```

```bash
docker attach secure-chat-client-bob-1
```

To show the MITM attack, attach to the proxy and type `attack`, then run `dh` again in a client:
in secure mode the server logs `HACKER DETECTED` and drops the key exchange.

```bash
docker attach secure-chat-attacker-1
```

A third client can join through the proxy with
`docker compose run --rm client-alice client 127.0.0.1 8001 Carol` (leave the name out to be
`Anonymous#N`, or use `server 8000` to bypass the proxy). For unsecure mode, append `--unsecure` to
the commands in `docker-compose.yml`. Stop everything with `docker compose down`; add `-v` to delete
the key volumes too.

The image runs as a non-root user, and `.dockerignore` keeps key files out of the build context.

### The four demo scenarios

| Scenario | Steps | Expected outcome |
|---|---|---|
| Secure chat | server; two clients on port 8000; each runs `rsa`, then `dh`; one sends a message | The sender gets `[Server]: You are chatting as <name>.` after `dh`; the other client prints `[Message from Server]: [<name>]: <message>` |
| Unsecure chat | as above with `--unsecure` everywhere and without `rsa` | The message is delivered |
| MITM, unsecure | server and proxy with `--unsecure`; proxy `attack`; two clients on port 8001 with `--unsecure` run `dh` and chat | The message is delivered, and the proxy prints `[MITM] Extracted Username: <name>` and `[MITM] Extracted Plaintext: <message>` |
| MITM, secure | server and proxy in secure mode; proxy `attack`; two clients on port 8001 run `rsa`, then `dh` | The server logs `WARNING - HACKER DETECTED! <client>: invalid signature, packet dropped`, no session key is derived, and no chat message gets through |

### Server audit log

The server logs its events through Python's `logging` module to stdout (so `docker compose logs server`
shows them too), in the format `[YYYY-MM-DD HH:MM:SS] LEVEL - message`:

```
[2026-10-20 14:16:24] INFO - Client connected: conn#1 (127.0.0.1)
[2026-10-20 14:16:26] INFO - RSA public key exchange completed with conn#1 (127.0.0.1)
[2026-10-20 14:16:26] INFO - AES session key established with conn#1 (127.0.0.1) (RSA-signed Diffie-Hellman)
[2026-10-20 14:16:26] INFO - conn#1 (127.0.0.1) joined the chat as Alice
[2026-10-20 14:16:27] INFO - Alice -> broadcasted to 1 client
[2026-10-20 14:16:27] INFO - Client disconnected: Alice (conn#1, 127.0.0.1)
```

Each connection is labelled `conn#N` with the client's IP, plus the username once the client has
one; TCP ports are not logged. Security events (`HACKER DETECTED`, failed decryption) are `WARNING`,
malformed packets are `ERROR`. The log never contains chat text or key material.

## Tests & CI

```bash
python -m unittest discover -s Test -t .
```

The suite has 103 tests: unit tests for framing, packet formats, AES-GCM (including known-answer
vectors), RSA keys, Diffie-Hellman, the CLI, error handling, the secure-mode rules, usernames and the
server audit log, plus end-to-end tests that start the server, proxy and clients as subprocesses and
run the demo scenarios on localhost. A full run takes about a minute.

The GitHub Actions workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push
to `main` and on every pull request to `main`. It installs `requirements.txt` on `ubuntu-latest` with
Python 3.13 and runs the same command.

## Known Limitations

- Textbook RSA signatures with 1024-bit keys, and no replay protection. Fine for teaching, not for
  real use.
- The MITM proxy always listens on `127.0.0.1`.
- Key files depend on the working directory: starting from another directory creates a new identity.
- The server does not tie a username to the client's RSA key or remember it between sessions: any
  client can take a name that is free at the moment. All anonymous clients on one machine share the
  `default_*` key files.
