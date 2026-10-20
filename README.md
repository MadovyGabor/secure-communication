# Secure Chat (Zabezpečená komunikace)

A small group-chat program used as a cryptography playground: clients connect to a server and chat,
and a built-in man-in-the-middle (MITM) proxy shows what the protection does and does not stop.

Authors: Gabriel Madový (283573), Petr Věříš (283559), Oliver Synak (281728), Donát Szabó (283384).
Course project for BPC-AKR (Applied Cryptography), FEKT VUT, 2025/2026.

## Quick start

```bash
pip install -r requirements.txt
```

Then, each in its own terminal from the repository root:

```bash
python main.py server 127.0.0.1 8000
```

```bash
python main.py client 127.0.0.1 8000 Alice
```

```bash
python main.py attack 127.0.0.1 8000
```

Run the tests:

```bash
python -m unittest discover -s Test -t .
```

Details for each step follow below.

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

Client connecting directly to the server, or through the proxy. The last argument is the username
shown in the chat, and it also names the client's key files. Without it the server assigns
`Anonymous#N`:

```bash
python main.py client 127.0.0.1 8000 Alice
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
| Secure chat | server; two clients on port 8000; each runs `rsa`, then `dh`; one sends a message | The sender gets `[Server]: You are chatting as <name>.` after `dh`; the other client prints `[Message from Server]: [<name>]: <message>` |
| Unsecure chat | as above with `--unsecure` everywhere and without `rsa` | The message is delivered |
| MITM, unsecure | server and proxy with `--unsecure`; proxy `attack`; two clients on port 8001 with `--unsecure` run `dh` and chat | The message is delivered, and the proxy prints `[MITM] Extracted Username: <name>` and `[MITM] Extracted Plaintext: <message>` |
| MITM, secure | server and proxy in secure mode; proxy `attack`; two clients on port 8001 run `rsa`, then `dh` | The server prints `[Security] HACKER DETECTED! Signature invalid. Dropping packet.`, no session key is derived, and no chat message gets through |

Console output of the program is partly in Czech.

## Docker

`Dockerfile` and `docker-compose.yml` run the demo in containers. Start everything with:

```bash
docker compose up --build
```

The compose file defines three services, each taking the same arguments as `python main.py`:

| Service | Command | Notes |
|---|---|---|
| `server` | `server 0.0.0.0 8000` | Keys in the `server-keys` volume. A healthcheck waits until port 8000 is listening. |
| `attacker` | `attack server 8000` | The MITM proxy. It listens on `127.0.0.1:8001` inside its own network namespace. |
| `client` | `client server 8000 docker` | Shares the attacker's network namespace, so it reaches the server as `server:8000` and the proxy as `127.0.0.1:8001`. Keys in the `client-keys` volume. |

`server` and `attacker` are on an internal network named `chat`. The client and the proxy read
commands from the terminal; attach to them with `docker attach secure-chat-client-1` or
`docker attach secure-chat-attacker-1` (detach with Ctrl+P, Ctrl+Q). For a client that goes through
the proxy, run `docker compose run --rm client client 127.0.0.1 8001 victim`. For unsecure mode,
append `--unsecure` to the commands in `docker-compose.yml`.

The image runs as a non-root user, and `.dockerignore` keeps key files out of the build context.

## Key files

Keys are stored as JSON in the **current working directory**:

| File | Content |
|---|---|
| `server_key.json` | The server's RSA key pair, created on first start |
| `<name>_client_key.json` | The client's RSA key pair, created on the first `rsa` (`default_` for an anonymous client) |
| `<name>_server_key.json` | The server public key the client saw first. A different key later is reported as a possible attack and rejected (trust on first use). |

Private keys are stored unencrypted. The `.gitignore` excludes `*.json`, so never commit them.

## Tests

```bash
python -m unittest discover -s Test -t .
```

The suite has 94 tests: unit tests for framing, packet formats, AES-GCM (including known-answer
vectors), RSA keys, Diffie-Hellman, the CLI, error handling, the secure-mode rules and usernames
(`test_naming.py`), plus end-to-end tests that start the server, proxy and clients as subprocesses and
run the demo scenarios on localhost. A full run takes about a minute.

## CI

[![CI](https://github.com/MadovyGabor/secure-comunication/actions/workflows/ci.yml/badge.svg)](https://github.com/MadovyGabor/secure-comunication/actions/workflows/ci.yml)

The GitHub Actions workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push
to `main` and on every pull request to `main`. It installs `requirements.txt` on `ubuntu-latest` with
Python 3.13 and runs `python -m unittest discover -s Test -t .`.

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
Dockerfile            container image for all three roles
docker-compose.yml    server, attacker and client services
.github/workflows/ci.yml   GitHub Actions workflow that runs the tests
requirements.txt      Python dependencies
```

## Bugs found and fixed

Found while refactoring the original code (see `git log main`). Root cause line numbers refer to the
file as it was just before the fix commit. Test names are classes and methods in `Test/`.

| ID | Symptom | Root cause (file:line) | Fix | Test that covers it |
|---|---|---|---|---|
| B1 | Ctrl+C did not shut the service down | `main.py:9` assigned a local `service`; the handler at `main.py:37` read the global, which stayed `None` | `7be2038` | `test_cli.TestRun.test_keyboard_interrupt_shuts_service_down` |
| B2 | Missing or invalid arguments exited silently with status 0 | `main.py:15-16`, `main.py:20-21`: bare `exit()` | `7be2038` | `test_cli.TestParseArgs.test_invalid_arguments_exit_with_usage` |
| B3 | Server shutdown raised `AttributeError` | `networkstack.py:167` iterated the client dict's keys (ports) and called `.shutdown()` on them | `b0c64b2` | `test_networkstack.TestServerSocket.test_shutdown_closes_all_clients` |
| B4 | A second client with an already registered peer port leaked its socket and ended the select round | `networkstack.py:144-145` returned without closing the accepted connection | `b0c64b2` | no test |
| B5 | One malformed packet (e.g. `RSA_INIT:x`) crashed the server | `networkstack.py:164` caught only `OSError`; parse errors from `Server.receive_handler` (`networkservice.py:232`) escaped | `7edebd5` | `test_error_handling.TestServerSurvivesMalformedPackets.test_secure_server`, `test_unsecure_server` |
| B6 | After a bad packet the client's `exit` command hung | `networkservice.py:137` acquired the lock without `try/finally`; an exception killed the thread with the lock held | `7edebd5` | `test_error_handling.TestClientSurvivesMalformedPackets.test_network_thread_survives_and_releases_lock` |
| B7 | A tampered encrypted frame killed the client's network thread | `networkservice.py:198` did not catch the GCM authentication error | `7edebd5` | `test_error_handling.TestClientSurvivesMalformedPackets.test_tampered_ciphertext_is_dropped` |
| B8 | A `DH_ACCEPT` without a pending exchange raised `TypeError` | `networkservice.py:191` used `self.p`, which is `None` before `dh` | `7edebd5` | `test_error_handling.TestClientSurvivesMalformedPackets.test_stray_dh_accept_is_ignored` |
| B9 | After a client reset its connection, the server stopped accepting new clients | `networkstack.py:87` raised `ConnectionResetError`, the liveness check at `networkstack.py:122` still passed, and `networkstack.py:164` aborted every select round | `7edebd5` | `test_networkstack.TestServerSocket.test_reset_client_is_dropped_and_others_still_accepted` |
| B10 | A corrupted key file crashed with a raw traceback | `RSA/RSA_Math.py:69-74` read the JSON fields unguarded | `7edebd5` | `test_rsa_keys.TestRsaKeyFiles.test_corrupted_key_file_raises_value_error` |
| B11 | In secure mode the client accepted an unsigned `DH_ACCEPT` | `networkservice.py:203` handled `DH_ACCEPT` whether or not it came inside a valid `RSA_AUTH` | `db3c014` | `test_secure_mode.TestSecureClient.test_unsigned_dh_accept_is_rejected` |
| B12 | In secure mode chat was sent in plaintext before a session key existed | `networkservice.py:134-136` fell back to an unencrypted send | `db3c014` | `test_secure_mode.TestSecureClient.test_chat_without_session_key_is_not_sent` |
| B13 | The initiator could force a weak Diffie-Hellman group | `diffieHellman/DHNetwork.py:34-36` used `p` and `g` from the packet without checking them | `db3c014` | `test_secure_mode.TestDHGroupEnforcement.test_non_standard_group_is_rejected` |
| B14 | The server kept a client's keys after it disconnected | `networkservice.py:249-253`: the per-port key maps were never cleared | `cb6cefd` | `test_disconnect.TestServerForgetsClient.test_keys_are_released_on_disconnect` |
| B15 | The proxy kept a relay and its upstream connection after the victim left | `networkservice.py:458` created relays, which were only removed at `networkservice.py:444` when the server side closed | `cb6cefd` | `test_disconnect.TestAttackerDropsRelay.test_relay_closed_when_victim_disconnects` |
| B16 | The server used 100% CPU while idle | `networkstack.py:128` passed every client to `select` as writable, so it returned at once | `ceabd7c` | `test_networkstack.TestServerSocket.test_idle_process_blocks_until_timeout` |
| B17 | A payload of exactly 2^32 bytes raised `OverflowError` | `networkstack.py:30` checked `>` instead of `>=` | `ceabd7c` | `test_networkstack.TestClientSocketFraming.test_send_rejects_oversized_payload` |
| B18 | The DH robustness script always reported FAIL and exited with 0 | `Test/test_dh_robustness.py:26` unpacked three return values into two names; `:34` compared a tuple to bytes | `a36946d` | `test_dh_robustness.TestDHRobustness.test_successful_signed_handshake` |
| B19 | The framing tests failed on Linux | `Test/test_networkstack.py:12` used `socket.socketpair()`, which is AF_UNIX on Linux and has no peer port | `4370052` | the `test_networkstack.TestClientSocketFraming` tests, run on Linux in CI |
| B20 | End-to-end tests failed intermittently with `WinError 10013` | `Test/harness.py:18` picked test ports with `bind(0)` from the ephemeral range | `dabbfc0` | no test |
| B21 | `.dockerignore` did not exclude nested files such as `RSA/__pycache__` | `.dockerignore:2-6`: patterns without `**/` only match at the context root | `5845077` | no test |

## Known limitations

- Textbook RSA signatures with 1024-bit keys, and no replay protection. Fine for teaching, not for
  real use.
- The MITM proxy always listens on `127.0.0.1`.
- Key files depend on the working directory: starting from another directory creates a new identity.
- The server does not tie a username to the client's RSA key or remember it between sessions: any
  client can take a name that is free at the moment. All anonymous clients on one machine share the
  `default_*` key files.

## Team Roles and My Post-Project Refactoring

This project started as a four-person university assignment where every team member built a specific part of the system.

**Original Team Breakdown:**
* **Gabriel Madový (me):** Diffie-Hellman key exchange and HKDF key derivation (`diffieHellman/`).
* **Petr Věříš:** TCP network stack, length-prefixed framing, and the client, server, and MITM proxy architecture (`networkstack.py`, `networkservice.py`).
* **Donát Szabó:** RSA key generation, signing, verification, and JSON key storage (`RSA/`).
* **Oliver Synak:** Symmetric encryption using a custom AES-GCM implementation (`GCM/`).

**My Standalone Improvements and Bug Fixes:**
After our team finished the university course, I took the codebase to clean it up and turn it into a reliable project. With the help of AI tools, I reviewed the entire repository, refactored the structure, and fixed 21 bugs across the networking and cryptography layers.

In the original version, the server used 100% CPU while idle because `select` checked every client socket as writable on each loop. A single malformed packet or a connection reset from a client crashed the server or stopped it from accepting new connections. On the client side, an error during packet processing left a thread lock acquired, which caused the `exit` command to hang. Disconnecting clients also left stale keys on the server and open relay connections on the MITM proxy.

I also fixed several critical security flaws in the protocol logic. Originally, the client accepted unsigned `DH_ACCEPT` packets even in secure mode, and it sent chat messages in plaintext if the user typed before running the key exchange. The Diffie-Hellman handler also accepted any `p` and `g` parameters sent over the network, which allowed an attacker to force a weak group. I updated the code to enforce valid signatures, block unencrypted messages in secure mode, and strictly check the RFC 3526 MODP Group 14 parameters.

To make sure everything works properly, I built a test suite of 70 unit and end-to-end tests that run all four demo scenarios automatically. I also added a GitHub Actions CI pipeline and created the Docker and Docker Compose setup so anyone can run the server, client, and MITM proxy in isolated containers without manual configuration.

**My commit history on `main` (`git log --author="Gabriel Madový"`):**
* **Refactoring and structure:** `c82124f`, `2976803`, `9fdd3d5`, `a2b06a2`, `7bf825b`
* **CLI improvements:** `7be2038`
* **Network and security bug fixes:** `b0c64b2`, `7edebd5`, `db3c014`, `cb6cefd`, `ceabd7c`
* **Unit and end-to-end tests:** `7bb4ce5`, `a36946d`, `03c5fa7`, `4370052`, `dabbfc0`
* **CI and Docker setup:** `a5b5efd`, `99c17c6`, `cc9ca6e`, `c06597a`, `5845077`, `08518a4`, `ff3dae0`
* **Documentation:** `5508034`, `d7bbcf6`, `6e398ef`, `a2d62c4`, `5f5ff7b`
