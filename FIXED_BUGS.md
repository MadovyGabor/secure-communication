# Resolved Bugs & Technical Refactoring

This document is a detailed historical record of the 21 critical network, concurrency and
cryptographic bugs that Gabriel Madový identified and fixed during the post-project refactoring of
this course project. For each bug it lists the symptom, the root cause, the commit with the fix and
the test that guards against a regression. The project overview is in [README.md](README.md).

Root cause line numbers refer to the file as it was just before the fix commit (see `git log main`).
Test names are classes and methods in `Test/`.

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
