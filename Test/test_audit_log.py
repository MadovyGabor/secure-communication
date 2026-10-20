"""The server writes an audit log through the logging module: format, events, and no secrets."""
import io
import logging
import re
import unittest

import server
from diffieHellman import DHNetwork
from RSA import RSA_Main, RSA_Math
from server import Server
from Test.test_disconnect import InTempDir, frame, until
from Test.test_naming import RawClient


class TestLogFormat(unittest.TestCase):

    def setUp(self):
        root = logging.getLogger()
        saved_handlers, saved_level = root.handlers[:], root.level

        def restore():
            for handler in root.handlers:
                root.removeHandler(handler)
            for handler in saved_handlers:
                root.addHandler(handler)
            root.setLevel(saved_level)
        self.addCleanup(restore)

    def test_format(self):
        stream = io.StringIO()
        server.configure_logging(stream)
        server.log.info("hello")
        server.log.warning("careful")
        self.assertRegex(stream.getvalue(),
                         r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] INFO - hello\n"
                         r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] WARNING - careful\n$")


class ServerLogCase(InTempDir):
    """Runs an in-process server while capturing everything its logger writes."""
    secure = False

    def setUp(self):
        super().setUp()
        self.logs = self.enterContext(self.assertLogs("server", level="INFO"))
        self.server = Server("127.0.0.1", self.port, secure=self.secure)
        self.addCleanup(self.server.shutdown)

    @property
    def lines(self):
        return [f"{r.levelname} - {r.getMessage()}" for r in self.logs.records]

    def assertLogged(self, pattern):
        self.assertTrue(any(re.search(pattern, line) for line in self.lines),
                        f"{pattern!r} not logged:\n" + "\n".join(self.lines))

    def client(self):
        return RawClient(self, self.server)


class TestServerEvents(ServerLogCase):

    def test_start_is_logged(self):
        self.assertLogged(rf"^INFO - Started listening on port {self.port} \(unsecure mode\)$")

    def test_malformed_packet_is_logged_as_error(self):
        raw = self.client()
        raw.sock.sendall(frame(b"DH_INIT:a:b:c"))
        self.assertTrue(until(lambda: any("dropping malformed packet" in l for l in self.lines), raw.step))
        self.assertLogged(r"^ERROR - .*dropping malformed packet")


class TestConnectionEvents(ServerLogCase):

    def test_connect_join_and_disconnect_are_logged_with_ip(self):
        alice = self.client()
        self.assertLogged(r"^INFO - Client connected: conn#1 \(127\.0\.0\.1\)$")
        alice.join("Alice")
        self.assertLogged(r"^INFO - conn#1 \(127\.0\.0\.1\) joined the chat as Alice$")

        alice.sock.close()
        self.sockets.remove(alice.sock)
        self.assertTrue(until(lambda: alice.port not in self.server.connections, alice.step))
        self.assertLogged(r"^INFO - Client disconnected: Alice \(conn#1, 127\.0\.0\.1\)$")

    def test_connections_are_numbered_and_ports_are_not_logged(self):
        first, second = self.client(), self.client()
        self.assertLogged(r"Client connected: conn#1 ")
        self.assertLogged(r"Client connected: conn#2 ")
        for port in (first.port, second.port):
            self.assertFalse(any(str(port) in line for line in self.lines))


class TestRoutingEvents(ServerLogCase):

    def test_broadcast_logs_route_but_not_content_or_keys(self):
        alice, bob, carol = self.client(), self.client(), self.client()
        for raw, name in ((alice, "Alice"), (bob, "Bob"), (carol, "Carol")):
            raw.join(name)
        alice.send_encrypted("top-secret-text")
        bob.recv_text()
        carol.recv_text()
        self.assertLogged(r"^INFO - Alice -> broadcasted to 2 clients$")

        log_text = "\n".join(self.lines)
        self.assertNotIn("top-secret-text", log_text)
        for key in self.server.client_aes_keys.values():
            self.assertNotIn(key.hex()[:8], log_text)

    def test_unauthenticated_session_is_logged(self):
        self.client().join("Alice")
        self.assertLogged(r"^INFO - AES session key established with conn#1 \(127\.0\.0\.1\) "
                          r"\(unauthenticated Diffie-Hellman\)$")


class TestSecureServerEvents(ServerLogCase):
    secure = True

    def test_rsa_exchange_and_signed_session_are_logged(self):
        raw = self.client()
        public, private = RSA_Math.generate_rsa_parameters(512)
        raw.sock.sendall(frame(RSA_Main.build_rsa_init_packet(public).encode("utf-8")))
        raw.recv()  # server's RSA_INIT
        self.assertLogged(r"^INFO - RSA public key exchange completed with conn#1 \(127\.0\.0\.1\)$")

        dh_init, _, _, _ = DHNetwork.build_init_packet()
        raw.sock.sendall(frame(RSA_Main.build_rsa_auth_packet(dh_init, private).encode("utf-8")))
        raw.recv()  # signed DH_ACCEPT
        self.assertLogged(r"^INFO - AES session key established with conn#1 \(127\.0\.0\.1\) "
                          r"\(RSA-signed Diffie-Hellman\)$")

    def test_unauthenticated_dh_is_logged_as_warning(self):
        raw = self.client()
        dh_init, _, _, _ = DHNetwork.build_init_packet()
        raw.sock.sendall(frame(dh_init.encode("utf-8")))
        self.assertTrue(until(lambda: any("HACKER DETECTED" in l for l in self.lines), raw.step))
        self.assertLogged(r"^WARNING - HACKER DETECTED! .*unauthenticated DH_INIT")


if __name__ == "__main__":
    unittest.main()
