"""Malformed or forged packets must not crash the server or wedge the client."""
import os
import socket
import tempfile
import time
import unittest

from diffieHellman import DHLogic
from Test.harness import LocalClient, Scenario, handshake


def frame(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


class TestServerSurvivesMalformedPackets(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scenario = Scenario(self.tmp.name)

    def tearDown(self):
        self.scenario.close()
        self.tmp.cleanup()

    def send_raw(self, packets):
        with socket.create_connection(("127.0.0.1", self.scenario.port)) as raw:
            for packet in packets:
                raw.sendall(frame(packet))
            time.sleep(1)

    def assert_still_serves_chat(self, server, secure):
        a = self.scenario.client("a", secure=secure)
        b = self.scenario.client("b", secure=secure)
        self.assertTrue(handshake(a, secure))
        self.assertTrue(handshake(b, secure))
        a.send("still-alive")
        b.wait_for("still-alive")
        self.assertIsNone(server.popen.poll())

    def test_secure_server(self):
        server = self.scenario.server(secure=True)
        self.send_raw([
            b"RSA_INIT:x",
            b"RSA_AUTH:no-separator",
            b"RSA_INIT:65537:3233",
            b"RSA_AUTH:DH_INIT:1:2:3|not-a-number",
            b"\xff\xfe binary junk",
        ])
        server.wait_for("dropping malformed packet")
        self.assert_still_serves_chat(server, secure=True)

    def test_unsecure_server(self):
        server = self.scenario.server(secure=False)
        p, g = DHLogic.get_dh_parameters()
        self.send_raw([
            b"DH_INIT:1:2",
            f"DH_INIT:{p}:{g}:1".encode(),
            b"DH_INIT:a:b:c",
        ])
        server.wait_for("dropping malformed packet")
        self.assert_still_serves_chat(server, secure=False)


class TestClientSurvivesMalformedPackets(unittest.TestCase):

    def setUp(self):
        self.local = LocalClient(secure=True)
        self.client = self.local.client

    def tearDown(self):
        self.local.close()

    def test_stray_dh_accept_is_ignored(self):
        unsecure = LocalClient(secure=False)
        try:
            unsecure.feed(b"DH_ACCEPT:12345")
            self.assertIn("no Diffie-Hellman exchange in progress", unsecure.output.getvalue())
            self.assertIsNone(unsecure.client.aes_session_key)
        finally:
            unsecure.close()

    def test_malformed_packets_are_dropped(self):
        self.local.feed(b"RSA_INIT:x", b"RSA_AUTH:no-separator")
        self.assertEqual(self.local.output.getvalue().count("dropping malformed packet"), 2)

    def test_tampered_ciphertext_is_dropped(self):
        key = os.urandom(32)
        self.client.aes_session_key = key
        packet = bytearray(self.client.encrypt_payload(b"hello", key))
        packet[-1] ^= 1
        self.local.feed(bytes(packet))
        self.assertIn("Decryption failed", self.local.output.getvalue())

    def test_network_thread_survives_and_releases_lock(self):
        with self.local.capture():
            self.local.peer.sendall(frame(b"RSA_AUTH:no-separator"))
            time.sleep(1)
            self.assertTrue(self.client.network_thread.is_alive())
            self.assertTrue(self.client.lock.acquire(timeout=2), "network thread kept the lock")
            self.client.lock.release()


if __name__ == "__main__":
    unittest.main()
