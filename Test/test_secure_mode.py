"""Secure mode must only accept signed key exchange and never send chat in plaintext."""
import socket
import unittest

import sympy

from diffieHellman import DHLogic, DHNetwork
from RSA import RSA_Main, RSA_Math
from Test.harness import LocalClient


class ClientCase(unittest.TestCase):
    secure = True

    @classmethod
    def setUpClass(cls):
        cls.server_pub, cls.server_priv = RSA_Math.generate_rsa_parameters(1024)

    def setUp(self):
        self.local = LocalClient(secure=self.secure)
        self.client = self.local.client
        self.client.peer_rsa_pub = self.server_pub
        _, self.client.p, self.client.g, self.client.private_key = DHNetwork.build_init_packet()

    def tearDown(self):
        self.local.close()

    def dh_accept(self):
        p, g = DHLogic.get_dh_parameters()
        server_pub = DHLogic.generate_public_key(DHLogic.generate_private_key(p), g, p)
        return f"DH_ACCEPT:{server_pub}"

    def sent(self, timeout=1.0):
        """Bytes the client wrote to the fake server within `timeout`."""
        self.local.peer.settimeout(timeout)
        try:
            return self.local.peer.recv(65536)
        except socket.timeout:
            return b""


class TestSecureClient(ClientCase):

    def test_unsigned_dh_accept_is_rejected(self):
        self.local.feed(self.dh_accept().encode())
        self.assertIsNone(self.client.aes_session_key)
        self.assertIn("Unsigned DH_ACCEPT", self.local.output.getvalue())

    def test_signed_dh_accept_is_accepted(self):
        signed = RSA_Main.build_rsa_auth_packet(self.dh_accept(), self.server_priv)
        self.local.feed(signed.encode())
        self.assertEqual(len(self.client.aes_session_key), 32)

    def test_dh_accept_signed_by_other_key_is_rejected(self):
        _, attacker_priv = RSA_Math.generate_rsa_parameters(1024)
        forged = RSA_Main.build_rsa_auth_packet(self.dh_accept(), attacker_priv)
        self.local.feed(forged.encode())
        self.assertIsNone(self.client.aes_session_key)

    def test_chat_without_session_key_is_not_sent(self):
        with self.local.capture():
            self.client.send_chat("secret")
        self.assertEqual(self.sent(), b"")
        self.assertIn("No session key yet", self.local.output.getvalue())

    def test_chat_with_session_key_is_encrypted(self):
        self.local.feed(RSA_Main.build_rsa_auth_packet(self.dh_accept(), self.server_priv).encode())
        with self.local.capture():
            self.client.send_chat("secret")
        frame = self.sent()
        self.assertNotIn(b"secret", frame)
        self.assertEqual(self.client.decrypt_payload(frame[4:], self.client.aes_session_key), b"secret")


class TestUnsecureClient(ClientCase):
    secure = False

    def test_unsigned_dh_accept_is_accepted(self):
        self.local.feed(self.dh_accept().encode())
        self.assertEqual(len(self.client.aes_session_key), 32)

    def test_chat_without_session_key_is_sent_in_plaintext(self):
        with self.local.capture():
            self.client.send_chat("hello")
        self.assertEqual(self.sent(), len(b"hello").to_bytes(4, "big") + b"hello")


class TestDHGroupEnforcement(unittest.TestCase):

    def test_standard_group_is_accepted(self):
        raw_init, _, _, _ = DHNetwork.build_init_packet()
        reply, _, key = DHNetwork.process_init_packet(raw_init)
        self.assertTrue(reply.startswith("DH_ACCEPT:"))
        self.assertEqual(len(key), 32)

    def test_non_standard_group_is_rejected(self):
        p, g = DHLogic.get_dh_parameters()
        weak_p = sympy.prevprime(2 ** 64)
        cases = {
            "small prime": (weak_p, 2, 5),
            "other generator": (p, 5, 12345),
        }
        for name, (p_, g_, pub) in cases.items():
            with self.subTest(name):
                with self.assertRaisesRegex(ValueError, "Group 14"):
                    DHNetwork.process_init_packet(f"DH_INIT:{p_}:{g_}:{pub}")


if __name__ == "__main__":
    unittest.main()
