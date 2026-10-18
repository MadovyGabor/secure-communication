import unittest

from diffieHellman import DHLogic
from diffieHellman import DHNetwork
from RSA import RSA_Main
from RSA import RSA_Math


class TestDHRobustness(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.alice_rsa_pub, cls.alice_rsa_priv = RSA_Math.generate_rsa_parameters(1024)
        cls.bob_rsa_pub, cls.bob_rsa_priv = RSA_Math.generate_rsa_parameters(1024)

    def test_successful_signed_handshake(self):
        # Initiator (Alice)
        raw_init, p, g, alice_dh_priv = DHNetwork.build_init_packet()
        signed_init = RSA_Main.build_rsa_auth_packet(raw_init, self.alice_rsa_priv)

        # Responder (Bob)
        is_valid, inner_init = RSA_Main.process_rsa_auth_packet(signed_init, self.alice_rsa_pub)
        self.assertTrue(is_valid, "Bob rejected Alice's signature")
        raw_accept, bob_secret, bob_aes_key = DHNetwork.process_init_packet(inner_init)
        signed_accept = RSA_Main.build_rsa_auth_packet(raw_accept, self.bob_rsa_priv)

        # Initiator (Alice)
        is_valid, inner_accept = RSA_Main.process_rsa_auth_packet(signed_accept, self.bob_rsa_pub)
        self.assertTrue(is_valid, "Alice rejected Bob's signature")
        alice_secret, alice_aes_key = DHNetwork.process_accept_packet(inner_accept, p, alice_dh_priv)

        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(alice_aes_key, bob_aes_key)
        self.assertEqual(len(alice_aes_key), 32)

    def test_mitm_modified_public_key_is_detected(self):
        raw_init, p, g, alice_dh_priv = DHNetwork.build_init_packet()
        signed_init = RSA_Main.build_rsa_auth_packet(raw_init, self.alice_rsa_priv)

        payload, signature = signed_init.rsplit("|", 1)
        fields = payload.split(":")  # RSA_AUTH, DH_INIT, p, g, public key
        fields[4] = str(int(fields[4]) + 1)
        malicious_packet = ":".join(fields) + "|" + signature

        is_valid, _ = RSA_Main.process_rsa_auth_packet(malicious_packet, self.alice_rsa_pub)
        self.assertFalse(is_valid)

    def test_weak_public_key_is_rejected(self):
        p, g = DHLogic.get_dh_parameters()
        for weak in (0, 1, p - 1, p):
            with self.subTest(public_key=weak):
                with self.assertRaises(ValueError):
                    DHNetwork.process_init_packet(f"DH_INIT:{p}:{g}:{weak}")


if __name__ == "__main__":
    unittest.main()
