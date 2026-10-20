import os
import unittest

import protocol
from diffieHellman import DHLogic, DHNetwork
from RSA import RSA_Main, RSA_Math


def old_attacker_rewrite(msg, prefix, index, value):
    """The packet rewriting the attacker used before protocol.split_dh_message existed."""
    parts = msg.split(prefix)
    dh_string = parts[1]
    signature_part = ""
    if "|" in dh_string:
        dh_core, signature_part = dh_string.split("|", 1)
        signature_part = "|" + signature_part
    else:
        dh_core = dh_string
    dh_parts = dh_core.split(":")
    dh_parts[index] = value
    parts[1] = ":".join(dh_parts) + signature_part
    return prefix.join(parts)


class TestWireFormat(unittest.TestCase):
    """Builders must produce exactly the strings the code used to format inline."""

    def test_rsa_init(self):
        self.assertEqual(protocol.build_rsa_init(65537, 3233), "RSA_INIT:65537:3233")
        self.assertEqual(protocol.parse_rsa_init("RSA_INIT:65537:3233"), (65537, 3233))

    def test_rsa_auth(self):
        packet = protocol.build_rsa_auth("DH_ACCEPT:42", 99)
        self.assertEqual(packet, "RSA_AUTH:DH_ACCEPT:42|99")
        self.assertEqual(protocol.parse_rsa_auth(packet), ("DH_ACCEPT:42", 99))

    def test_rsa_auth_signature_is_last_separator(self):
        self.assertEqual(protocol.parse_rsa_auth("RSA_AUTH:a|b|7"), ("a|b", 7))

    def test_dh_init(self):
        self.assertEqual(protocol.build_dh_init(23, 5, 8), "DH_INIT:23:5:8")
        self.assertEqual(protocol.parse_dh_init("DH_INIT:23:5:8"), (23, 5, 8))

    def test_dh_accept(self):
        self.assertEqual(protocol.build_dh_accept(19), "DH_ACCEPT:19")
        self.assertEqual(protocol.parse_dh_accept("DH_ACCEPT:19"), 19)

    def test_malformed_packets_raise_value_error(self):
        cases = [
            (protocol.parse_rsa_init, "RSA_INIT:x"),
            (protocol.parse_rsa_init, "RSA_INIT:1"),
            (protocol.parse_rsa_init, "DH_INIT:1:2"),
            (protocol.parse_rsa_auth, "RSA_AUTH:no-separator"),
            (protocol.parse_rsa_auth, "RSA_AUTH:text|sig"),
            (protocol.parse_dh_init, "DH_INIT:1:2"),
            (protocol.parse_dh_init, "DH_INIT:1:2:3:4"),
            (protocol.parse_dh_accept, "DH_ACCEPT:"),
            (protocol.parse_dh_accept, "DH_ACCEPT:1:2"),
        ]
        for parse, packet in cases:
            with self.subTest(packet=packet):
                with self.assertRaises(ValueError):
                    parse(packet)

    def test_encrypted_frame_layout(self):
        nonce, tag, ciphertext = os.urandom(12), os.urandom(16), os.urandom(33)
        frame = protocol.build_encrypted(nonce, tag, ciphertext)
        self.assertEqual(frame, (12 + 16 + 33).to_bytes(4, "big") + nonce + tag + ciphertext)
        self.assertEqual(protocol.parse_encrypted(frame), (nonce, tag, ciphertext))


class TestNamePacket(unittest.TestCase):

    def test_round_trip(self):
        self.assertEqual(protocol.build_name("Alice"), "NAME:Alice")
        self.assertEqual(protocol.parse_name("NAME:Alice"), "Alice")

    def test_anonymous_packet(self):
        self.assertEqual(protocol.build_name(None), "NAME:")
        self.assertIsNone(protocol.parse_name("NAME:"))

    def test_name_is_stripped_and_may_contain_spaces_and_colons(self):
        self.assertEqual(protocol.parse_name("NAME:  Bob Smith  "), "Bob Smith")
        self.assertEqual(protocol.parse_name("NAME:a:b"), "a:b")
        self.assertEqual(protocol.parse_name("NAME:Žofie"), "Žofie")

    def test_unusable_names_mean_anonymous(self):
        for name in ["   ", "x" * (protocol.MAX_NAME_LENGTH + 1), "evil\nname", "tab\tname",
                     "[Server]", "a]b", "Anonymous#1", "anonymous#7"]:
            with self.subTest(name=name):
                self.assertIsNone(protocol.normalize_name(name))
                self.assertIsNone(protocol.parse_name(protocol.build_name(name)))

    def test_longest_allowed_name(self):
        name = "x" * protocol.MAX_NAME_LENGTH
        self.assertEqual(protocol.normalize_name(name), name)

    def test_wrong_prefix_raises_value_error(self):
        with self.assertRaises(ValueError):
            protocol.parse_name("DH_ACCEPT:5")


class TestHandshakeModulesUseSameFormat(unittest.TestCase):

    def test_dh_network_packets(self):
        packet, p, g, _ = DHNetwork.build_init_packet()
        self.assertEqual(packet, f"DH_INIT:{p}:{g}:{protocol.parse_dh_init(packet)[2]}")
        reply, _, _ = DHNetwork.process_init_packet(packet)
        self.assertRegex(reply, r"^DH_ACCEPT:\d+$")

    def test_rsa_main_packets(self):
        public, private = RSA_Math.generate_rsa_parameters(512)
        signed = RSA_Main.build_rsa_auth_packet("DH_ACCEPT:5", private)
        self.assertRegex(signed, r"^RSA_AUTH:DH_ACCEPT:5\|\d+$")
        self.assertEqual(RSA_Main.process_rsa_auth_packet(signed, public), (True, "DH_ACCEPT:5"))


class TestDhMessageRewrite(unittest.TestCase):

    def test_matches_old_attacker_rewrite(self):
        p, g = DHLogic.get_dh_parameters()
        cases = [
            (f"DH_INIT:{p}:{g}:12345", protocol.DH_INIT, 2),
            (f"RSA_AUTH:DH_INIT:{p}:{g}:12345|987654321", protocol.DH_INIT, 2),
            ("DH_ACCEPT:555", protocol.DH_ACCEPT, 0),
            ("RSA_AUTH:DH_ACCEPT:555|42", protocol.DH_ACCEPT, 0),
        ]
        for message, prefix, index in cases:
            with self.subTest(message=message[:40]):
                head, fields, tail = protocol.split_dh_message(message, prefix)
                self.assertEqual(protocol.join_dh_message(head, fields, tail), message)
                fields[index] = "777"
                self.assertEqual(protocol.join_dh_message(head, fields, tail),
                                 old_attacker_rewrite(message, prefix, index, "777"))


if __name__ == "__main__":
    unittest.main()
