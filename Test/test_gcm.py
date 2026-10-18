import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from GCM.GCM import aes_gcm_encrypt, aes_gcm_decrypt


class TestAesGcmVectors(unittest.TestCase):
    # Test cases 2 and 3 from "The Galois/Counter Mode of Operation (GCM)", McGrew & Viega
    VECTORS = [
        (
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        ),
        (
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        ),
    ]

    def test_known_answer_vectors(self):
        for key, nonce, plaintext, ciphertext, tag in self.VECTORS:
            key, nonce, plaintext = bytes.fromhex(key), bytes.fromhex(nonce), bytes.fromhex(plaintext)
            c, t = aes_gcm_encrypt(nonce, key, plaintext)
            self.assertEqual(c.hex(), ciphertext)
            self.assertEqual(t.hex(), tag)
            self.assertEqual(aes_gcm_decrypt(nonce, key, c, t), plaintext)

    def test_matches_reference_implementation(self):
        for length in (0, 1, 15, 16, 17, 100):
            key, nonce, plaintext = os.urandom(32), os.urandom(12), os.urandom(length)
            c, t = aes_gcm_encrypt(nonce, key, plaintext)
            self.assertEqual(c + t, AESGCM(key).encrypt(nonce, plaintext, None))


class TestAesGcmTampering(unittest.TestCase):

    def setUp(self):
        self.key, self.nonce = os.urandom(32), os.urandom(12)
        self.ciphertext, self.tag = aes_gcm_encrypt(self.nonce, self.key, b"attack at dawn")

    def test_tampered_tag_rejected(self):
        bad_tag = bytes([self.tag[0] ^ 1]) + self.tag[1:]
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(self.nonce, self.key, self.ciphertext, bad_tag)

    def test_tampered_ciphertext_rejected(self):
        bad = bytes([self.ciphertext[0] ^ 1]) + self.ciphertext[1:]
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(self.nonce, self.key, bad, self.tag)

    def test_wrong_key_rejected(self):
        with self.assertRaises(ValueError):
            aes_gcm_decrypt(self.nonce, os.urandom(32), self.ciphertext, self.tag)

    def test_bad_nonce_length_rejected(self):
        with self.assertRaises(ValueError):
            aes_gcm_encrypt(b"short", self.key, b"x")


if __name__ == "__main__":
    unittest.main()
