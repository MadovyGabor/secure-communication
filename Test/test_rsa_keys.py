import contextlib
import io
import os
import tempfile
import unittest

from RSA import RSA_Main


class TestRsaKeyFiles(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "node_key.json")
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None, None, None)
        self.tmp.cleanup()

    def test_keys_are_created_once_and_reloaded(self):
        public, private = RSA_Main.load_or_create_keys(self.path)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(RSA_Main.load_or_create_keys(self.path), (public, private))
        self.assertEqual(public[1], private[1])

    def test_without_filename_keys_are_not_saved(self):
        public, private = RSA_Main.load_or_create_keys()
        self.assertEqual(public[0], 65537)
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_init_packet_carries_public_key(self):
        public, _ = RSA_Main.load_or_create_keys(self.path)
        packet = RSA_Main.build_rsa_init_packet(public)
        self.assertEqual(packet, f"RSA_INIT:{public[0]}:{public[1]}")
        self.assertEqual(RSA_Main.process_rsa_init_packet(packet), public)

    def test_corrupted_key_file_raises_value_error(self):
        for content in ["not json", "{}", '{"public_key": {"e": 3}}']:
            with self.subTest(content=content):
                with open(self.path, "w") as f:
                    f.write(content)
                with self.assertRaisesRegex(ValueError, "corrupted"):
                    RSA_Main.load_or_create_keys(self.path)


if __name__ == "__main__":
    unittest.main()
