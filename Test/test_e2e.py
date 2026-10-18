"""End-to-end demo scenarios: server, optional MITM proxy and two clients as subprocesses."""
import tempfile
import time
import unittest

from Test.harness import Scenario, handshake


class TestEndToEnd(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scenario = Scenario(self.tmp.name)

    def tearDown(self):
        self.scenario.close()
        self.tmp.cleanup()

    def chat(self, secure, port=None):
        a = self.scenario.client("a", port, secure)
        b = self.scenario.client("b", port, secure)
        keyed = [handshake(a, secure), handshake(b, secure)]
        a.send("hello-from-a")
        return a, b, keyed

    def test_secure_chat(self):
        self.scenario.server(secure=True)
        a, b, keyed = self.chat(secure=True)
        self.assertEqual(keyed, [True, True])
        b.wait_for("[Message from Server]: ")
        b.wait_for("hello-from-a")

    def test_unsecure_chat(self):
        self.scenario.server(secure=False)
        a, b, keyed = self.chat(secure=False)
        self.assertEqual(keyed, [True, True])
        b.wait_for("hello-from-a")

    def test_mitm_succeeds_in_unsecure_mode(self):
        self.scenario.server(secure=False)
        attacker = self.scenario.attacker(secure=False)
        attacker.send("attack")
        attacker.wait_for("MITM Attack Mode: ENABLED")
        a, b, keyed = self.chat(secure=False, port=self.scenario.port + 1)
        self.assertEqual(keyed, [True, True])
        b.wait_for("hello-from-a")
        attacker.wait_for("[MITM] Extracted Plaintext: hello-from-a")

    def test_mitm_detected_in_secure_mode(self):
        server = self.scenario.server(secure=True)
        attacker = self.scenario.attacker(secure=True)
        attacker.send("attack")
        attacker.wait_for("MITM Attack Mode: ENABLED")
        a, b, keyed = self.chat(secure=True, port=self.scenario.port + 1)
        self.assertEqual(keyed, [False, False])
        server.wait_for("HACKER DETECTED")
        time.sleep(1.5)
        self.assertFalse(b.contains("hello-from-a"))
        self.assertFalse(attacker.contains("Extracted Plaintext"))


if __name__ == "__main__":
    unittest.main()
