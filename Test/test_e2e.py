"""End-to-end demo scenarios: server, optional MITM proxy and two clients as subprocesses."""
import re
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

    def chat(self, secure, port=None, usernames=(None, None)):
        a = self.scenario.client("a", port, secure, usernames[0])
        b = self.scenario.client("b", port, secure, usernames[1])
        keyed = [handshake(a, secure), handshake(b, secure)]
        a.send("hello-from-a")
        return a, b, keyed

    def test_secure_chat(self):
        self.scenario.server(secure=True)
        a, b, keyed = self.chat(secure=True)
        self.assertEqual(keyed, [True, True])
        b.wait_for("[Message from Server]: ")
        b.wait_for("hello-from-a")

    def test_named_chat(self):
        self.scenario.server(secure=True)
        a, b, keyed = self.chat(secure=True, usernames=("Alice", "Bob"))
        self.assertEqual(keyed, [True, True])
        a.wait_for("You are chatting as Alice.")
        b.wait_for("[Alice]: hello-from-a")

    def test_anonymous_chat_hides_port(self):
        self.scenario.server(secure=True)
        a, b, keyed = self.chat(secure=True)
        self.assertEqual(keyed, [True, True])
        a.wait_for("You are chatting as Anonymous#1.")
        b.wait_for("You are chatting as Anonymous#2.")
        b.wait_for("[Anonymous#1]: hello-from-a")
        self.assertIsNone(re.search(r"\d+: hello-from-a", b.output))

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
        a, b, keyed = self.chat(secure=False, port=self.scenario.port + 1, usernames=("Alice", None))
        self.assertEqual(keyed, [True, True])
        b.wait_for("[Alice]: hello-from-a")
        attacker.wait_for("[MITM] Extracted Username: Alice")
        attacker.wait_for("[MITM] Extracted Plaintext: hello-from-a")

    def test_mitm_tampers_message_in_unsecure_mode(self):
        self.scenario.server(secure=False)
        attacker = self.scenario.attacker(secure=False)
        attacker.send("attack")
        attacker.wait_for("MITM Attack Mode: ENABLED")
        a = self.scenario.client("a", self.scenario.port + 1, secure=False)
        b = self.scenario.client("b", self.scenario.port + 1, secure=False)
        self.assertTrue(handshake(a, secure=False))
        self.assertTrue(handshake(b, secure=False))
        attacker.send("tamper forged-text")
        attacker.wait_for("Next intercepted message will be replaced")
        a.send("original-text")
        b.wait_for("forged-text")
        attacker.wait_for("TAMPERING MESSAGE")
        self.assertFalse(b.contains("original-text"))

    def test_mitm_detected_in_secure_mode(self):
        server = self.scenario.server(secure=True)
        attacker = self.scenario.attacker(secure=True)
        attacker.send("attack")
        attacker.wait_for("MITM Attack Mode: ENABLED")
        a, b, keyed = self.chat(secure=True, port=self.scenario.port + 1, usernames=("Alice", "Bob"))
        self.assertEqual(keyed, [False, False])
        server.wait_for("HACKER DETECTED")
        time.sleep(1.5)
        self.assertFalse(b.contains("hello-from-a"))
        self.assertFalse(attacker.contains("Extracted Plaintext"))
        self.assertFalse(attacker.contains("Alice"))


if __name__ == "__main__":
    unittest.main()
