import socket
import unittest

import networkstack


class TestClientSocketFraming(unittest.TestCase):

    def setUp(self):
        self.peer, local = socket.socketpair()
        self.client = networkstack.ClientSocket(local)
        self.received = []

    def tearDown(self):
        self.client.shutdown()
        self.peer.close()

    def handler(self, sender, data):
        self.received.append(data)

    def read_until(self, count, max_calls=50):
        for _ in range(max_calls):
            if len(self.received) >= count:
                return
            self.assertTrue(self.client.process_reading(self.handler))
        self.fail("message not received")

    @staticmethod
    def frame(data):
        return len(data).to_bytes(4, "big") + data

    def test_single_message(self):
        self.peer.sendall(self.frame(b"hello"))
        self.read_until(1)
        self.assertEqual(self.received, [b"hello"])

    def test_header_split_across_reads(self):
        framed = self.frame(b"split header")
        self.peer.sendall(framed[:2])
        self.assertTrue(self.client.process_reading(self.handler))
        self.assertEqual(self.received, [])
        self.peer.sendall(framed[2:])
        self.read_until(1)
        self.assertEqual(self.received, [b"split header"])

    def test_body_split_across_reads(self):
        framed = self.frame(b"0123456789")
        self.peer.sendall(framed[:7])
        self.client.process_reading(self.handler)
        self.client.process_reading(self.handler)
        self.assertEqual(self.received, [])
        self.peer.sendall(framed[7:])
        self.read_until(1)
        self.assertEqual(self.received, [b"0123456789"])

    def test_multiple_messages_in_one_chunk(self):
        self.peer.sendall(self.frame(b"one") + self.frame(b"two") + self.frame(b"three"))
        self.read_until(3)
        self.assertEqual(self.received, [b"one", b"two", b"three"])

    def test_disconnect_returns_false(self):
        self.peer.close()
        self.assertFalse(self.client.process_reading(self.handler))

    def test_send_writes_length_prefixed_frame(self):
        done = []
        self.assertTrue(self.client.send(b"payload", lambda sock: done.append(sock)))
        while self.client.send_queue:
            self.client.process_writing()
        self.assertEqual(self.peer.recv(64), self.frame(b"payload"))
        self.assertEqual(done, [self.client])

    def test_send_empty_is_noop(self):
        self.assertTrue(self.client.send(b""))
        self.assertEqual(self.client.send_queue, [])


if __name__ == "__main__":
    unittest.main()
