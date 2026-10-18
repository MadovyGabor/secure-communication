import socket
import struct
import time
import unittest

import networkstack


def tcp_pair():
    """Connected loopback TCP sockets. socket.socketpair() is AF_UNIX on Linux, which has no peer port."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        peer = socket.create_connection(listener.getsockname())
        local, _ = listener.accept()
    return peer, local


class TestClientSocketFraming(unittest.TestCase):

    def setUp(self):
        self.peer, local = tcp_pair()
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

    def test_idle_process_blocks_until_timeout(self):
        start = time.monotonic()
        self.assertTrue(self.client.process(self.handler, timeout=0.3))
        self.assertGreaterEqual(time.monotonic() - start, 0.25, "select returned immediately: busy loop")

    def test_process_writes_queued_data(self):
        self.client.send(b"queued")
        self.client.process(self.handler, timeout=1)
        self.assertEqual(self.peer.recv(64), self.frame(b"queued"))

    def test_send_rejects_oversized_payload(self):
        class Huge:
            def __len__(self):
                return 2 ** 32
        self.assertFalse(self.client.send(Huge()))

    def test_send_empty_is_noop(self):
        self.assertTrue(self.client.send(b""))
        self.assertEqual(self.client.send_queue, [])


class TestServerSocket(unittest.TestCase):

    def setUp(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        self.address = listener.getsockname()
        self.server = networkstack.ServerSocket(listener)
        self.peers = []

    def tearDown(self):
        for peer in self.peers:
            peer.close()
        self.server.server_socket.close()

    def connect(self):
        peer = socket.create_connection(self.address)
        self.peers.append(peer)
        self.server.process(lambda *args: None)
        return peer

    def test_accepts_and_greets_clients(self):
        peer = self.connect()
        self.assertEqual(list(self.server.clients), [peer.getsockname()[1]])
        self.server.process(lambda *args: None)  # flush the welcome message
        peer.settimeout(5)
        self.assertEqual(peer.recv(64)[4:], b"welcome to the server")

    def test_reset_client_is_dropped_and_others_still_accepted(self):
        reset_peer = self.connect()
        reset_port = reset_peer.getsockname()[1]
        reset_peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        reset_peer.close()  # linger 0 -> RST instead of FIN
        self.peers.remove(reset_peer)

        for _ in range(5):
            if reset_port not in self.server.clients:
                break
            self.server.process(lambda *args: None)
        self.assertNotIn(reset_port, self.server.clients)

        peer = self.connect()
        self.assertIn(peer.getsockname()[1], self.server.clients)

    def test_idle_process_blocks_until_timeout(self):
        self.connect()
        self.server.process(lambda *args: None)  # flush the welcome message
        start = time.monotonic()
        self.server.process(lambda *args: None, timeout=0.3)
        self.assertGreaterEqual(time.monotonic() - start, 0.25, "select returned immediately: busy loop")

    def test_queued_message_is_written(self):
        peer = self.connect()
        self.server.process(lambda *args: None)
        peer.settimeout(5)
        peer.recv(64)  # welcome
        (client,) = self.server.clients.values()
        client.send(b"ping")
        self.server.process(lambda *args: None, timeout=1)
        self.assertEqual(peer.recv(64), len(b"ping").to_bytes(4, "big") + b"ping")

    def test_shutdown_closes_all_clients(self):
        peers = [self.connect(), self.connect()]
        clients = list(self.server.clients.values())
        self.assertEqual(len(clients), 2)

        self.server.shutdown()

        self.assertEqual(self.server.clients, {})
        self.assertTrue(all(client.socket is None for client in clients))
        self.assertEqual(self.server.server_socket.fileno(), -1)
        for peer in peers:
            peer.settimeout(5)
            try:
                while peer.recv(64):  # drain the welcome message, then expect EOF
                    pass
            except ConnectionResetError:
                pass  # Windows may reset instead of a clean FIN; either way the socket is closed


if __name__ == "__main__":
    unittest.main()
