"""The server names clients by username or Anonymous#N and never shows their TCP port in the chat."""
import contextlib
import unittest

import protocol
from diffieHellman import DHNetwork
from server import Server
from Test.test_disconnect import InTempDir, frame, until


class RawClient:
    """A client speaking the wire protocol over a plain socket to an in-process server."""

    def __init__(self, case, server):
        self.server = server
        self.sock = case.connect(case.port)
        self.sock.setblocking(False)
        self.port = self.sock.getsockname()[1]
        self.buffer = b""
        self.key = None
        self.recv()  # plaintext greeting sent on accept

    def step(self):
        self.server.server_socket.process(self.server.receive_handler, timeout=0.05)

    def recv(self):
        def frame_ready():
            with contextlib.suppress(BlockingIOError):
                self.buffer += self.sock.recv(65536)
            return len(self.buffer) >= 4 and len(self.buffer) >= 4 + int.from_bytes(self.buffer[:4], "big")
        if not until(frame_ready, self.step, rounds=200):
            raise AssertionError("no frame received from server")
        length = int.from_bytes(self.buffer[:4], "big")
        data, self.buffer = self.buffer[4:4 + length], self.buffer[4 + length:]
        return data

    def recv_text(self):
        return self.server.decrypt_and_decode(self.recv(), self.key)

    def send_encrypted(self, text):
        self.sock.sendall(frame(self.server.encrypt_payload(text.encode("utf-8"), self.key)))

    def handshake(self):
        dh_init, p, _, private_key = DHNetwork.build_init_packet()
        self.sock.sendall(frame(dh_init.encode("utf-8")))
        _, self.key = DHNetwork.process_accept_packet(self.recv().decode("utf-8"), p, private_key)

    def join(self, name):
        """Handshake, introduce itself and return the server's welcome notice."""
        self.handshake()
        self.send_encrypted(protocol.build_name(name))
        return self.recv_text()


class TestServerNaming(InTempDir):

    def setUp(self):
        super().setUp()
        self.server = Server("127.0.0.1", self.port, secure=False)
        self.addCleanup(self.server.shutdown)

    def client(self):
        return RawClient(self, self.server)

    def test_named_client_is_broadcast_by_name(self):
        alice, bob = self.client(), self.client()
        self.assertEqual(alice.join("Alice"), "[Server]: You are chatting as Alice.")
        bob.join("Bob")
        alice.send_encrypted("Hello!")
        message = bob.recv_text()
        self.assertEqual(message, "[Alice]: Hello!")
        self.assertNotIn(str(alice.port), message)

    def test_clients_without_name_get_sequential_anonymous_ids(self):
        first, second = self.client(), self.client()
        self.assertEqual(first.join(None), "[Server]: You are chatting as Anonymous#1.")
        self.assertEqual(second.join("   "), "[Server]: You are chatting as Anonymous#2.")
        second.send_encrypted("hi")
        self.assertEqual(first.recv_text(), "[Anonymous#2]: hi")

    def test_reserved_name_cannot_impersonate_anonymous(self):
        self.assertEqual(self.client().join("Anonymous#5"), "[Server]: You are chatting as Anonymous#1.")

    def test_duplicate_name_falls_back_to_anonymous(self):
        self.client().join("Alice")
        notice = self.client().join("alice")
        self.assertEqual(notice, "[Server]: The name 'alice' is already taken. You are chatting as Anonymous#1.")

    def test_client_without_name_packet_is_anonymous(self):
        silent, listener = self.client(), self.client()
        silent.handshake()
        listener.join("Bob")
        silent.send_encrypted("no NAME frame first")
        self.assertEqual(silent.recv_text(), "[Server]: You are chatting as Anonymous#1.")
        self.assertEqual(listener.recv_text(), "[Anonymous#1]: no NAME frame first")

    def test_name_packet_after_first_frame_is_chat(self):
        alice, bob = self.client(), self.client()
        alice.join("Alice")
        bob.join("Bob")
        alice.send_encrypted("NAME:Mallory")
        self.assertEqual(bob.recv_text(), "[Alice]: NAME:Mallory")

    def test_rekey_keeps_name(self):
        alice = self.client()
        alice.join("Alice")
        self.assertEqual(alice.join("Eve"), "[Server]: You are chatting as Alice.")

    def test_name_is_released_on_disconnect(self):
        alice = self.client()
        alice.join("Alice")
        alice.sock.close()
        self.sockets.remove(alice.sock)
        self.assertTrue(until(lambda: alice.port not in self.server.client_names, alice.step))
        self.assertNotIn(alice.port, self.server.awaiting_name)
        self.assertEqual(self.client().join("Alice"), "[Server]: You are chatting as Alice.")


if __name__ == "__main__":
    unittest.main()
