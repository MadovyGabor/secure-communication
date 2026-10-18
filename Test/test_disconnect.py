"""Per-connection state is released when a peer disconnects."""
import contextlib
import io
import os
import socket
import tempfile
import time
import unittest

import networkservice
from diffieHellman import DHNetwork
from Test.harness import free_port_pair


def frame(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def until(condition, step, rounds=50):
    for _ in range(rounds):
        if condition():
            return True
        step()
        time.sleep(0.01)
    return condition()


class InTempDir(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.output = io.StringIO()
        self.quiet = contextlib.redirect_stdout(self.output)
        self.quiet.__enter__()
        self.port = free_port_pair()
        self.sockets = []

    def tearDown(self):
        for s in self.sockets:
            s.close()
        self.quiet.__exit__(None, None, None)
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def connect(self, port):
        s = socket.create_connection(("127.0.0.1", port))
        self.sockets.append(s)
        return s


class TestServerForgetsClient(InTempDir):

    def test_keys_are_released_on_disconnect(self):
        server = networkservice.Server("127.0.0.1", self.port, secure=False)
        self.addCleanup(server.shutdown)
        step = lambda: server.server_socket.process(server.receive_handler)

        raw = self.connect(self.port)
        raw_port = raw.getsockname()[1]
        self.assertTrue(until(lambda: raw_port in server.server_socket.clients, step))

        dh_init, _, _, _ = DHNetwork.build_init_packet()
        raw.sendall(frame(dh_init.encode()))
        self.assertTrue(until(lambda: raw_port in server.client_aes_keys, step))

        raw.close()
        self.sockets.remove(raw)
        self.assertTrue(until(lambda: raw_port not in server.server_socket.clients, step))
        self.assertNotIn(raw_port, server.client_aes_keys)
        self.assertNotIn(raw_port, server.client_raw_dh_secrets)


class TestAttackerDropsRelay(InTempDir):

    def test_relay_closed_when_victim_disconnects(self):
        upstream_listener = socket.socket()
        upstream_listener.bind(("127.0.0.1", self.port))
        upstream_listener.listen(1)
        self.sockets.append(upstream_listener)

        attacker = networkservice.Attacker("127.0.0.1", self.port)
        self.addCleanup(attacker.shutdown)

        victim = self.connect(self.port + 1)
        victim.sendall(frame(b"hello"))
        self.assertTrue(until(lambda: attacker.relays, attacker.process_once))

        upstream, _ = upstream_listener.accept()
        self.sockets.append(upstream)
        upstream.settimeout(5)

        victim.close()
        self.sockets.remove(victim)
        self.assertTrue(until(lambda: not attacker.relays, attacker.process_once))

        received = b""
        with contextlib.suppress(ConnectionError):
            while chunk := upstream.recv(1024):
                received += chunk
        self.assertEqual(received, frame(b"hello"))  # upstream got the data, then EOF


if __name__ == "__main__":
    unittest.main()
