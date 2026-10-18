"""Helpers for end-to-end tests that drive main.py in subprocesses."""
import os
import random
import socket
import subprocess
import sys
import threading
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN = os.path.join(REPO_ROOT, "main.py")
TIMEOUT = 30


# Below the OS ephemeral ranges (Linux 32768+, Windows 49152+). A port the OS hands out with
# bind(0) is ephemeral: an outgoing connection elsewhere on the machine can take it between this
# check and the moment the server or attacker subprocess binds it (seen as WinError 10013).
TEST_PORTS = range(20000, 32000, 2)


def free_port_pair():
    """Return a port p such that p and p + 1 are both free on 127.0.0.1."""
    for _ in range(100):
        port = random.choice(TEST_PORTS)
        try:
            with socket.socket() as s1, socket.socket() as s2:
                s1.bind(("127.0.0.1", port))
                s2.bind(("127.0.0.1", port + 1))
            return port
        except OSError:
            continue
    raise RuntimeError("no free port pair")


class Proc:
    """A main.py subprocess with captured output and line-based stdin."""

    def __init__(self, args, cwd):
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        self.popen = subprocess.Popen(
            [sys.executable, "-u", MAIN] + list(args), cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace")
        self.lines = []
        self._lock = threading.Lock()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.popen.stdout:
            with self._lock:
                self.lines.append(line)

    @property
    def output(self):
        with self._lock:
            return "".join(self.lines)

    def send(self, line):
        self.popen.stdin.write(line + "\n")
        self.popen.stdin.flush()

    def wait_for(self, text, timeout=TIMEOUT, start=0):
        """Wait until `text` appears in output after offset `start`; return the offset after it."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            out = self.output
            index = out.find(text, start)
            if index != -1:
                return index + len(text)
            if self.popen.poll() is not None:
                time.sleep(0.2)
                out = self.output
                if text in out[start:]:
                    return out.find(text, start) + len(text)
                break
            time.sleep(0.05)
        raise AssertionError(f"{text!r} not seen. Output:\n{self.output}")

    def contains(self, text):
        return text in self.output

    def stop(self):
        if self.popen.poll() is None:
            try:
                self.popen.stdin.close()
            except OSError:
                pass
            self.popen.kill()
        self.popen.wait(timeout=10)
        self.popen.stdout.close()


class Scenario:
    """Owns processes started for one test and kills them on cleanup."""

    def __init__(self, cwd):
        self.cwd = cwd
        self.procs = []
        self.port = free_port_pair()

    def start(self, *args):
        proc = Proc([str(a) for a in args], self.cwd)
        self.procs.append(proc)
        return proc

    def server(self, secure=True):
        srv = self.start("server", "127.0.0.1", self.port, *([] if secure else ["--unsecure"]))
        srv.wait_for("Started listening")
        return srv

    def attacker(self, secure=True):
        att = self.start("attack", "127.0.0.1", self.port, *([] if secure else ["--unsecure"]))
        att.wait_for("Attacker Proxy started")
        return att

    def client(self, name, port=None, secure=True):
        port = self.port if port is None else port
        cl = self.start("client", "127.0.0.1", port, name, *([] if secure else ["--unsecure"]))
        cl.wait_for("help")
        return cl

    def close(self):
        for proc in self.procs:
            proc.stop()


class LocalClient:
    """An in-process client.Client connected to a bare listening socket in a temp CWD."""

    def __init__(self, secure=True):
        import contextlib
        import io
        import tempfile
        import client

        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.output = io.StringIO()
        self.capture = lambda: contextlib.redirect_stdout(self.output)
        with self.capture():
            self.client = client.Client(*self.listener.getsockname(), secure=secure)
        self.peer, _ = self.listener.accept()

    def feed(self, *packets):
        with self.capture():
            for packet in packets:
                self.client.receive_handler(None, packet)

    def close(self):
        self.client.shutdown()
        self.client.network_thread.join(timeout=5)
        self.peer.close()
        self.listener.close()
        os.chdir(self.cwd)
        self.tmp.cleanup()


def handshake(client, secure=True):
    """Run rsa (secure only) and dh on a client; return True if a session key was derived."""
    if secure:
        client.send("rsa")
        client.wait_for("Exchanged RSA Public Keys")
    mark = len(client.output)
    client.send("dh")
    try:
        client.wait_for("AES Session Key Derived", timeout=5, start=mark)
        return True
    except AssertionError:
        return False
