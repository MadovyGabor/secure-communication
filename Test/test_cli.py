import contextlib
import io
import unittest
from unittest import mock

import main


class TestParseArgs(unittest.TestCase):

    def parse(self, line):
        args = main.parse_args(line.split())
        return args.mode, args.host, args.port, args.name, args.secure

    def test_readme_commands(self):
        cases = {
            "server 127.0.0.1 8000": ("server", "127.0.0.1", 8000, None, True),
            "server 127.0.0.1 8000 --unsecure": ("server", "127.0.0.1", 8000, None, False),
            "attack 127.0.0.1 8000": ("attack", "127.0.0.1", 8000, None, True),
            "attack 127.0.0.1 8000 --unsecure": ("attack", "127.0.0.1", 8000, None, False),
            "client 127.0.0.1 8000 Alice": ("client", "127.0.0.1", 8000, "Alice", True),
            "client 127.0.0.1 8001 Alice --unsecure": ("client", "127.0.0.1", 8001, "Alice", False),
            "client 127.0.0.1 8000": ("client", "127.0.0.1", 8000, None, True),
        }
        for line, expected in cases.items():
            with self.subTest(line=line):
                self.assertEqual(self.parse(line), expected)

    def test_unsecure_flag_anywhere(self):
        self.assertEqual(self.parse("--unsecure client 127.0.0.1 8000 a"),
                         ("client", "127.0.0.1", 8000, "a", False))

    def test_invalid_arguments_exit_with_usage(self):
        for line in ["", "server 127.0.0.1", "bogus 127.0.0.1 8000", "server 127.0.0.1 abc", "server 127.0.0.1 70000"]:
            with self.subTest(line=line):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as cm:
                    main.parse_args(line.split())
                self.assertNotEqual(cm.exception.code, 0)
                self.assertIn("usage:", stderr.getvalue())


class TestRun(unittest.TestCase):

    def test_keyboard_interrupt_shuts_service_down(self):
        service = mock.Mock()
        service.loop.side_effect = KeyboardInterrupt
        main.run(service)
        service.shutdown.assert_called_once_with()

    def test_main_reports_connection_error(self):
        with mock.patch.object(main, "build_service", side_effect=ConnectionRefusedError("refused")):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main.main(["client", "127.0.0.1", "8000"]), 1)
        self.assertIn("cannot start client", stderr.getvalue())

    def test_build_service_dispatch(self):
        args = main.parse_args(["client", "h", "1", "inst", "--unsecure"])
        with mock.patch("client.Client") as client:
            main.build_service(args)
        client.assert_called_once_with("h", 1, "inst", secure=False)

    def test_anonymous_client_dispatch(self):
        with mock.patch("client.Client") as client:
            main.build_service(main.parse_args(["client", "h", "1"]))
        client.assert_called_once_with("h", 1, None, secure=True)

    def test_main_rejects_invalid_name(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main.main(["client", "127.0.0.1", "8000", "../evil"]), 1)
        self.assertIn("invalid username", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
