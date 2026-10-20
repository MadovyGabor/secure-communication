import contextlib
import io
import unittest
from unittest import mock

import main


class TestParseArgs(unittest.TestCase):

    def parse(self, line):
        args = main.parse_args(line.split())
        return args.mode, args.host, args.port, args.instance, args.secure

    def test_readme_commands(self):
        cases = {
            "server 127.0.0.1 8000": ("server", "127.0.0.1", 8000, "default", True),
            "server 127.0.0.1 8000 --unsecure": ("server", "127.0.0.1", 8000, "default", False),
            "attack 127.0.0.1 8000": ("attack", "127.0.0.1", 8000, "default", True),
            "attack 127.0.0.1 8000 --unsecure": ("attack", "127.0.0.1", 8000, "default", False),
            "client 127.0.0.1 8000 klient1": ("client", "127.0.0.1", 8000, "klient1", True),
            "client 127.0.0.1 8001 klient1 --unsecure": ("client", "127.0.0.1", 8001, "klient1", False),
            "client 127.0.0.1 8000": ("client", "127.0.0.1", 8000, "default", True),
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
        client.assert_called_once_with("h", 1, "inst", secure=False, name=None)

    def test_name_option(self):
        args = main.parse_args(["client", "h", "1", "inst", "--name", "Bob Smith"])
        self.assertEqual((args.instance, args.name), ("inst", "Bob Smith"))
        self.assertIsNone(main.parse_args(["client", "h", "1"]).name)
        with mock.patch("client.Client") as client:
            main.build_service(args)
        client.assert_called_once_with("h", 1, "inst", secure=True, name="Bob Smith")

    def test_main_rejects_invalid_name(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(main.main(["client", "127.0.0.1", "8000", "--name", "[Server]"]), 1)
        self.assertIn("invalid username", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
