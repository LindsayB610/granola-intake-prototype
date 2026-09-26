from contextlib import redirect_stdout, redirect_stderr
import io
import json
import plistlib
import unittest
from unittest.mock import patch

import test_detector as fixtures
from test_detector import API, NOW, page
from detector import run_once
from cli import main


class CLITests(unittest.TestCase):
    setUp = fixtures.DetectorTests.setUp
    tearDown = fixtures.DetectorTests.tearDown
    queue = fixtures.DetectorTests.queue

    def config_file(self):
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config))
        path.chmod(0o600)
        return path

    def call(self, args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_definition_only_contains_bounded_schedule(self):
        with patch("adapters.file_credential", side_effect=AssertionError("must not read credential file")), \
                patch("subprocess.run", side_effect=AssertionError("must not run subprocess")):
            code, out, err = self.call(["--config", str(self.config_file()), "scheduler-definition"])
        self.assertEqual(code, 0)
        definition = plistlib.loads(out.encode())
        self.assertEqual(definition["StartInterval"], 60)
        self.assertEqual(definition["ProgramArguments"][-1], "run-once")
        self.assertEqual(definition["StandardErrorPath"], "/dev/null")
        self.assertFalse((self.root / "state").exists())

    def test_status_and_explicit_reset_do_not_send(self):
        self.config["max_pages"] = 1
        run_once(self.config, API([page([], "expired-cursor")]), self.queue, NOW)
        config = self.config_file()
        code, out, _ = self.call(["--config", str(config), "status"])
        self.assertTrue(json.loads(out)["cycle_in_progress"])
        code, _, _ = self.call(["--config", str(config), "reset-discovery"])
        self.assertNotEqual(code, 0)
        code, out, _ = self.call(["--config", str(config), "reset-discovery", "--confirm-reset"])
        self.assertEqual(code, 0)
        api = API([page()])
        run_once(self.config, api, self.queue, NOW)
        self.assertNotIn("cursor", api.calls[0])
        self.assertEqual(self.sent, [])

    def test_config_error_and_source_exception_are_sanitized(self):
        path = self.config_file()
        path.write_text("grn_SECRET_INVALID_JSON")
        code, out, err = self.call(["--config", str(path), "status"])
        self.assertEqual(code, 1)
        self.assertNotIn("grn_SECRET", out + err)
        path = self.config_file()
        with patch("cli.GranolaAPI", side_effect=RuntimeError("grn_SECRET")):
            code, out, err = self.call(["--config", str(path), "run-once"])
        self.assertEqual(code, 1)
        self.assertNotIn("grn_SECRET", out + err)


if __name__ == "__main__":
    unittest.main()
