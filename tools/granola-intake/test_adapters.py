import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock

from adapters import GranolaAPI, NoRedirect, RetryLater, file_credential, queue_wake
from unittest.mock import patch
import test_detector as fixtures
from test_detector import NOTE, NOW, page, note, API
from detector import run_once


class Response:
    def __init__(self, data):
        self.data = data
        self.status = 200
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, limit):
        return self.data[:limit]


class AdapterTests(unittest.TestCase):
    setUp = fixtures.DetectorTests.setUp
    tearDown = fixtures.DetectorTests.tearDown
    queue = fixtures.DetectorTests.queue
    rows = fixtures.DetectorTests.rows
    def test_api_fixed_origin_bounded_read_and_secret_header(self):
        opener = Mock()
        opener.open.return_value = Response(json.dumps(page([note()])).encode())
        api = GranolaAPI(self.config, credential=lambda: "grn_SYNTHETIC", opener=opener)
        result = api.list_notes({"page_size": 30, "created_after": NOW})
        self.assertEqual(result["notes"][0]["id"], NOTE)
        request = opener.open.call_args[0][0]
        self.assertTrue(request.full_url.startswith("https://public-api.granola.ai/v1/notes?"))
        self.assertEqual(request.headers["Authorization"], "Bearer grn_SYNTHETIC")
        self.assertEqual(opener.open.call_args[1]["timeout"], 15)

    def test_invalid_oversize_and_http_errors_do_not_leak(self):
        for data in (b"grn_SECRET bad JSON", b"x" * (1048576 + 1)):
            opener = Mock()
            opener.open.return_value = Response(data)
            with self.assertRaises(Exception) as caught:
                GranolaAPI(self.config, credential=lambda: "grn_SECRET", opener=opener).list_notes({})
            self.assertNotIn("grn_SECRET", str(caught.exception))
        for code in (301, 401, 400, 500):
            opener = Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://example.test", code,
                                                            "grn_SECRET", {}, io.BytesIO(b"grn_SECRET"))
            with self.assertRaises(Exception) as caught:
                GranolaAPI(self.config, credential=lambda: "grn_SECRET", opener=opener).list_notes({})
            self.assertNotIn("grn_SECRET", str(caught.exception))
            self.assertEqual(opener.open.call_count, 1)

    def test_429_is_persisted_backoff_not_busy_wait(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError("https://example.test", 429,
                                                        "grn_SECRET", {"Retry-After": "120"}, None)
        api = GranolaAPI(self.config, credential=lambda: "grn_SECRET", opener=opener)
        result = run_once(self.config, api, self.queue, NOW)
        self.assertEqual(result["outcome"], "backoff")
        later = API([])
        again = run_once(self.config, later, self.queue, "2026-09-25T00:01:00Z")
        self.assertEqual(again["outcome"], "backoff")
        self.assertEqual(later.calls, [])
        self.assertEqual(self.sent, [])

    def test_queue_uses_fixed_argv_and_holds_nonzero(self):
        runner = Mock(return_value=Mock(returncode=0))
        payload = {"operation_id": "a" * 64, "attempt_id": "00000000-0000-4000-8000-000000000003"}
        queue_wake(self.config, payload, runner=runner)
        args, kwargs = runner.call_args
        self.assertEqual(args[0][:4], ["/usr/bin/true", "queue", "--thread", self.config["dispatcher_thread"]])
        self.assertIn(payload["attempt_id"], args[0][-1])
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        runner.return_value.returncode = 1
        with self.assertRaisesRegex(Exception, "wake outcome uncertain"):
            queue_wake(self.config, payload, runner=runner)

    def test_default_transport_refuses_redirects(self):
        api = GranolaAPI(self.config, credential=lambda: "grn_SYNTHETIC")
        handlers = [h for h in api.opener.handlers if isinstance(h, NoRedirect)]
        self.assertEqual(len(handlers), 1)
        with self.assertRaisesRegex(Exception, "redirect rejected"):
            handlers[0].redirect_request(None, None, 302, "grn_SECRET", {}, "https://evil.test")

    def test_local_credential_requires_private_owned_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api-key"
            path.write_text("grn_SYNTHETIC\n", encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(file_credential(path=path), "grn_SYNTHETIC")
            path.chmod(0o640)
            with self.assertRaisesRegex(Exception, "credential unavailable"):
                file_credential(path=path)

    def test_local_credential_rejects_symlink_and_non_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("grn_SYNTHETIC", encoding="ascii")
            target.chmod(0o600)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(Exception, "credential unavailable"):
                file_credential(path=link)
            with self.assertRaisesRegex(Exception, "credential unavailable"):
                file_credential(path=root)

    def test_local_credential_rejects_invalid_or_oversized_content_without_leaking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api-key"
            for value in ("grn_SECRET other", "grn_SECRET\n\n", "bad-token", "grn_" + "A" * 4093):
                path.write_text(value, encoding="ascii")
                path.chmod(0o600)
                with self.subTest(size=len(value)), self.assertRaisesRegex(Exception, "credential unavailable") as caught:
                    file_credential(path=path)
                self.assertNotIn("grn_SECRET", str(caught.exception))

    def test_default_credential_file_path_is_gitignored(self):
        from adapters import _CREDENTIAL_PATH
        self.assertEqual(_CREDENTIAL_PATH.name, ".granola-api-key")
        self.assertEqual(_CREDENTIAL_PATH.parent.name, "granola-intake")

    def test_failed_auth_is_visible_in_status_without_sensitive_details(self):
        from detector import status
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError("https://example.test", 401, "grn_SECRET", {}, None)
        with self.assertRaises(Exception):
            run_once(self.config, GranolaAPI(self.config, credential=lambda: "grn_SECRET", opener=opener), self.queue, NOW)
        result = status(self.config)
        self.assertEqual(result["last_failure"]["code"], "Granola API access unavailable")
        self.assertNotIn("grn_SECRET", json.dumps(result))
        for path in (self.root / "state").iterdir():
            self.assertNotIn(b"grn_SECRET", path.read_bytes())

    def test_reflected_credential_cannot_reach_ledger(self):
        secret = "grn_SYNTHETIC_SECRET"
        opener = Mock()
        raw = json.dumps(page([], secret)).replace("grn_", "\\u0067rn_")
        opener.open.return_value = Response(raw.encode())
        api = GranolaAPI(self.config, credential=lambda: secret, opener=opener)
        with self.assertRaisesRegex(Exception, "API credential reflection rejected"):
            run_once(self.config, api, self.queue, NOW)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.sent, [])
        for path in (self.root / "state").iterdir():
            self.assertNotIn(secret.encode(), path.read_bytes())


if __name__ == "__main__":
    unittest.main()
