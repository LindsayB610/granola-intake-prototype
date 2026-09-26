"""Synthetic, content-free contract tests for REST transcript retrieval."""
import io
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import socket
import signal
import subprocess
import sys
from contextlib import contextmanager
import threading
import time
import unittest
import urllib.error
from unittest.mock import Mock, patch

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from source import SourceError, retrieve_source
import source


NOTE = "not_1234567890abcd"
OWNER = "owner@example.test"


def metadata(owner=OWNER, version="2026-09-24T11:00:00Z"):
    return {"id": NOTE, "object": "note", "owner": {"email": owner},
            "created_at": "2026-09-24T10:00:00Z", "updated_at": version,
            "title": "synthetic", "attendees": []}


def segment(text="Zażółć 🐈", source="microphone"):
    return {"speaker": {"source": source, "diarization_label": "Speaker A"}, "text": text,
            "start_time": "2026-09-24T10:00:00Z"}


def page(items, cursor=None):
    return {"transcript": items, "hasMore": cursor is not None, "cursor": cursor}


class Response:
    status = 200
    def __init__(self, data):
        self.data = data if isinstance(data, bytes) else json.dumps(data).encode()
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, size):
        return self.data[:size]


class ExactWindowTests(unittest.TestCase):
    def test_wrong_mode_window_stops_after_exact_metadata_before_transcript(self):
        for mode, created in (('pilot','2026-09-24T10:00:00Z'),
                              ('recovery','2026-09-26T10:00:00Z')):
            with self.subTest(mode=mode):
                row = metadata()
                row['created_at'] = created
                opener = Mock()
                opener.open.side_effect = [Response(row),
                    AssertionError('transcript endpoint must not be read')]
                with self.assertRaisesRegex(SourceError,'outside_exact_window'):
                    source._retrieve_source(NOTE,OWNER,synthetic_credential,opener,None,
                        2,4096,8192,exact_mode=mode,
                        exact_cutoff='2026-09-25T00:00:00Z',deadline=time.monotonic()+2)
                self.assertEqual(opener.open.call_count,1)


class TimedResponse(Response):
    def __init__(self, data, delay=0):
        super().__init__(data)
        self.delay = delay

    def read(self, size):
        # Ignores the socket timeout, as a continually trickling body can do.
        time.sleep(self.delay)
        return super().read(size)


class TrickleResponse(Response):
    def read(self, size):
        # Real HTTPResponse body logic over a local socketpair, no network.
        client, server = socket.socketpair()
        client.settimeout(0.1)

        def send():
            try:
                server.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                               str(len(self.data)).encode() + b"\r\n\r\n")
                for byte in self.data:
                    server.sendall(bytes([byte]))
                    time.sleep(0.02)  # Progress always beats the idle timeout.
            except OSError:
                pass
            finally:
                server.close()

        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        try:
            with http.client.HTTPResponse(client) as response:
                response.begin()
                return response.read(size)
        finally:
            client.close()
            server.close()
            sender.join(0.2)


def synthetic_credential():
    return "grn_SYNTHETIC"


class UnauthorizedResponse(Response):
    def __enter__(self):
        raise urllib.error.HTTPError("x", 401, "grn_SECRET", {}, None)


class SlowSerializationCredential:
    def __init__(self, log=None):
        self.log = log

    def __reduce__(self):
        if self.log:
            Path(self.log).write_text("serialized")
        time.sleep(1.2)
        return (SlowSerializationCredential, ())

    def __call__(self):
        return "grn_SYNTHETIC"


def partial_worker(writer, deadline, *args):
    os.write(writer.fileno(), b"partial, not a source envelope")
    time.sleep(2)


def interrupted_worker(writer, deadline, *args):
    os._exit(7)


class RecordedOpener:
    def __init__(self, responses, log, delays=None):
        self.responses = list(responses)
        self.log = log
        self.delays = list(delays or [0] * len(responses))

    def open(self, request, timeout):
        with open(self.log, "a") as stream:
            stream.write(json.dumps({"url": request.full_url, "timeout": timeout}) + "\n")
        time.sleep(self.delays.pop(0))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class SourceTests(unittest.TestCase):
    def fetch(self, responses, **limits):
        opener = Mock()
        opener.open.side_effect = [Response(x) if not isinstance(x, Exception) else x for x in responses]
        result = retrieve_source(NOTE, OWNER, credential=lambda: "grn_SYNTHETIC", opener=opener, **limits)
        return result, opener

    def assert_code(self, responses, code, **limits):
        with self.assertRaises(SourceError) as caught:
            self.fetch(responses, **limits)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn("grn_", str(caught.exception))

    def test_owned_multipage_unicode_order_and_digest(self):
        first, second = segment(), segment("第二页", "speaker")
        raw_first = json.dumps(page([first], "next"), ensure_ascii=False, indent=2).encode()
        raw_second = json.dumps(page([second]), ensure_ascii=False).encode()
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "requests.jsonl"
            opener = RecordedOpener([Response(x) for x in
                                     [metadata(), raw_first, raw_second, metadata()]], str(log))
            result = retrieve_source(NOTE, OWNER, credential=lambda: "grn_SYNTHETIC", opener=opener)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["segments"], [first, second])
        self.assertEqual(json.loads(result["representation"]), {"transcript": [first, second]})
        import hashlib
        self.assertEqual(result["sha256"], hashlib.sha256(result["representation"]).hexdigest())
        self.assertEqual(result["page_count"], 2)
        self.assertEqual(result["raw_pages"], [raw_first, raw_second])
        self.assertEqual(result["raw_page_sha256"], [hashlib.sha256(raw_first).hexdigest(),
                                                      hashlib.sha256(raw_second).hexdigest()])
        urls = [call["url"] for call in calls]
        self.assertEqual(urls[0], f"https://public-api.granola.ai/v1/notes/{NOTE}")
        self.assertIn(f"/notes/{NOTE}/transcript?page_size=100", urls[1])
        self.assertIn("cursor=next", urls[2])
        self.assertEqual(urls[-1], urls[0])

    def test_wrong_owner_and_malformed_metadata(self):
        self.assert_code([metadata(owner="shared@example.test")], "wrong_owner")
        self.assert_code([dict(metadata(), id="not_1234567890abce")], "invalid_source")

    def test_absent_empty_and_incomplete_pages(self):
        self.assert_code([urllib.error.HTTPError("x", 404, "secret", {}, None)], "not_ready_or_unavailable")
        self.assert_code([metadata(), page([]), metadata()], "empty_transcript")
        self.assert_code([metadata(), page([segment()], "next"), page([]), metadata()], "missing_page")
        self.assert_code([metadata(), page([segment()], "next"), page([segment()], "next")], "cursor_loop")
        self.assert_code([metadata(), page([segment()], "next")], "missing_page", max_pages=1)
        self.assert_code([metadata(), page([segment()], "next"),
                          urllib.error.HTTPError("x", 404, "gone", {}, None)], "missing_page")

    def test_repeated_or_overlapping_page_data_is_held(self):
        first = segment("first")
        second = segment("second")
        third = segment("third")
        self.assert_code([metadata(), page([first], "next"), page([first]), metadata()],
                         "inconsistent_pages")
        self.assert_code([metadata(), page([first, second], "next"),
                          page([second, third]), metadata()], "inconsistent_pages")

    def test_change_and_oversize(self):
        self.assert_code([metadata(), page([segment()]), metadata(version="2026-09-24T11:01:00Z")], "source_changed")
        self.assert_code([metadata(), page([segment("x" * 200)]), metadata()], "oversize", max_total_bytes=100)
        self.assert_code([metadata(), urllib.error.HTTPError("x", 413, "secret", {}, None)], "oversize")

    def test_malformed_redirect_auth_and_rate_limit_are_sanitized(self):
        self.assert_code([metadata(), b"not json"], "invalid_source")
        self.assert_code([metadata(), {"transcript": [segment()], "hasMore": True, "cursor": None}], "invalid_source")
        self.assert_code([metadata(), page([segment()]), metadata(owner="shared@example.test")], "wrong_owner")
        self.assert_code([metadata(), page([segment("grn_SYNTHETIC")])], "invalid_source")
        self.assert_code([metadata(), b"x" * 4097], "oversize", max_page_bytes=4096)
        self.assert_code([metadata(), b'{"transcript":[],"transcript":[],"hasMore":false,"cursor":null}'], "invalid_source")
        for code, expected in ((301, "redirect"), (401, "unauthorized"), (403, "unauthorized"),
                               (429, "rate_limited"), (500, "temporarily_unavailable")):
            self.assert_code([urllib.error.HTTPError("x", code, "grn_SECRET", {"Retry-After": "120"}, io.BytesIO(b"secret"))], expected)

    def test_invalid_unicode_is_sanitized_before_source_is_returned(self):
        bad_page = b'{"transcript":[{"speaker":{"source":"microphone"},"text":"\\ud800"}],"hasMore":false,"cursor":null}'
        self.assert_code([metadata(), bad_page], "invalid_source")
        bad_metadata = dict(metadata(), title="\ud800")
        self.assert_code([bad_metadata], "invalid_source")
        self.assert_code([metadata(), b'\xff'], "invalid_source")

    def test_nonfinite_numbers_are_rejected_in_pages_and_metadata(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity", b"1e9999"):
            bad_page = (b'{"transcript":[{"speaker":{"source":"microphone"},'
                        b'"text":"synthetic","confidence":' + constant +
                        b'}],"hasMore":false,"cursor":null}')
            self.assert_code([metadata(), bad_page, metadata()], "invalid_source")
            bad_metadata = json.dumps(metadata()).encode()[:-1] + b',"confidence":' + constant + b'}'
            self.assert_code([bad_metadata], "invalid_source")
            self.assert_code([metadata(), page([segment()]), bad_metadata], "invalid_source")

    def test_invalid_id_and_missing_credential_make_no_request(self):
        with self.assertRaises(SourceError) as caught:
            retrieve_source("../evil", OWNER, credential=lambda: "grn_SYNTHETIC")
        self.assertEqual(caught.exception.code, "invalid_request")
        with self.assertRaises(SourceError) as caught:
            retrieve_source(NOTE, OWNER)
        self.assertEqual(caught.exception.code, "credential_unavailable")


class SourceDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = Path(self.tmp.name) / "requests.jsonl"
        self.initial_children = {child.pid for child in multiprocessing.active_children()}
        self.worker_pids = []
        close = source._Worker.close
        def observed_close(worker):
            if worker.pid is not None:
                self.worker_pids.append(worker.pid)
            return close(worker)
        observer = patch.object(source._Worker, "close", observed_close)
        observer.start()
        self.addCleanup(observer.stop)

    def tearDown(self):
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, self.initial_children)
        for pid in self.worker_pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            with self.assertRaises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)

    @contextmanager
    def native_fixture(self, mode="timeout"):
        def command(fd):
            return [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
                    "--synthetic-worker", str(fd), str(self.log), mode]
        with patch("source._native_command", command):
            yield

    def native_fetch(self, **kwargs):
        return retrieve_source(NOTE, OWNER,
                               config={"keychain_service": "test.granola", "keychain_account": OWNER},
                               **kwargs)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def fetch(self, responses, delays=None, **kwargs):
        opener = RecordedOpener(responses, str(self.log), delays)
        return retrieve_source(NOTE, OWNER, credential=lambda: "grn_SYNTHETIC", opener=opener, **kwargs)

    def assert_timeout(self, responses, delays=None, total_timeout=0.3):
        start = time.monotonic()
        with self.assertRaises(SourceError) as caught:
            self.fetch(responses, delays, total_timeout=total_timeout)
        self.assertEqual((caught.exception.code, caught.exception.retry_after), ("temporarily_unavailable", 60))
        self.assertEqual(str(caught.exception), "temporarily_unavailable")
        # Broad scheduler tolerance; simulated stalls last much longer than this.
        self.assertLess(time.monotonic() - start, total_timeout + 0.75)

    def test_slow_pages_share_one_budget_and_never_return_partial_success(self):
        responses = [Response(metadata())] + [
            Response(page([segment(str(i))], str(i + 1) if i < 7 else None)) for i in range(8)
        ] + [Response(metadata())]
        self.assert_timeout(responses, [0.1] * len(responses))
        calls = self.calls()
        self.assertGreaterEqual(len(calls), 2)
        self.assertLess(len(calls), len(responses))
        self.assertTrue(all(0 < call["timeout"] <= 0.3 for call in calls))
        self.assertTrue(all(a["timeout"] > b["timeout"] for a, b in zip(calls, calls[1:])))
        time.sleep(0.15)
        self.assertEqual(self.calls(), calls)  # No surviving worker continues paging.

    def test_stalled_open_at_each_stage_is_interrupted(self):
        for stage in range(3):
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                responses = [Response(metadata()), Response(page([segment()])), Response(metadata())]
                delays = [0, 0, 0]
                delays[stage] = 2
                self.assert_timeout(responses, delays)
                self.assertEqual(len(self.calls()), stage + 1)

    def test_slow_body_at_each_stage_is_interrupted(self):
        for stage in range(3):
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                responses = [TimedResponse(value, 2 if i == stage else 0)
                             for i, value in enumerate([metadata(), page([segment()]), metadata()])]
                self.assert_timeout(responses)
                self.assertEqual(len(self.calls()), stage + 1)

    def test_trickling_http_body_cannot_extend_the_total_deadline(self):
        self.assert_timeout([Response(metadata()), TrickleResponse(page([segment()])), Response(metadata())])
        self.assertEqual(len(self.calls()), 2)

    def test_fast_complete_source_survives_ipc_with_exact_bytes(self):
        raw = json.dumps(page([segment("🐈" * 100000)]), ensure_ascii=False, indent=2).encode()
        result = self.fetch([Response(metadata()), Response(raw), Response(metadata())], total_timeout=2)
        self.assertEqual(result["raw_pages"], [raw])
        self.assertEqual(result["status"], "ready")
        self.assertEqual(len(self.calls()), 3)

    def test_retry_hint_is_returned_without_sleep_or_internal_retry(self):
        start = time.monotonic()
        for status, code in [(429, "rate_limited"), (503, "temporarily_unavailable")]:
            with self.subTest(status=status):
                self.log.unlink(missing_ok=True)
                error = urllib.error.HTTPError("x", status, "grn_SECRET", {"Retry-After": "600"}, None)
                with self.assertRaises(SourceError) as caught:
                    self.fetch([error], total_timeout=1)
                self.assertEqual((caught.exception.code, caught.exception.retry_after), (code, 600))
                self.assertEqual(len(self.calls()), 1)
                self.assertNotIn("grn_", str(caught.exception))
        self.assertLess(time.monotonic() - start, 1)

    def test_invalid_time_budget_rejects_before_callbacks(self):
        for value in [0, -1, True, "1", None, float("nan"), float("inf"), 301, 10 ** 1000]:
            with self.subTest(value=value):
                callback = Mock(side_effect=AssertionError("must not access source"))
                with self.assertRaises(SourceError) as caught:
                    retrieve_source(NOTE, OWNER, credential=callback, total_timeout=value)
                self.assertEqual(caught.exception.code, "invalid_request")
                callback.assert_not_called()

    def test_fresh_interpreter_worker_success_timeout_and_error_cleanup(self):
        for mode, expected in [("ready", None), ("timeout", "temporarily_unavailable"),
                               ("unauthorized", "unauthorized")]:
            with self.subTest(mode=mode), self.native_fixture(mode):
                if expected:
                    with self.assertRaises(SourceError) as caught:
                        self.native_fetch(total_timeout=0.5)
                    self.assertEqual(caught.exception.code, expected)
                else:
                    result = self.native_fetch(total_timeout=2)
                    self.assertEqual(result["status"], "ready")
                    self.assertEqual(result["segments"], [segment()])

    def test_stalled_credential_callback_is_also_bounded(self):
        def slow_credential():
            time.sleep(2)
            return "grn_SYNTHETIC"
        start = time.monotonic()
        with self.assertRaises(SourceError) as caught:
            retrieve_source(NOTE, OWNER, credential=slow_credential,
                            opener=Mock(), total_timeout=0.3)
        self.assertEqual((caught.exception.code, caught.exception.retry_after), ("temporarily_unavailable", 60))
        self.assertLess(time.monotonic() - start, 1)

    def test_partial_ipc_and_crashed_worker_cannot_return_success(self):
        for worker, expected in [(partial_worker, "temporarily_unavailable"),
                                 (interrupted_worker, "invalid_source")]:
            with self.subTest(expected=expected), patch("source._source_worker", worker):
                with self.assertRaises(SourceError) as caught:
                    self.fetch([], total_timeout=0.3)
                self.assertEqual(caught.exception.code, expected)

    def test_caller_cancellation_reaps_worker(self):
        with patch("source.select.select", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.fetch([TimedResponse(metadata(), 2)], total_timeout=1)

    def test_fork_fixture_seam_rejects_threaded_callers_before_effects(self):
        errors = []
        def invoke():
            try:
                self.fetch([Response(metadata())])
            except SourceError as error:
                errors.append(error.code)
        thread = threading.Thread(target=invoke)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["invalid_request"])
        self.assertEqual(self.calls(), [])

    def test_native_dependency_paths_select_subprocess_without_accessing_them(self):
        config = {"keychain_service": "test.granola", "keychain_account": OWNER}
        for options in [dict(config=config), dict(credential=synthetic_credential),
                        dict(config=config, opener=RecordedOpener([], str(self.log)))]:
            with self.subTest(keys=list(options)), patch.object(source._Worker, "launch_native",
                                                               side_effect=OSError("grn_SECRET")) as launch:
                with self.assertRaises(SourceError) as caught:
                    retrieve_source(NOTE, OWNER, **options)
                if len(options) == 1 and "config" in options:
                    self.assertEqual(str(caught.exception), "invalid_source")
                    launch.assert_called_once()
                else:
                    self.assertEqual(str(caught.exception), "invalid_request")
                    launch.assert_not_called()

    def test_oversized_bootstrap_fields_fail_before_worker_creation(self):
        with patch.object(source._Worker, "launch_native") as context:
            with self.assertRaises(SourceError) as caught:
                retrieve_source(NOTE, "x" * 255, credential=synthetic_credential)
            self.assertEqual(caught.exception.code, "invalid_request")
            with self.assertRaises(SourceError) as caught:
                retrieve_source(NOTE, OWNER, config={"keychain_service": "x" * 255,
                                                   "keychain_account": OWNER})
            self.assertEqual(caught.exception.code, "invalid_source")
            context.assert_called_once()

    def test_partial_injection_rejects_without_serializing_callback(self):
        start = time.monotonic()
        with self.assertRaises(SourceError) as caught:
            retrieve_source(NOTE, OWNER, credential=SlowSerializationCredential(str(self.log)),
                            total_timeout=0.2)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 0.7)
        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertFalse(self.log.exists())

    def test_launch_cancellation_reaps_actual_pid_for_both_start_methods(self):
        for native in (True, False):
            name = "launch_native" if native else "launch_fixture"
            original = getattr(source._Worker, name)
            pids = []
            def cancel_after_launch(worker, *args):
                original(worker, *args)
                pids.append(worker.pid)
                raise KeyboardInterrupt
            with self.subTest(native=native), self.native_fixture(), \
                    patch.object(source._Worker, name, cancel_after_launch):
                try:
                    with self.assertRaises(KeyboardInterrupt):
                        if native:
                            self.native_fetch(total_timeout=0.3)
                        else:
                            self.fetch([TimedResponse(metadata(), 2)], total_timeout=0.3)
                    self.assertEqual(len(pids), 1)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pids[0], 0)
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(pids[0], os.WNOHANG)
                    calls = self.calls()
                    time.sleep(0.05)
                    self.assertEqual(self.calls(), calls)
                finally:
                    for pid in pids:
                        try: os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        try: os.waitpid(pid, 0)
                        except ChildProcessError: pass

    def test_sigint_during_os_launch_is_deferred_until_pid_is_owned(self):
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        for native in (True, False):
            pids = []
            continued = []
            if native:
                original = subprocess.Popen.__init__
                def interrupt(obj, *args, **kwargs):
                    original(obj, *args, **kwargs)
                    pids.append(obj.pid)
                    os.kill(os.getpid(), signal.SIGINT)
                    continued.append(True)
                injection = patch.object(subprocess.Popen, "__init__", interrupt)
            else:
                original = os.fork
                def interrupt():
                    pid = original()
                    if pid:
                        pids.append(pid)
                        os.kill(os.getpid(), signal.SIGINT)
                        continued.append(True)
                    return pid
                injection = patch("source.os.fork", interrupt)
            with self.subTest(native=native), self.native_fixture(), injection:
                try:
                    with self.assertRaises(KeyboardInterrupt):
                        if native:
                            self.native_fetch(total_timeout=0.3)
                        else:
                            self.fetch([TimedResponse(metadata(), 2)], total_timeout=0.3)
                    self.assertEqual(continued, [True])
                    self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
                    self.assertEqual(len(pids), 1)
                    with self.assertRaises(ProcessLookupError): os.kill(pids[0], 0)
                    with self.assertRaises(ChildProcessError): os.waitpid(pids[0], os.WNOHANG)
                finally:
                    for pid in pids:
                        try: os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        try: os.waitpid(pid, 0)
                        except ChildProcessError: pass

    def test_fully_injected_callbacks_are_never_serialized(self):
        serialize_log = Path(self.tmp.name) / "serialization"
        opener = RecordedOpener([Response(metadata()), Response(page([segment()])), Response(metadata())],
                                str(self.log))
        result = retrieve_source(NOTE, OWNER, credential=SlowSerializationCredential(str(serialize_log)),
                                 opener=opener, total_timeout=0.5)
        self.assertEqual(result["status"], "ready")
        self.assertFalse(serialize_log.exists())

    def test_launch_exception_before_pid_is_sanitized_and_closes_handle(self):
        for native in (True, False):
            target = "source.subprocess.Popen.__init__" if native else "source.os.fork"
            with self.subTest(native=native), patch(target, side_effect=OSError("grn_SECRET")):
                with self.assertRaises(SourceError) as caught:
                    if native:
                        self.native_fetch()
                    else:
                        self.fetch([])
                self.assertEqual(str(caught.exception), "invalid_source")

    def test_native_main_with_sibling_and_nonmain_callers_reject_before_launch(self):
        stop = threading.Event()
        sibling = threading.Thread(target=lambda: stop.wait(3))
        sibling.start()
        try:
            with patch.object(source._Worker, "launch_native") as launch:
                with self.assertRaises(SourceError) as caught:
                    self.native_fetch(total_timeout=0.2)
                self.assertEqual(caught.exception.code, "invalid_request")
                errors = []
                def call():
                    try: self.native_fetch(total_timeout=0.2)
                    except SourceError as error: errors.append(error.code)
                caller = threading.Thread(target=call)
                caller.start()
                caller.join(1)
                self.assertFalse(caller.is_alive())
                self.assertEqual(errors, ["invalid_request"])
                launch.assert_not_called()
                self.assertEqual(self.worker_pids, [])
        finally:
            stop.set()
            sibling.join(1)

    def test_full_parent_stdout_pipe_does_not_delay_either_launch(self):
        for native in (True, False):
            with self.subTest(native=native), self.native_fixture():
                reader, writer = os.pipe()
                os.set_blocking(writer, False)
                filled = 0
                try:
                    while True: filled += os.write(writer, b"x" * 4096)
                except BlockingIOError: pass
                os.set_blocking(writer, True)
                drainer = os.fork()
                if drainer == 0:
                    os.close(writer)
                    time.sleep(1.2)
                    os.read(reader, filled)
                    os.close(reader)
                    os._exit(0)
                buffered = os.fdopen(writer, "w", buffering=8192)
                buffered.write("synthetic buffered log\n")
                original_stdout = sys.stdout
                start = time.monotonic()
                try:
                    sys.stdout = buffered
                    with self.assertRaises(SourceError) as caught:
                        if native:
                            self.native_fetch(total_timeout=0.2)
                        else:
                            self.fetch([TimedResponse(metadata(), 2)], total_timeout=0.2)
                    elapsed = time.monotonic() - start
                    self.assertEqual(caught.exception.code, "temporarily_unavailable")
                    self.assertLess(elapsed, 0.75)
                finally:
                    sys.stdout = original_stdout
                    buffered.close()
                    os.close(reader)
                    os.waitpid(drainer, 0)
                with self.assertRaises(ProcessLookupError): os.kill(drainer, 0)
                with self.assertRaises(ChildProcessError): os.waitpid(drainer, os.WNOHANG)

    def test_native_constructor_cancellation_retains_popen_pid(self):
        original = subprocess.Popen.__init__
        pids = []
        def cancel(obj, *args, **kwargs):
            original(obj, *args, **kwargs)
            pids.append(obj.pid)
            raise KeyboardInterrupt
        with self.native_fixture(), patch.object(subprocess.Popen, "__init__", cancel):
            with self.assertRaises(KeyboardInterrupt): self.native_fetch(total_timeout=0.2)
        self.assertEqual(len(pids), 1)
        with self.assertRaises(ProcessLookupError): os.kill(pids[0], 0)
        with self.assertRaises(ChildProcessError): os.waitpid(pids[0], os.WNOHANG)


def synthetic_native_main():
    result_fd = sys.argv[2]
    log, mode = sys.argv[3:5]
    responses = ([TimedResponse(metadata(), 2)] if mode == "timeout" else
                 [UnauthorizedResponse({})] if mode == "unauthorized" else
                 [Response(metadata()), Response(page([segment()])), Response(metadata())])
    # Inject only inside this fresh interpreter, then exercise the actual native
    # bootstrap/credential/HTTP path. No callback crosses the parent spawn boundary.
    source.file_credential = lambda: synthetic_credential()
    source.urllib.request.build_opener = lambda *args: RecordedOpener(responses, log)
    sys.argv = [source.__file__, "--source-worker", result_fd]
    os._exit(source._native_main())


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--synthetic-worker":
        try:
            synthetic_native_main()
        except BaseException:
            os._exit(1)
        os._exit(0)
    unittest.main()
