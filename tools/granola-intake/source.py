"""Bounded retrieval of a selected Granola REST transcript representation."""
import hashlib
import json
import math
import os
import pickle
import re
import select
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

if __name__ == "__main__":
    # Isolated (-I -S) child imports only its adjacent maintained modules.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from adapters import NoRedirect, file_credential
from detector import DetectorError, timestamp


NOTE_ID = re.compile(r"not_[A-Za-z0-9]{14}\Z")
TOKEN = re.compile(r"grn_[A-Za-z0-9_-]{1,4092}\Z")
ORIGIN = "https://public-api.granola.ai/v1/notes/"


class SourceError(RuntimeError):
    def __init__(self, code, retry_after=None):
        super().__init__(code)
        self.code = code
        self.retry_after = retry_after


BOOTSTRAP_LIMIT = 8192


def _native_command(result_fd):
    return [sys.executable, "-I", "-S", "-B", os.path.abspath(__file__),
            "--source-worker", str(result_fd)]


class _Worker:
    """Own the OS child independently of a launch function's return value."""
    def __init__(self):
        self.process = None
        self.fork_pid = None
        self.returncode = None

    @property
    def pid(self):
        return getattr(self.process, "pid", None) if self.process is not None else self.fork_pid

    def launch_native(self, writer):
        # Retain the Popen object before __init__ can create a child and raise.
        # No multiprocessing, preexec_fn, parent stream flush, callback pickle,
        # user site import, or caller-main-module re-import occurs here.
        self.process = subprocess.Popen.__new__(subprocess.Popen)
        subprocess.Popen.__init__(self.process, _native_command(writer.fileno()),
                                  stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, bufsize=0,
                                  close_fds=True, pass_fds=(writer.fileno(),))

    def launch_fixture(self, reader, writer, previous_mask, args):
        self.fork_pid = os.fork()
        if self.fork_pid == 0:
            try:
                reader.close()
                with open(os.devnull, "wb") as sink:
                    os.dup2(sink.fileno(), 1)
                    os.dup2(sink.fileno(), 2)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                _source_worker(writer, *args)
            except BaseException:
                os._exit(1)
            os._exit(0)  # Never flush inherited parent Python streams/atexit hooks.

    def poll(self):
        if self.process is not None:
            return self.process.poll()
        if self.returncode is None:
            pid, status = os.waitpid(self.fork_pid, os.WNOHANG)
            if pid:
                self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait_until(self, deadline):
        while self.poll() is None:
            time.sleep(min(0.005, _remaining(deadline)))
        return self.poll()

    def close(self):
        if self.pid is not None:
            if self.poll() is None:
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if self.process is not None:
                self.process.wait()
            elif self.returncode is None:
                _, status = os.waitpid(self.fork_pid, 0)
                self.returncode = os.waitstatus_to_exitcode(status)
        if self.process is not None and getattr(self.process, "stdin", None) is not None:
            self.process.stdin.close()  # bufsize=0: no deferred flush.


def _write_bootstrap(stream, payload, deadline):
    fd = stream.fileno()
    os.set_blocking(fd, False)
    pending = memoryview(payload)
    while pending:
        _, writable, _ = select.select([], [fd], [], _remaining(deadline))
        if not writable:
            raise SourceError("temporarily_unavailable", 60)
        pending = pending[os.write(fd, pending):]
    stream.close()


def _read_bootstrap():
    body = sys.stdin.buffer.read(BOOTSTRAP_LIMIT + 1)
    if len(body) > BOOTSTRAP_LIMIT:
        raise ValueError()
    return json.loads(body)


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError()


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SourceError("temporarily_unavailable", 60)
    return remaining


def _request(url, token, opener, limit, deadline):
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token,
                                                   "Accept": "application/json"}, method="GET")
    try:
        with opener.open(request, timeout=min(15, _remaining(deadline))) as response:
            if response.status != 200:
                raise SourceError("invalid_source")
            body = response.read(limit + 1)
            _remaining(deadline)
            if len(body) > limit:
                raise SourceError("oversize")
        value = json.loads(body, object_pairs_hook=_pairs_unique, parse_constant=_reject_constant)
        normalized = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if token.encode("ascii") in normalized:
            raise SourceError("invalid_source")
        return value, body
    except urllib.error.HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            raise SourceError("redirect") from None
        if error.code in (401, 403):
            raise SourceError("unauthorized") from None
        if error.code == 404:
            raise SourceError("not_ready_or_unavailable") from None
        if error.code == 413:
            raise SourceError("oversize") from None
        if error.code == 429 or error.code >= 500:
            raw = error.headers.get("Retry-After", "60") if error.headers else "60"
            delay = min(86400, max(60, int(raw))) if re.fullmatch(r"[0-9]{1,9}", raw) else 60
            raise SourceError("rate_limited" if error.code == 429 else "temporarily_unavailable", delay) from None
        raise SourceError("request_rejected") from None
    except SourceError:
        raise
    except DetectorError as error:
        raise SourceError("redirect" if str(error) == "API redirect rejected" else "credential_unavailable") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SourceError("temporarily_unavailable", 60) from None
    except Exception:
        raise SourceError("invalid_source") from None


def _metadata(value, note_id, owner_email):
    if not isinstance(value, dict) or value.get("id") != note_id or value.get("object") != "note":
        raise SourceError("invalid_source")
    owner = value.get("owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("email"), str):
        raise SourceError("invalid_source")
    if owner["email"] != owner_email:
        raise SourceError("wrong_owner")
    if not all(isinstance(value.get(key), str) and value[key] for key in ("created_at", "updated_at")):
        raise SourceError("invalid_source")
    return value


def _page(value):
    if not isinstance(value, dict) or type(value.get("hasMore")) is not bool or not isinstance(value.get("transcript"), list):
        raise SourceError("invalid_source")
    cursor = value.get("cursor")
    if value["hasMore"]:
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024:
            raise SourceError("invalid_source")
    elif cursor is not None:
        raise SourceError("invalid_source")
    for item in value["transcript"]:
        if (not isinstance(item, dict) or not isinstance(item.get("text"), str)
                or not isinstance(item.get("speaker"), dict)
                or not isinstance(item["speaker"].get("source"), str)):
            raise SourceError("invalid_source")
    return value


def validate_limits(max_pages, max_page_bytes, max_total_bytes):
    """Shared source policy bounds, checked before credential/provider access."""
    if (type(max_pages) is not int or not 1 <= max_pages <= 100
            or type(max_page_bytes) is not int or not 1 <= max_page_bytes <= 4 * 1024 * 1024
            or type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 32 * 1024 * 1024):
        raise SourceError("invalid_request")


def retrieve_source(note_id, owner_email, credential=None, opener=None, config=None,
                    max_pages=40, max_page_bytes=1024 * 1024,
                    max_total_bytes=8 * 1024 * 1024, total_timeout=60,
                    exact_mode=None, exact_cutoff=None):
    """Return transient canonical UTF-8 transcript JSON, never a saved artifact.

    Completion is bounded to the REST representation and a before/after note
    version check. Granola does not document an atomic cross-page snapshot.
    One worker owns credentials, HTTP, parsing and serialization. A parent-side
    monotonic deadline covers all stages, including blocked reads and IPC.
    Native dependencies use an isolated subprocess; fully injected fixtures use
    direct fork. Both require a single-threaded main-thread POSIX caller.
    """
    validate_limits(max_pages, max_page_bytes, max_total_bytes)
    if (exact_mode is None) != (exact_cutoff is None):
        raise SourceError("invalid_request")
    if exact_mode is not None:
        if exact_mode not in ("pilot", "recovery") or type(exact_cutoff) is not str:
            raise SourceError("invalid_request")
        try:
            timestamp(exact_cutoff)
        except ValueError:
            raise SourceError("invalid_request") from None
    if (type(total_timeout) not in (int, float) or not 0 < total_timeout <= 300
            or not math.isfinite(total_timeout)
            or type(note_id) is not str or not NOTE_ID.fullmatch(note_id)
            or type(owner_email) is not str or not 1 <= len(owner_email) <= 254):
        raise SourceError("invalid_request")
    # Native bootstrap never serializes caller code; fixtures supply both seams.
    if (credential is None) != (opener is None):
        raise SourceError("invalid_request")
    if credential is None and type(config) is not dict:
        raise SourceError("credential_unavailable")
    # The credential path is fixed beside this maintained module; no selector
    # or credential value crosses the worker boundary.
    config = {} if credential is None else None
    injected = credential is not None and opener is not None
    if (os.name != "posix" or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1):
        raise SourceError("invalid_request")
    deadline = time.monotonic() + total_timeout
    # Never fork the production local-file/urllib path on macOS. The fixture seam
    # is restricted to fork-safe synthetic callbacks in a controlled test host.
    reader = writer = worker = None
    chunks = []
    size = 0
    # Pickle contains only this worker's JSON-derived builtins/bytes, never a
    # provider-supplied pickle. Bound IPC independently of response/source caps.
    wire_limit = 4 * max_total_bytes + 4 * max_page_bytes + 1024 * 1024
    try:
        read_fd, write_fd = os.pipe()
        reader, writer = os.fdopen(read_fd, "rb", buffering=0), os.fdopen(write_fd, "wb", buffering=0)
        worker = _Worker()
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            if injected:
                worker.launch_fixture(reader, writer, previous,
                                      (deadline, note_id, owner_email, credential, opener, config,
                                       max_pages, max_page_bytes, max_total_bytes,
                                       exact_mode, exact_cutoff))
            else:
                payload = json.dumps({"deadline": deadline, "note_id": note_id,
                                      "owner_email": owner_email, "config": config,
                                      "max_pages": max_pages, "max_page_bytes": max_page_bytes,
                                      "max_total_bytes": max_total_bytes,
                                      "exact_mode": exact_mode, "exact_cutoff": exact_cutoff,
                                      "sigmask": sorted(int(item) for item in previous)}).encode("ascii")
                if len(payload) > BOOTSTRAP_LIMIT:
                    raise SourceError("invalid_request")
                worker.launch_native(writer)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        if not injected:
            _write_bootstrap(worker.process.stdin, payload, deadline)
        writer.close()
        os.set_blocking(reader.fileno(), False)
        while True:
            readable, _, _ = select.select([reader.fileno()], [], [], _remaining(deadline))
            if not readable:
                raise SourceError("temporarily_unavailable", 60)
            chunk = os.read(reader.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > wire_limit:
                raise SourceError("oversize")
            chunks.append(chunk)
        exitcode = worker.wait_until(deadline)
        _remaining(deadline)
        if exitcode != 0:
            raise SourceError("invalid_source")
        kind, result = pickle.loads(b"".join(chunks))
        _remaining(deadline)
        if kind == "error":
            raise SourceError(*result)
        if kind != "ready" or not isinstance(result, dict):
            raise SourceError("invalid_source")
        return result
    except SourceError:
        raise
    except Exception:
        raise SourceError("invalid_source") from None
    finally:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            if worker is not None:
                worker.close()
            if reader is not None:
                reader.close()
            if writer is not None:
                writer.close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _source_worker(writer, deadline, *args):
    # Even a dependency exception must not print provider text/credentials.
    with open(os.devnull, "wb") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        try:
            result = ("ready", _retrieve_source(*args, deadline=deadline))
        except SourceError as error:
            result = ("error", (error.code, error.retry_after))
        except BaseException:
            result = ("error", ("invalid_source", None))
        payload = memoryview(pickle.dumps(result, protocol=4))
        while payload:
            _remaining(deadline)
            payload = payload[os.write(writer.fileno(), payload[:65536]):]
    except (SourceError, OSError):
        pass  # Parent deadline/IPC failure owns the sanitized outcome.
    finally:
        writer.close()


def _check_exact_window(created_at, exact_mode, exact_cutoff):
    if exact_mode is None:
        return
    try:
        created = timestamp(created_at)
        cutoff = timestamp(exact_cutoff)
    except (TypeError, ValueError):
        raise SourceError("invalid_source") from None
    if (exact_mode == "pilot" and created < cutoff or
            exact_mode == "recovery" and created >= cutoff):
        raise SourceError("outside_exact_window")


def _retrieve_source(note_id, owner_email, credential, opener, config,
                     max_pages, max_page_bytes, max_total_bytes,
                     exact_mode=None, exact_cutoff=None, *, deadline):
    try:
        token = (credential or file_credential)()
    except Exception:
        raise SourceError("credential_unavailable") from None
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise SourceError("credential_unavailable")
    opener = opener or urllib.request.build_opener(NoRedirect())
    note_url = ORIGIN + note_id
    before_value, before_bytes = _request(note_url, token, opener, max_page_bytes, deadline)
    before = _metadata(before_value, note_id, owner_email)
    _check_exact_window(before["created_at"], exact_mode, exact_cutoff)
    segments = []
    raw_pages = []
    prior_pages = []
    raw_size = 0
    cursor = None
    seen = set()
    for index in range(max_pages):
        params = {"page_size": 100}
        if cursor is not None:
            params["cursor"] = cursor
        url = note_url + "/transcript?" + urllib.parse.urlencode(params)
        try:
            value, raw = _request(url, token, opener, max_page_bytes, deadline)
            result = _page(value)
        except SourceError as error:
            if error.code == "not_ready_or_unavailable" and index > 0:
                raise SourceError("missing_page") from None
            raise
        if not result["transcript"] and (result["hasMore"] or index > 0):
            raise SourceError("missing_page")
        if result["hasMore"] and result["cursor"] in seen:
            raise SourceError("cursor_loop")
        items = result["transcript"]
        if (any(items == earlier for earlier in prior_pages)
                or any(segments[-length:] == items[:length]
                       for length in range(1, min(len(segments), len(items)) + 1))):
            raise SourceError("inconsistent_pages")
        prior_pages.append(items)
        raw_size += len(raw)
        if raw_size > max_total_bytes:
            raise SourceError("oversize")
        raw_pages.append(raw)
        segments.extend(result["transcript"])
        representation = json.dumps({"transcript": segments}, ensure_ascii=False, allow_nan=False,
                                    separators=(",", ":")).encode("utf-8")
        if len(representation) > max_total_bytes:
            raise SourceError("oversize")
        if not result["hasMore"]:
            break
        cursor = result["cursor"]
        seen.add(cursor)
    else:
        raise SourceError("missing_page")
    if not segments or not any(item["text"] for item in segments):
        raise SourceError("empty_transcript")
    after_value, _ = _request(note_url, token, opener, max_page_bytes, deadline)
    after = _metadata(after_value, note_id, owner_email)
    _check_exact_window(after["created_at"], exact_mode, exact_cutoff)
    if (before["created_at"], before["updated_at"]) != (after["created_at"], after["updated_at"]):
        raise SourceError("source_changed")
    return {"status": "ready", "note_id": note_id, "owner_email": owner_email,
            "metadata": before, "updated_at": before["updated_at"], "segments": segments,
            "representation": representation, "sha256": hashlib.sha256(representation).hexdigest(),
            "raw_pages": raw_pages, "raw_page_sha256": [hashlib.sha256(raw).hexdigest() for raw in raw_pages],
            "raw_metadata": before_bytes,
            "page_count": index + 1, "representation_kind": "canonical-json-transcript-v1"}


def _native_main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--source-worker":
            return 2
        writer = os.fdopen(int(sys.argv[2]), "wb", buffering=0)
        params = _read_bootstrap()
        signal.pthread_sigmask(signal.SIG_SETMASK, params.pop("sigmask"))
        _remaining(params["deadline"])
        _source_worker(writer, params.pop("deadline"), params.pop("note_id"),
                       params.pop("owner_email"), None, None, params.pop("config"),
                       params.pop("max_pages"), params.pop("max_page_bytes"),
                       params.pop("max_total_bytes"), params.pop("exact_mode"),
                       params.pop("exact_cutoff"))
        return 0
    except BaseException:
        return 1  # Startup errors cannot print source, credential or config data.


if __name__ == "__main__":
    os._exit(_native_main())
