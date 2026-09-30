"""Fenced, local command handoff for one owner-configured receiver."""
import fcntl
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import threading
import time
import uuid

from portable_holding import HoldingStore, HoldingError

HEX = re.compile(r"[0-9a-f]{64}\Z")
DEST = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
MAX_REQUEST = 4096
GROUP_STOP_SECONDS = 0.5
_group_lock = threading.RLock()
_active_groups = set()
_terminating = False
_guard_state = "unused"
_main_spawning = False
_deferred_signals = []


class HandoffError(RuntimeError):
    """Content-free error code."""


def need(value, code):
    if not value:
        raise HandoffError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def checkout_root():
    module = Path(__file__).resolve().parent
    return module.parents[1] if module.name == "granola-intake" and module.parent.name == "tools" else module


def private_dir(path):
    p = Path(path)
    checkout = checkout_root()
    need(p.is_absolute() and str(p.resolve()) == str(p) and p.is_dir() and
         not p.is_symlink() and p.stat().st_uid == os.getuid() and
         not p.stat().st_mode & 0o077 and p != checkout and
         checkout not in p.parents, "unsafe_private_directory")


def config_check(config):
    need(type(config) is dict and set(config) == {"schema_version", "holding_root",
         "state_dir", "receipt_root", "destination_id", "command", "timeout_seconds"}
         and config["schema_version"] == 1 and
         type(config["destination_id"]) is str and DEST.fullmatch(config["destination_id"])
         and type(config["timeout_seconds"]) is int and
         1 <= config["timeout_seconds"] <= 300, "invalid_command_config")
    for key in ("holding_root", "state_dir", "receipt_root"):
        need(type(config[key]) is str, "invalid_command_config")
        private_dir(config[key])
    roots = [config[x] for x in ("holding_root", "state_dir", "receipt_root")]
    need(all(os.path.commonpath((a, b)) not in (a, b)
             for i, a in enumerate(roots) for b in roots[i + 1:]), "overlapping_private_roots")
    command = config["command"]
    need(type(command) is list and 1 <= len(command) <= 16 and
         all(type(part) is str and 0 < len(part) <= 1024 and "\x00" not in part
             for part in command) and sum(map(len, command)) <= 4096,
         "invalid_command_config")
    executable = Path(command[0])
    need(executable.is_absolute() and executable.is_file() and
         os.access(executable, os.X_OK),
         "command_unavailable")
    # Configuration is trusted owner input. Source text never supplies argv.
    return config


def load_config(path):
    target = Path(path)
    need(target.is_absolute() and str(target.resolve()) == str(target) and
         not target.is_symlink() and target != checkout_root() and
         checkout_root() not in target.parents, "unsafe_command_config")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             info.st_nlink == 1 and not info.st_mode & 0o077 and
             0 < info.st_size <= 8192, "unsafe_command_config")
        raw = os.read(fd, 8193)
        need(len(raw) == info.st_size, "unsafe_command_config")
        return config_check(json.loads(raw))
    finally:
        os.close(fd)


def source_claim(config, operation, expected_sha):
    need(type(operation) is str and HEX.fullmatch(operation) and
         type(expected_sha) is str and HEX.fullmatch(expected_sha), "invalid_source_pointer")
    try:
        held = HoldingStore.for_operation_resolution(config["holding_root"]).resolve_operation(operation)
        need(held["source_sha256"] == expected_sha, "source_changed")
        # resolve_operation opens and hashes every preserved component.
        return held["source_evidence_sha256"]
    except (HoldingError, OSError, ValueError, KeyError, TypeError):
        raise HandoffError("source_unavailable") from None


def _read_record(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             info.st_nlink == 1 and not info.st_mode & 0o077 and
             0 < info.st_size <= 8192, "unsafe_state")
        raw = os.read(fd, 8193)
        need(len(raw) == info.st_size, "unsafe_state")
        return json.loads(raw)
    finally:
        os.close(fd)


def _write_new(path, data):
    raw = canonical(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, raw) == len(raw), "state_write_failed")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _replace(path, data):
    tmp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    _write_new(tmp, data)
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _stop_command_group(process):
    # The receiver may have exited while one of its descendants remains.
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(GROUP_STOP_SECONDS)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            # macOS can report EPERM after the group has vanished.
            pass
        try:
            process.wait(timeout=GROUP_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=GROUP_STOP_SECONDS)


def _stop_active_groups():
    with _group_lock:
        for process in tuple(_active_groups):
            try:
                _stop_command_group(process)
            finally:
                _active_groups.discard(process)


def _drain_deferred_signals():
    # Only the installed guard can defer these signals. Dispatch after the
    # child has either been registered or stopped on a failed spawn.
    while _deferred_signals:
        signum, frame = _deferred_signals.pop(0)
        signal.getsignal(signum)(signum, frame)


@contextmanager
def sender_termination_guard():
    """Main-thread entry-point guard for commands launched by webhook workers."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("termination_guard_requires_main_thread")
    global _terminating, _guard_state
    with _group_lock:
        if _guard_state != "unused":
            raise RuntimeError("termination_guard_single_use")
        _guard_state = "active"
    previous = {signum: signal.getsignal(signum)
                for signum in (signal.SIGTERM, signal.SIGINT)}

    def terminate(signum, frame):
        global _terminating
        if _main_spawning:
            # Python runs this handler on the spawning main thread. Its RLock
            # would let it exit between Popen and registration.
            _terminating = True
            _deferred_signals.append((signum, frame))
            return
        with _group_lock:
            _terminating = True
        _stop_active_groups()
        prior = previous[signum]
        if callable(prior):
            prior(signum, frame)
            # A host handler may intentionally keep the service alive.
            with _group_lock:
                if _guard_state == "active":
                    _terminating = False
        else:
            raise SystemExit(128 + signum)

    for signum, prior in previous.items():
        if prior != signal.SIG_IGN:
            signal.signal(signum, terminate)
    try:
        yield
    finally:
        # Close admission before taking the cleanup snapshot. This state is
        # terminal for the sender process: a late daemon worker cannot start a
        # new receiver after the main thread restores its handlers or exits.
        with _group_lock:
            _guard_state = "closed"
            _terminating = True
        try:
            # A worker can still be running when the main guard unwinds on
            # KeyboardInterrupt or another exit. Reap it before restoration.
            _stop_active_groups()
        finally:
            for signum, prior in previous.items():
                signal.signal(signum, prior)
            with _group_lock:
                _deferred_signals.clear()


def _run_command_group(argv, *, input, stdout, stderr, timeout, check, close_fds):
    """Run one command in an owned session; stop its whole group on every exit."""
    global _main_spawning
    main_spawn = threading.current_thread() is threading.main_thread()
    process = None
    try:
        with _group_lock:
            if _terminating:
                raise HandoffError("sender_terminating")
            if main_spawn:
                _main_spawning = True
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout,
                                           stderr=stderr, close_fds=close_fds,
                                           start_new_session=True)
                _active_groups.add(process)
            except BaseException:
                if process is not None:
                    _stop_command_group(process)
                raise
            finally:
                if main_spawn:
                    _main_spawning = False
    finally:
        if main_spawn:
            _drain_deferred_signals()
    try:
        process.communicate(input=input, timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode)
    finally:
        with _group_lock:
            try:
                if process in _active_groups:
                    _stop_command_group(process)
            finally:
                _active_groups.discard(process)


class CommandHandoff:
    def __init__(self, config, *, runner=None, clock=time.time):
        self.config = config_check(config)
        self.runner = runner or _run_command_group
        self.clock = clock

    def _lock(self, operation):
        need(type(operation) is str and HEX.fullmatch(operation), "invalid_operation")
        root = Path(self.config["state_dir"])
        fd = os.open(root / (operation + ".lock"), os.O_RDWR | os.O_CREAT |
                     os.O_NOFOLLOW, 0o600)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             info.st_nlink == 1 and not info.st_mode & 0o077, "unsafe_state")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd, root / (operation + ".json")

    def preflight(self, operation=None):
        config_check(self.config)
        if operation is not None:
            held = HoldingStore.for_operation_resolution(self.config["holding_root"]).resolve_operation(operation)
            source_claim(self.config, operation, held["source_sha256"])
        return {"status": "ready", "destination_id": self.config["destination_id"]}

    def status(self, operation):
        fd, path = self._lock(operation)
        try:
            return _read_record(path) if path.exists() else None
        finally:
            os.close(fd)

    def deliver(self, operation):
        fd, path = self._lock(operation)
        try:
            need(not path.exists(), "existing_delivery_hold")
            self.preflight(operation)
            held = HoldingStore.for_operation_resolution(self.config["holding_root"]).resolve_operation(operation)
            claim = source_claim(self.config, operation, held["source_sha256"])
            request = {"schema_version": 1, "operation_id": operation,
                       "source_sha256": held["source_sha256"],
                       "source_evidence_sha256": claim,
                       "destination_id": self.config["destination_id"],
                       "attempt_id": uuid.uuid4().hex}
            binding = hashlib.sha256(canonical({"destination_id": self.config["destination_id"],
                                                "command": self.config["command"],
                                                "holding_root": self.config["holding_root"],
                                                "receipt_root": self.config["receipt_root"]})).hexdigest()
            record = {"schema_version": 1, "request": request, "binding_sha256": binding,
                      "executable_sha256": executable_hash(self.config),
                      "status": "uncertain", "reserved_at": self.clock()}
            _write_new(path, record)  # Durable fence precedes any command invocation.
            try:
                result = self.runner(self.config["command"], input=canonical(request),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=self.config["timeout_seconds"], check=False,
                    close_fds=True)
            except Exception:
                return {"status": "uncertain", "reason": "command_outcome_unknown"}
            record["status"] = "accepted_unobserved" if result.returncode == 0 else "uncertain"
            if result.returncode != 0:
                record["failure"] = "command_failed_or_partial"
            _replace(path, record)
            return {"status": record["status"]}
        finally:
            os.close(fd)

    def observe(self, operation):
        fd, path = self._lock(operation)
        try:
            need(path.exists(), "missing_delivery")
            record = _read_record(path)
            request = record["request"]
            binding = hashlib.sha256(canonical({"destination_id": self.config["destination_id"],
                                                "command": self.config["command"],
                                                "holding_root": self.config["holding_root"],
                                                "receipt_root": self.config["receipt_root"]})).hexdigest()
            need(record["binding_sha256"] == binding and request["operation_id"] == operation,
                 "delivery_binding_changed")
            need(record["executable_sha256"] == executable_hash(self.config),
                 "command_changed")
            need(source_claim(self.config, operation, request["source_sha256"]) ==
                 request["source_evidence_sha256"], "source_changed")
            receipt = read_receipt(self.config, request)
            record["status"] = "verified_received"
            record["receipt_sha256"] = hashlib.sha256(canonical(receipt)).hexdigest()
            _replace(path, record)
            return {"status": "verified_received", "receipt_sha256": record["receipt_sha256"]}
        finally:
            os.close(fd)


def _receipt_path(config, request):
    return Path(config["receipt_root"]) / (request["operation_id"] + ".json")


def executable_hash(config):
    path = config["command"][0]
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_receipt(config, request):
    """Call from the receiving process after reading the complete source."""
    config_check(config)
    need(type(request) is dict and set(request) == {"schema_version", "operation_id",
         "source_sha256", "source_evidence_sha256", "destination_id", "attempt_id"}
         and request["schema_version"] == 1 and
         request["destination_id"] == config["destination_id"] and
         type(request["attempt_id"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", request["attempt_id"]), "invalid_handoff_request")
    need(source_claim(config, request["operation_id"], request["source_sha256"]) ==
         request["source_evidence_sha256"], "source_changed")
    receipt = {"schema_version": 1, "operation_id": request["operation_id"],
               "source_sha256": request["source_sha256"],
               "source_evidence_sha256": request["source_evidence_sha256"],
               "destination_id": request["destination_id"],
               "attempt_id": request["attempt_id"], "complete_source_read": True}
    _write_new(_receipt_path(config, request), receipt)
    return receipt


def read_receipt(config, request):
    try:
        receipt = _read_record(_receipt_path(config, request))
    except FileNotFoundError:
        raise HandoffError("receipt_pending") from None
    need(receipt == {"schema_version": 1, "operation_id": request["operation_id"],
         "source_sha256": request["source_sha256"],
         "source_evidence_sha256": request["source_evidence_sha256"],
         "destination_id": request["destination_id"],
         "attempt_id": request["attempt_id"], "complete_source_read": True},
         "receipt_mismatch")
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("preflight", "deliver", "status", "observe"):
        item = sub.add_parser(action)
        item.add_argument("--operation", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    handoff = CommandHandoff(load_config(args.config))
    result = getattr(handoff, args.action)(args.operation)
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        with sender_termination_guard():
            main()
    except HandoffError as error:
        raise SystemExit(str(error)) from None
