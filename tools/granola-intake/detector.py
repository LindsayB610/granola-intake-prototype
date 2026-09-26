"""Bounded Granola discovery. No service is installed by this module."""

import hashlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
OPERATION = re.compile(r"[0-9a-f]{64}")
CONFIG_KEYS = {"owner_email", "activation_cutoff", "dispatcher_thread", "dispatcher_host",
               "codex_path", "state_dir", "max_pages", "max_wakes"}
LEGACY_CREDENTIAL_KEYS = {"keychain_service", "keychain_account"}
SAFE_FAILURES = {"Granola API access unavailable", "Granola API credential unavailable",
                 "invalid API page", "invalid API response", "cursor loop", "wake outcome uncertain",
                 "API request rejected", "API redirect rejected", "API response exceeds size limit",
                 "API response rejected", "API credential reflection rejected", "ledger operation failed"}


class DetectorError(RuntimeError):
    """Sanitized failure; never include a provider response or secret."""


class RetryLater(DetectorError):
    def __init__(self, seconds=60):
        super().__init__("API temporarily unavailable")
        self.seconds = min(86400, max(60, seconds))


def validate_config(config):
    try:
        if (not isinstance(config, dict)
                or set(config) not in (CONFIG_KEYS, CONFIG_KEYS | LEGACY_CREDENTIAL_KEYS)):
            raise ValueError()
        if config["dispatcher_host"] != "local" or not UUID.fullmatch(config["dispatcher_thread"]):
            raise ValueError()
        if not re.fullmatch(r"[^\s@]{1,120}@[^\s@]{1,120}", config["owner_email"]):
            raise ValueError()
        timestamp(config["activation_cutoff"])
        for key, limit in (("max_pages", 10), ("max_wakes", 10)):
            if type(config[key]) is not int or not 1 <= config[key] <= limit:
                raise ValueError()
        # Legacy Keychain selector fields remain accepted during migration so
        # existing ledgers keep their configuration digest. They are ignored by
        # credential lookup and must not appear in new config files.
        for key in LEGACY_CREDENTIAL_KEYS & set(config):
            if not isinstance(config[key], str) or not re.fullmatch(r"[A-Za-z0-9@._+ -]{1,254}", config[key]):
                raise ValueError()
        for key in ("state_dir", "codex_path"):
            path = Path(config[key])
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError()
        binary = Path(config["codex_path"])
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError()
    except (ValueError, TypeError, KeyError, OSError):
        raise DetectorError("invalid configuration") from None


def no_symlinks(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            raise DetectorError("unsafe state path")


def private_file(path):
    no_symlinks(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise DetectorError("unsafe state file")


def private_root(config):
    root = Path(config["state_dir"])
    no_symlinks(root)
    if not root.exists():
        root.mkdir(mode=0o700)  # Its explicit parent must already exist.
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise DetectorError("unsafe state directory")
    return root


def is_paused(config):
    """A missing marker is active; a malformed or unsafe marker fails closed."""
    marker = Path(config["state_dir"]) / "paused.json"
    if not marker.exists() and not marker.is_symlink():
        return False
    private_file(marker)
    if marker.read_bytes() != b'{"schema_version":1,"paused":true}\n':
        raise DetectorError("invalid pause marker")
    return True


@contextmanager
def locked(config):
    validate_config(config)
    root = private_root(config)
    lock = root / "worker.lock"
    if lock.exists() or lock.is_symlink():
        private_file(lock)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        private_file(lock)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield None
            return
        db = open_ledger(config)
        try:
            yield db
        finally:
            db.close()
    finally:
        os.close(fd)


def status(config, operation=None, offset=0):
    if (operation is not None and (not isinstance(operation, str) or not OPERATION.fullmatch(operation))
            or type(offset) is not int or not 0 <= offset <= 10000000):
        raise DetectorError("invalid status query")
    with locked(config) as db:
        if db is None:
            return {"outcome": "already-running"}
        if operation:
            rows = db.execute("SELECT * FROM operations WHERE operation_id=?", (operation,)).fetchall()
        else:
            rows = db.execute("SELECT * FROM operations ORDER BY CASE state WHEN 'uncertain' THEN 0 "
                              "WHEN 'pending' THEN 1 ELSE 2 END,created_at,operation_id LIMIT 100 OFFSET ?",
                              (offset,)).fetchall()
        return {"outcome": "status", "operations": [dict(row) for row in rows], "offset": offset,
                "counts": {row[0]: row[1] for row in db.execute("SELECT state,COUNT(*) FROM operations GROUP BY state")},
                "operation_count": db.execute("SELECT COUNT(*) FROM operations").fetchone()[0],
                "cycle_in_progress": meta(db, "cycle") is not None,
                "retry_at": meta(db, "retry_at"), "last_failure": meta(db, "last_failure"),
                "last_run": meta(db, "last_run")}


def reconcile(config, operation, evidence_path, confirmed=False, now=None):
    if not confirmed or not isinstance(operation, str) or not OPERATION.fullmatch(operation):
        raise DetectorError("native evidence confirmation required")
    try:
        path = Path(evidence_path)
        private_file(path)
        if path.stat().st_size > 8192:
            raise ValueError()
        evidence = json.loads(path.read_text())
        expected = {"schema_version", "operation_id", "attempt_id", "dispatcher_thread", "outcome", "observed_at", "turn_id", "reference"}
        if (set(evidence) != expected or evidence["schema_version"] != 1
                or evidence["operation_id"] != operation
                or evidence["dispatcher_thread"] != config["dispatcher_thread"]
                or evidence["outcome"] not in ("accepted", "not_sent")
                or not UUID.fullmatch(evidence["attempt_id"])
                or not UUID.fullmatch(evidence["turn_id"])
                or evidence["reference"] != "codex://threads/" + config["dispatcher_thread"]):
            raise ValueError()
        observed = timestamp(evidence["observed_at"])
        current = timestamp(now) if now else datetime.now(timezone.utc)
        if observed > current or current - observed > timedelta(days=7):
            raise ValueError()
    except (OSError, ValueError, TypeError, KeyError):
        raise DetectorError("invalid reconciliation evidence") from None
    with locked(config) as db:
        if db is None:
            raise DetectorError("worker busy")
        row = db.execute("SELECT * FROM operations WHERE operation_id=?", (operation,)).fetchone()
        if not row or row["state"] != "uncertain":
            raise DetectorError("invalid transition")
        attempt = db.execute("SELECT * FROM attempts WHERE attempt_id=?",
                             (evidence["attempt_id"],)).fetchone()
        if (row["attempt_id"] != evidence["attempt_id"] or attempt is None or
                attempt["operation_id"] != operation or attempt["state"] != "uncertain" or
                attempt["attempted_at"] != row["attempted_at"]):
            raise DetectorError("attempt mismatch")
        if observed < timestamp(row["attempted_at"]):
            raise DetectorError("evidence precedes attempt")
        attestation = {"kind": "operator-attested", "outcome": evidence["outcome"],
                       "attempt_id": evidence["attempt_id"],
                       "observed_at": evidence["observed_at"], "turn_id": evidence["turn_id"],
                       "reference": evidence["reference"]}
        with db:
            db.execute("UPDATE attempts SET state=?,evidence=? WHERE attempt_id=?",
                       (evidence["outcome"], json.dumps(attestation, sort_keys=True), row["attempt_id"]))
            db.execute("UPDATE operations SET state=?,evidence=? WHERE operation_id=?",
                       ("accepted" if evidence["outcome"] == "accepted" else "pending",
                        json.dumps(attestation, sort_keys=True), operation))
        return True


def timestamp(value):
    if (not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value)):
        raise ValueError("invalid timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timezone required")
    return result.astimezone(timezone.utc)


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def validate_page(value):
    try:
        if (not isinstance(value, dict) or type(value.get("hasMore")) is not bool
                or not isinstance(value.get("notes"), list) or len(value["notes"]) > 30):
            raise ValueError()
        cursor = value["cursor"]
        if value["hasMore"]:
            if not isinstance(cursor, str) or not 0 < len(cursor) <= 4096 or any(ord(c) < 32 for c in cursor):
                raise ValueError()
        elif cursor is not None:
            raise ValueError()
        for item in value["notes"]:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    or not re.fullmatch(r"not_[A-Za-z0-9]{14}", item["id"])
                    or not isinstance(item.get("owner"), dict)
                    or not isinstance(item["owner"].get("email"), str)
                    or not 0 < len(item["owner"]["email"]) <= 254):
                raise ValueError()
            timestamp(item["created_at"])
            timestamp(item["updated_at"])
        return value
    except (TypeError, ValueError, KeyError, OverflowError):
        raise DetectorError("invalid API page") from None


def operation_id(note_id):
    return hashlib.sha256(("granola-initial-v1:" + note_id).encode()).hexdigest()


def open_ledger(config):
    root = Path(config["state_dir"])
    path = root / "ledger.sqlite3"
    new = not path.exists() and not path.is_symlink()
    if new:
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
    private_file(path)
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            private_file(sidecar)
    db = sqlite3.connect(path, timeout=1)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA synchronous=FULL")
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, 1) or (version == 0 and db.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]):
        db.close()
        raise DetectorError("unsupported ledger version")
    db.execute("""CREATE TABLE IF NOT EXISTS operations (
        operation_id TEXT PRIMARY KEY, note_id TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL, state TEXT NOT NULL, attempted_at TEXT,
        evidence TEXT, attempt_id TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS attempts (
        attempt_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
        attempted_at TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT)""")
    db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS cursors (value TEXT PRIMARY KEY)")
    binding_keys = CONFIG_KEYS | (LEGACY_CREDENTIAL_KEYS & set(config))
    binding = hashlib.sha256(json.dumps({key: config[key] for key in sorted(binding_keys - {"max_pages", "max_wakes"})},
                                       sort_keys=True).encode()).hexdigest()
    if meta(db, "binding", binding) != binding:
        db.close()
        raise DetectorError("configuration binding changed")
    with db:
        set_meta(db, "binding", binding)
        db.execute("PRAGMA user_version=1")
    return db


def meta(db, key, default=None):
    row = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def set_meta(db, key, value):
    db.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, json.dumps(value)))


def run_once(config, api, queue, now):
    """Discover and wake eligible operations through injected boundaries."""
    validate_config(config)
    try:
        current = timestamp(now)
        if current <= timestamp(config["activation_cutoff"]):
            return {"outcome": "before-activation", "discovered": 0, "accepted": 0}
    except (TypeError, ValueError):
        raise DetectorError("invalid current time") from None
    with locked(config) as db:
        if db is None:
            return {"outcome": "already-running", "discovered": 0, "accepted": 0}
        if is_paused(config):
            return {"outcome": "paused", "discovered": 0, "accepted": 0}
        try:
            result = run_locked(config, api, queue, now, db)
            with db:
                set_meta(db, "last_run", {"at": now, "outcome": result["outcome"]})
                db.execute("DELETE FROM metadata WHERE key='last_failure'")
            return result
        except Exception as error:
            code = str(error) if isinstance(error, DetectorError) and str(error) in SAFE_FAILURES else "detector operation failed"
            try:
                with db:
                    set_meta(db, "last_failure", {"at": now, "code": code})
            except sqlite3.Error:
                pass
            raise DetectorError(code) from None


def run_locked(config, api, queue, now, db):
    discovered = accepted = 0
    try:
        due = meta(db, "retry_at")
        if due and timestamp(now) < timestamp(due):
            return {"outcome": "backoff", "discovered": 0, "accepted": 0, "retry_at": due}
        cutoff = timestamp(config["activation_cutoff"])
        cycle = meta(db, "cycle", {"before": now, "cursor": None})
        for _ in range(config["max_pages"]):
            params = {"created_after": iso(cutoff - timedelta(seconds=1)),
                      "created_before": cycle["before"], "page_size": 30}
            if cycle["cursor"]:
                params["cursor"] = cycle["cursor"]
            result = validate_page(api.list_notes(params))
            cursor = result["cursor"]
            if cursor and db.execute("SELECT 1 FROM cursors WHERE value=?", (cursor,)).fetchone():
                raise DetectorError("cursor loop")
            with db:
                db.execute("DELETE FROM metadata WHERE key='retry_at'")
                for item in result["notes"]:
                    if (item["owner"]["email"] == config["owner_email"]
                            and cutoff <= timestamp(item["created_at"]) < timestamp(cycle["before"])):
                        inserted = db.execute(
                            "INSERT OR IGNORE INTO operations VALUES (?,?,?,'pending',NULL,NULL,NULL)",
                            (operation_id(item["id"]), item["id"], item["created_at"]))
                        discovered += inserted.rowcount
                if cursor:
                    db.execute("INSERT INTO cursors VALUES (?)", (cursor,))
                    cycle["cursor"] = cursor
                    set_meta(db, "cycle", cycle)
                else:
                    db.execute("DELETE FROM cursors")
                    db.execute("DELETE FROM metadata WHERE key='cycle'")
            if not cursor:
                break
        for row in db.execute("SELECT operation_id FROM operations WHERE state='pending' ORDER BY created_at,operation_id LIMIT ?",
                              (config["max_wakes"],)).fetchall():
            _attempt(db, row["operation_id"], queue, now)
            accepted += 1
        return {"outcome": "work" if discovered or accepted else "idle",
                "discovered": discovered, "accepted": accepted}
    except RetryLater as error:
        due = iso(timestamp(now) + timedelta(seconds=error.seconds))
        with db:
            set_meta(db, "retry_at", due)
        return {"outcome": "backoff", "discovered": discovered, "accepted": accepted, "retry_at": due}
    except sqlite3.Error:
        raise DetectorError("ledger operation failed") from None


def _attempt(db, operation, queue, now):
    """The shared durable fence for discovery and exact-note notices."""
    attempt = str(uuid.uuid4())
    with db:
        db.execute("INSERT INTO attempts VALUES (?,?,?,'uncertain',NULL)", (attempt, operation, now))
        db.execute("UPDATE operations SET state='uncertain',attempted_at=?,attempt_id=?,evidence=NULL WHERE operation_id=?",
                   (now, attempt, operation))
    try:
        notice_receipt = queue({"operation_id": operation, "attempt_id": attempt})
        if notice_receipt is not None and not (
                type(notice_receipt) is dict and set(notice_receipt) ==
                {'kind', 'thread_id', 'recipient_status', 'processing'} and
                notice_receipt['kind'] == 'native-notice-accepted' and
                type(notice_receipt['thread_id']) is str and
                UUID.fullmatch(notice_receipt['thread_id']) and
                notice_receipt['recipient_status'] in ('idle', 'active') and
                notice_receipt['processing'] == 'unobserved'):
            raise DetectorError('invalid notice acceptance')
    except Exception:
        raise DetectorError("wake outcome uncertain") from None
    with db:
        evidence = json.dumps(dict(notice_receipt, attempt_id=attempt) if notice_receipt
                              else {"kind": "queue-exit-success", "attempt_id": attempt},
                              sort_keys=True)
        db.execute("UPDATE operations SET state='accepted',evidence=? WHERE operation_id=?", (evidence, operation))
        db.execute("UPDATE attempts SET state='accepted',evidence=? WHERE attempt_id=?", (evidence, attempt))


def run_exact(config, note_id, created_at, queue, now, *, recovery=False):
    """Fence one source-verified note without discovery or a cutoff change.

    A pre-cutoff note requires the separately selected recovery mode. Existing
    operations, including pending/uncertain ones, are never retried here.
    """
    validate_config(config)
    if type(note_id) is not str or not re.fullmatch(r'not_[A-Za-z0-9]{14}', note_id):
        raise DetectorError('invalid exact note')
    try:
        created = timestamp(created_at)
        current = timestamp(now)
        cutoff = timestamp(config['activation_cutoff'])
    except (TypeError, ValueError):
        raise DetectorError('invalid exact time') from None
    if (created > current or (created < cutoff and not recovery) or
            (created >= cutoff and recovery)):
        raise DetectorError('exact note outside selected window')
    with locked(config) as db:
        if db is None:
            raise DetectorError('worker busy')
        if is_paused(config):
            return {'outcome':'paused','accepted':0}
        operation = operation_id(note_id)
        row = db.execute('SELECT note_id,state FROM operations WHERE operation_id=? OR note_id=?',
                         (operation,note_id)).fetchone()
        if row is not None:
            if row['note_id'] != note_id:
                raise DetectorError('exact identity conflict')
            return {'outcome':'existing','operation_id':operation,'state':row['state'],'accepted':0}
        with db:
            db.execute("INSERT INTO operations VALUES (?,?,?,'pending',NULL,NULL,NULL)",
                       (operation,note_id,iso(created)))
        _attempt(db,operation,queue,iso(current))
        return {'outcome':'accepted','operation_id':operation,'accepted':1}


def retry_not_sent_held(config, operation, queue, now):
    """Retry only a positively not-sent operation, without listing notes."""
    validate_config(config)
    if type(operation) is not str or not OPERATION.fullmatch(operation) or not callable(queue):
        raise DetectorError('invalid held retry')
    try:
        stamp = iso(timestamp(now))
    except (TypeError, ValueError):
        raise DetectorError('invalid held retry') from None
    with locked(config) as db:
        if db is None:
            raise DetectorError('worker busy')
        if is_paused(config):
            return {'outcome':'paused','accepted':0}
        row = db.execute('SELECT * FROM operations WHERE operation_id=?',(operation,)).fetchone()
        try:
            proof = json.loads(row['evidence']) if row is not None else None
        except (TypeError, ValueError):
            proof = None
        attempt = (db.execute('SELECT * FROM attempts WHERE attempt_id=?',
                              (row['attempt_id'],)).fetchone() if row is not None and
                   row['attempt_id'] is not None else None)
        try:
            attempt_proof = json.loads(attempt['evidence']) if attempt is not None else None
        except (TypeError, ValueError):
            attempt_proof = None
        if (row is None or row['state'] != 'pending' or
                operation_id(row['note_id']) != operation or
                type(proof) is not dict or proof.get('kind') != 'operator-attested' or
                proof.get('outcome') != 'not_sent' or
                proof.get('attempt_id') != row['attempt_id'] or
                attempt is None or attempt['operation_id'] != operation or
                attempt['state'] != 'not_sent' or attempt['attempted_at'] != row['attempted_at'] or
                type(attempt_proof) is not dict or attempt_proof != proof):
            raise DetectorError('held retry unverified')
        _attempt(db,operation,queue,stamp)
        return {'outcome':'accepted','operation_id':operation,'accepted':1}
