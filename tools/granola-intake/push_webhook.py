"""Granola signed webhook receiver for the owner-configured local command.

The public request contains an opaque note ID only. Source and credentials stay
in the private holding store; the configured command receives the local handoff.
"""
import base64
import binascii
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time

EVENT = re.compile(r'[0-9a-fA-F-]{36}')
NOTE = re.compile(r'not_[A-Za-z0-9]{14}')
KINDS = {'note.generated', 'note.access_granted'}
MAX_BODY = 4096


class PushError(RuntimeError):
    """Fixed codes only; never includes provider content."""


def private_secret(path):
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 256):
        raise PushError('secret_unavailable')
    value = Path(path).read_text(encoding='ascii').strip()
    if not value.startswith('whsec_'):
        raise PushError('secret_unavailable')
    try:
        key = base64.b64decode(value[6:], validate=True)
    except (ValueError, binascii.Error):
        raise PushError('secret_unavailable') from None
    if len(key) < 16:
        raise PushError('secret_unavailable')
    return key


def verify(headers, body, key, now=None):
    """Verify raw bytes before JSON parsing, per Granola's Standard Webhooks format."""
    if type(body) is not bytes or not 0 < len(body) <= MAX_BODY:
        raise PushError('invalid_delivery')
    event_id = headers.get('webhook-id', '')
    timestamp = headers.get('webhook-timestamp', '')
    signatures = headers.get('webhook-signature', '')
    if not EVENT.fullmatch(event_id) or not timestamp.isascii() or not timestamp.isdecimal():
        raise PushError('invalid_delivery')
    stamp = int(timestamp)
    if abs((time.time() if now is None else now) - stamp) > 300:
        raise PushError('stale_delivery')
    expected = base64.b64encode(hmac.new(key, event_id.encode() + b'.' +
                                   timestamp.encode() + b'.' + body,
                                   hashlib.sha256).digest()).decode()
    supplied = [piece.split(',', 1)[1] for piece in signatures.split()
                if piece.startswith('v1,')]
    if not any(hmac.compare_digest(expected, item) for item in supplied):
        raise PushError('invalid_signature')
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        raise PushError('invalid_delivery') from None
    if (type(payload) is not dict or payload.get('event_id') != event_id or
            payload.get('event_type') not in KINDS or
            type(payload.get('note_id')) is not str or
            not NOTE.fullmatch(payload['note_id']) or
            type(payload.get('occurred_at')) is not str):
        raise PushError('invalid_delivery')
    try:
        occurred = datetime.fromisoformat(payload['occurred_at'].replace('Z', '+00:00'))
        if occurred.tzinfo is None:
            raise ValueError()
    except ValueError:
        raise PushError('invalid_delivery') from None
    return {'event_id':event_id, 'note_id':payload['note_id'],
            'event_type':payload['event_type'], 'occurred_at':occurred.astimezone(timezone.utc).isoformat()}


class Inbox:
    """Owner-only local event journal. Duplicate deliveries never create new work."""

    def __init__(self, directory):
        root = Path(directory)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PushError('state_unavailable')
        self.path = root / 'push-events.sqlite3'
        if self.path.exists():
            file_info = self.path.lstat()
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != os.getuid() or
                    file_info.st_mode & 0o077 or file_info.st_nlink != 1):
                raise PushError('state_unavailable')
        old_umask = os.umask(0o077)
        try:
            with self._connect() as db:
                db.execute('''CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY, note_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, occurred_at TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    next_at REAL NOT NULL DEFAULT 0, result TEXT)''')
        finally:
            os.umask(old_umask)

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute('PRAGMA busy_timeout=5000')
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def add(self, event):
        with self._connect() as db:
            db.execute('INSERT OR IGNORE INTO events(event_id,note_id,event_type,occurred_at) VALUES(?,?,?,?)',
                       (event['event_id'], event['note_id'], event['event_type'], event['occurred_at']))

    def due(self, now=None):
        # Pause is an owner-only gate on *new* work. A worker already holding
        # an event may finish; its durable delivery reservation still fences it.
        pause = self.path.parent / 'paused'
        if pause.exists() or pause.is_symlink():
            info = pause.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                    info.st_mode & 0o077 or info.st_nlink != 1):
                raise PushError('state_unavailable')
            return None
        with self._connect() as db:
            row = db.execute("SELECT event_id,note_id,event_type,occurred_at,attempts FROM events WHERE state='pending' AND next_at<=? ORDER BY occurred_at,event_id LIMIT 1",
                             (time.time() if now is None else now,)).fetchone()
            return row

    def set_state(self, event_id, state, *, delay=0, result=None):
        if state not in ('pending', 'accepted', 'attention') or result not in (None, 'existing', 'sent', 'source_pending', 'runtime_pending', 'failed', 'handoff_uncertain', 'handoff_accepted_unobserved', 'handoff_verified_received'):
            raise PushError('invalid_state')
        with self._connect() as db:
            db.execute('UPDATE events SET state=?,attempts=attempts+1,next_at=?,result=? WHERE event_id=?',
                       (state, time.time() + delay, result, event_id))


def handler_for(inbox, secret_key, changed, *, invalid_signature_status=400):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # HTTP logs may otherwise include untrusted paths or provider IDs.

        def do_POST(self):
            if self.path != '/granola':
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_BODY:
                    raise PushError('invalid_delivery')
                body = self.rfile.read(length)
                event = verify(self.headers, body, secret_key)
                inbox.add(event)
            except PushError as error:
                self.send_error(invalid_signature_status if str(error) == 'invalid_signature' else 400)
                return
            except Exception:
                self.send_error(503)
                return
            self.send_response(204)
            self.end_headers()
            changed.set()

    return Handler


def serve(host, port, inbox, secret_key, process_one, *, handler_factory=handler_for):
    changed = threading.Event()
    server = ThreadingHTTPServer((host, port), handler_factory(inbox, secret_key, changed))

    def worker():
        while True:
            event = inbox.due()
            if event is None:
                changed.wait(30)
                changed.clear()
                continue
            event_id = event[0]
            try:
                outcome = process_one(event)
                state = event_state_for_outcome(outcome)
                inbox.set_state(event_id, state, result=outcome)
            except PushError as error:
                if str(error) in ('source_pending', 'runtime_pending'):
                    inbox.set_state(event_id, 'pending', delay=60, result=str(error))
                else:
                    inbox.set_state(event_id, 'attention', result='failed')
            except Exception:
                inbox.set_state(event_id, 'attention', result='failed')

    threading.Thread(target=worker, daemon=True, name='granola-push-worker').start()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


def event_state_for_outcome(outcome):
    if outcome in ('handoff_uncertain', 'handoff_accepted_unobserved'):
        return 'attention'
    if outcome in ('existing', 'sent', 'handoff_verified_received'):
        return 'accepted'
    raise PushError('invalid_state')
