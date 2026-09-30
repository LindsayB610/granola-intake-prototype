"""Configurable signed-event to private exact-source path; no agent handoff."""
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

# Python -I excludes the script directory on current macOS Python. The
# LaunchAgent intentionally uses -I, so resolve only this shipped module set.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import portable_identity as detector
from portable_holding import HoldingError, HoldingStore, _private_directory
from push_webhook import Inbox, PushError, private_secret, serve
import portable_source_api as source


class PortableError(RuntimeError):
    """Content-free codes only."""


def _private_json(path):
    target = _private_path(path)
    _private_directory(str(target.parent))
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1
                or not 0 < info.st_size <= 8192):
            raise PortableError('invalid_private_file')
        return json.loads(os.read(fd, 8193))
    finally:
        os.close(fd)


def _policy(value):
    if type(value) is not dict or set(value) != {
            'max_pages', 'max_page_bytes', 'max_total_bytes', 'total_timeout'}:
        raise PortableError('invalid_source_policy')
    source.validate_limits(value['max_pages'], value['max_page_bytes'], value['max_total_bytes'])
    seconds = value['total_timeout']
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 300:
        raise PortableError('invalid_source_policy')
    return dict(value)


def _private_path(path):
    if type(path) is not str or not os.path.isabs(path) or '..' in Path(path).parts:
        raise PortableError('invalid_private_path')
    target = Path(path)
    if any(part.is_symlink() for part in (target, *target.parents)):
        raise PortableError('invalid_private_path')
    return target


def load_config(path):
    """Require explicit owner-selected paths outside the checkout."""
    try:
        raw = _private_json(str(_private_path(path)))
        if (type(raw) is not dict or set(raw) != {
                'schema_version', 'owner_email', 'state_dir', 'holding_root',
                'credential_path', 'signing_secret_path', 'source_policy', 'event_types'}
                or raw['schema_version'] != 1
                or type(raw['owner_email']) is not str
                or not re.fullmatch(r'[^\s@]+@[^\s@]+', raw['owner_email'])
                or raw['event_types'] != ['note.generated']):
            raise PortableError('invalid_portable_config')
        raw['source_policy'] = _policy(raw['source_policy'])
        for key in ('state_dir', 'holding_root'):
            raw[key] = str(_private_directory(str(_private_path(raw[key]))))
        if raw['state_dir'] == raw['holding_root']:
            raise PortableError('invalid_portable_config')
        for key in ('credential_path', 'signing_secret_path'):
            target = _private_path(raw[key])
            _private_directory(str(target.parent))
            info = target.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise PortableError('invalid_private_file')
        private_secret(raw['signing_secret_path'])
        return raw
    except PortableError:
        raise
    except Exception:
        raise PortableError('invalid_portable_config') from None


def _fetch(note_id, config):
    policy = config['source_policy']
    request = {'note_id': note_id, 'owner_email': config['owner_email'],
               'credential_path': config['credential_path'], 'source_policy': policy}
    try:
        result = subprocess.run(
            [sys.executable, '-I', '-S', '-B', str(Path(__file__).with_name('portable_source_worker.py'))],
            input=json.dumps(request).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=policy['total_timeout'] + 5, check=True)
        if len(result.stdout) > 4 * policy['max_total_bytes'] + 4 * policy['max_page_bytes'] + 1048576:
            raise source.SourceError('oversize')
        response = json.loads(result.stdout)
        if response.get('status') == 'error':
            raise source.SourceError(response['code'])
        if response.get('status') != 'ready':
            raise source.SourceError('invalid_source')
        item = response['item']
        for key in ('representation', 'raw_metadata'):
            item[key] = base64.b64decode(item[key], validate=True)
        item['raw_pages'] = [base64.b64decode(raw, validate=True) for raw in item['raw_pages']]
        return item
    except source.SourceError:
        raise
    except Exception:
        raise source.SourceError('temporarily_unavailable', 60) from None


def process_event(event, config, *, retrieve=_fetch, handoff=None):
    """One note operation survives different event IDs and process restarts."""
    _, note_id, event_type, _, _ = event
    if event_type != 'note.generated':
        return 'existing'  # Access grants are journaled but cannot fetch/intake.
    operation = detector.operation_id(note_id)
    lock_path = Path(config['state_dir']) / ('source-' + operation + '.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PortableError('state_unavailable')
        fcntl.flock(fd, fcntl.LOCK_EX)
        holding = HoldingStore.for_operation_resolution(config['holding_root'])
        note_dir = Path(config['holding_root'], 'transcripts', 'granola', note_id)
        if note_dir.exists() or note_dir.is_symlink():
            holding.resolve(operation, note_id, config['owner_email'])
            return _deliver_ready(operation, handoff) or 'existing'
        transient = retrieve(note_id, config)
        if (type(transient) is not dict or transient.get('note_id') != note_id
                or transient.get('owner_email') != config['owner_email']):
            raise PortableError('source_mismatch')
        from portable_preservation import preserve_source
        preserve_source(transient, config['holding_root'], operation_id=operation,
                        retrieved_at=datetime.now(timezone.utc).isoformat(),
                        markdown=True)
        holding.resolve(operation, note_id, config['owner_email'])
        return _deliver_ready(operation, handoff) or 'sent'
    except source.SourceError as error:
        if error.code in ('not_ready_or_unavailable', 'temporarily_unavailable',
                          'rate_limited', 'source_changed'):
            raise PushError('source_pending') from None
        raise PushError('source_unavailable') from None
    except (HoldingError, PortableError):
        raise PushError('source_unavailable') from None
    finally:
        os.close(fd)


def _deliver_ready(operation, handoff):
    if handoff is None:
        return
    from portable_command_handoff import HandoffError
    try:
        record = handoff.status(operation)
        outcome = handoff.deliver(operation) if record is None else record
        if outcome['status'] not in ('uncertain', 'accepted_unobserved', 'verified_received'):
            raise PushError('runtime_pending')
        return 'handoff_' + outcome['status']
    except HandoffError:
        raise PushError('runtime_pending') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description='Portable signed Granola source receiver')
    parser.add_argument('--config', required=True)
    parser.add_argument('--handoff-config', help='owner-only local command config')
    parser.add_argument('--port', type=int, default=8769)
    args = parser.parse_args(argv)
    os.umask(0o077)
    config = load_config(args.config)
    handoff = None
    if args.handoff_config:
        from portable_command_handoff import (CommandHandoff, HandoffError,
                                              load_config as load_handoff_config,
                                              sender_termination_guard)
        try:
            handoff = CommandHandoff(load_handoff_config(args.handoff_config))
        except HandoffError:
            raise PortableError('handoff_config_invalid') from None
        if handoff.config['holding_root'] != config['holding_root']:
            raise PortableError('holding_root_mismatch')
    inbox = Inbox(config['state_dir'])
    if handoff is not None:
        with sender_termination_guard():
            serve('127.0.0.1', args.port, inbox, private_secret(config['signing_secret_path']),
                  lambda event: process_event(event, config, handoff=handoff))
    else:
        serve('127.0.0.1', args.port, inbox, private_secret(config['signing_secret_path']),
              lambda event: process_event(event, config, handoff=handoff))


if __name__ == '__main__':
    try:
        main()
    except (PortableError, PushError) as error:
        raise SystemExit(str(error)) from None
