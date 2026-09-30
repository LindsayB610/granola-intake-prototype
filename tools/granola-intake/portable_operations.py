"""Owner-scoped macOS operations for the portable signed source receiver.

This module never reads a transcript into status output and never clears a
delivery reservation. Provider settings are external and must be read back by
the owner in Granola's account UI.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import urllib.parse

from portable_command_handoff import CommandHandoff, HandoffError, load_config as load_handoff
from portable_holding import HoldingError, HoldingStore, _private_directory
from portable_identity import NOTE_ID, operation_id
from portable_source import load_config as load_source, process_event
from push_webhook import Inbox, PushError, event_state_for_outcome, private_secret, verify
import base64
import hashlib
import hmac
import time

SLUG = re.compile(r'[a-z0-9][a-z0-9-]{0,47}\Z')
SERVICE_KEYS = {'schema_version', 'service_id', 'source_config', 'handoff_config',
                'port', 'ngrok_executable', 'public_url'}


class OperationsError(RuntimeError):
    """Content-free operator code."""


def need(condition, code):
    if not condition:
        raise OperationsError(code)


def private_file(path, *, limit=8192):
    target = Path(path)
    need(target.is_absolute() and not any(p.is_symlink() for p in (target, *target.parents)),
         'unsafe_private_file')
    _private_directory(str(target.parent))
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             not info.st_mode & 0o077 and info.st_nlink == 1 and
             0 < info.st_size <= limit, 'unsafe_private_file')
        data = os.read(fd, limit + 1)
        need(len(data) == info.st_size, 'unsafe_private_file')
        return data
    finally:
        os.close(fd)


def load_operations(path):
    try:
        config = json.loads(private_file(path))
        need(type(config) is dict and set(config) == SERVICE_KEYS and
             config['schema_version'] == 1 and type(config['service_id']) is str and
             SLUG.fullmatch(config['service_id']) and
             type(config['port']) is int and 1024 <= config['port'] <= 65535,
             'invalid_operations_config')
        url = urllib.parse.urlsplit(config['public_url'])
        need(url.scheme == 'https' and url.hostname and not url.username and
             not url.password and not url.port and not url.query and
             not url.fragment and url.path in ('', '/granola'), 'invalid_public_url')
        config['public_url'] = 'https://' + url.hostname + '/granola'
        ngrok = Path(config['ngrok_executable'])
        need(ngrok.is_absolute() and ngrok.is_file() and os.access(ngrok, os.X_OK),
             'ngrok_unavailable')
        source = load_source(config['source_config'])
        handoff = CommandHandoff(load_handoff(config['handoff_config']))
        need(source['holding_root'] == handoff.config['holding_root'] and
             source['state_dir'] != handoff.config['state_dir'], 'private_root_mismatch')
        return config, source, handoff
    except OperationsError:
        raise
    except Exception:
        raise OperationsError('invalid_operations_config') from None


def labels(config):
    stem = 'local.granola-intake.' + config['service_id']
    return stem + '.receiver', stem + '.tunnel'


def launch_paths(config, *, home=None):
    root = (Path(home) if home else Path.home()) / 'Library' / 'LaunchAgents'
    return tuple(root / (label + '.plist') for label in labels(config))


def installation_path(config):
    source = load_source(config['source_config'])
    return Path(source['state_dir']) / 'portable-installation.json'


def upgrade_journal_path(config):
    source = load_source(config['source_config'])
    return Path(source['state_dir']) / 'portable-upgrade-recovery.json'


def _write_replacement(path, content, suffix, *, owned=None):
    temporary = path.with_suffix(suffix)
    _write_exclusive(temporary, content)
    identity = _temporary_identity(temporary, content)
    if owned is not None:
        owned[temporary] = identity
    try:
        os.replace(temporary, path)
    except BaseException:
        _unlink_revalidated_temporary(temporary, identity)
        if owned is not None:
            owned.pop(temporary, None)
        raise
    if owned is not None:
        owned.pop(temporary, None)


def _recover_interrupted_upgrade(config, *, home=None, runner=subprocess.run):
    journal_path = upgrade_journal_path(config)
    journal_temps = sorted(journal_path.parent.glob(journal_path.name + '.tmp-*'))
    if not journal_path.exists() and not journal_path.is_symlink():
        paths = launch_paths(config, home=home)
        marker = installation_path(config)
        if journal_temps or _existing_paths(_upgrade_temporary_paths(paths, marker)):
            # The creating invocation is gone. Private mode cannot prove that
            # this command owns the leftover path, so preserve it for review.
            raise OperationsError('service_upgrade_recovery_required')
        return
    try:
        journal_bytes = private_file(journal_path, limit=65536)
        journal_identity = _temporary_identity(journal_path, journal_bytes)
        journal = json.loads(journal_bytes)
        need(type(journal) is dict and journal.get('schema_version') == 1 and
             journal.get('service_id') == config['service_id'] and
             type(journal.get('old_plists')) is dict and
             type(journal.get('new_plists')) is dict and
             set(journal['old_plists']) == set(labels(config)) == set(journal['new_plists']),
             'service_upgrade_recovery_required')
        old = {label: base64.b64decode(value, validate=True)
               for label, value in journal['old_plists'].items()}
        new = {label: base64.b64decode(value, validate=True)
               for label, value in journal['new_plists'].items()}
        old_marker = base64.b64decode(journal['old_marker'], validate=True)
        new_marker = base64.b64decode(journal['new_marker'], validate=True)
        old_identity = json.loads(old_marker)
        new_identity = json.loads(new_marker)
        need(all(type(identity) is dict and identity.get('schema_version') == 2 and
                 identity.get('service_id') == config['service_id'] and
                 identity.get('plists') == {
                     label: hashlib.sha256(data).hexdigest()
                     for label, data in descriptors.items()}
                 for identity, descriptors in ((old_identity, old), (new_identity, new))),
             'service_upgrade_recovery_required')
        marker_path = installation_path(config)
        marker_bytes = private_file(marker_path, limit=1024)
        need(marker_bytes in (old_marker, new_marker), 'service_upgrade_recovery_required')
        paths = launch_paths(config, home=home)
        for path, label in zip(paths, labels(config)):
            value = _owned_plist(path, label)
            raw = private_file(path, limit=16384)
            need(raw in (old[label], new[label]), 'foreign_service')
            need(value.get('Label') == label, 'foreign_service')
        need(not journal_temps and not _existing_paths(
            _upgrade_temporary_paths(paths, marker_path)),
            'service_upgrade_recovery_required')
        for label, path in zip(labels(config), paths):
            state = _service_state(label, runner=runner)
            need(state != 'unknown', 'service_state_unavailable')
            if state == 'loaded':
                code, _ = _launchctl('bootout', 'gui/' + str(os.getuid()),
                                     str(path), runner=runner)
                need(code == 0 or _service_state(label, runner=runner) == 'absent',
                     'service_stop_failed')
        for path, label in zip(paths, labels(config)):
            _write_replacement(path, old[label], '.plist.recover')
        _write_replacement(marker_path, old_marker, '.json.recover')
        for path in paths:
            code, _ = _launchctl('bootstrap', 'gui/' + str(os.getuid()),
                                 str(path), runner=runner)
            need(code == 0, 'service_start_failed')
        _unlink_revalidated_temporary(journal_path, journal_identity)
    except OperationsError:
        raise
    except Exception:
        raise OperationsError('service_upgrade_recovery_required') from None


def installed_identity(config, *, required=False):
    path = installation_path(config)
    if not path.exists() and not path.is_symlink():
        need(not required, 'service_not_installed')
        return False
    try:
        record = json.loads(private_file(path, limit=1024))
    except Exception:
        raise OperationsError('installation_identity_changed') from None
    need(type(record) is dict and record.get('schema_version') == 2 and
         record.get('service_id') == config['service_id'] and
         type(record.get('plists')) is dict and set(record['plists']) == set(labels(config)) and
         all(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value)
             for value in record['plists'].values()),
         'installation_identity_changed')
    return True


def _plist_digests(config):
    return {value['Label']: hashlib.sha256(plistlib.dumps(value)).hexdigest()
            for value in plists(config)}


def _validate_installed_set(config, paths):
    installed_identity(config, required=True)
    marker = json.loads(private_file(installation_path(config), limit=1024))
    expected = marker['plists']
    # Validate every descriptor before bootout/unlink can affect either service.
    for path, label in zip(paths, labels(config)):
        _owned_plist(path, label)
        raw = private_file(path, limit=16384)
        need(hashlib.sha256(raw).hexdigest() == expected[label], 'foreign_service')


def plists(config):
    receiver, tunnel = labels(config)
    script = str(Path(__file__).resolve().with_name('portable_source.py'))
    common = {'RunAtLoad': True, 'KeepAlive': True,
              'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null',
              'EnvironmentVariables': {'PYTHONDONTWRITEBYTECODE': '1'},
              'GranolaPortableServiceId': config['service_id']}
    return (
        dict(common, Label=receiver,
             ProgramArguments=[sys.executable, '-I', '-B', script, '--config',
                               config['source_config'], '--handoff-config',
                               config['handoff_config'], '--port', str(config['port'])]),
        dict(common, Label=tunnel,
             ProgramArguments=[config['ngrok_executable'], 'http', str(config['port']),
                               '--url', config['public_url'][:-len('/granola')],
                               '--inspect=false', '--log=false']))


def _write_exclusive(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
         not info.st_mode & 0o022 and not path.parent.is_symlink(),
         'unsafe_launch_directory')
    if path.exists() or path.is_symlink():
        raise OperationsError('service_already_installed')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        need(os.write(fd, content) == len(content), 'service_write_failed')
        os.fsync(fd)
    except BaseException:
        try:
            opened = os.fstat(fd)
            info = path.lstat()
            if ((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and
                    stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    not info.st_mode & 0o077 and info.st_nlink == 1):
                read_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    current = os.fstat(read_fd)
                    partial = os.read(read_fd, len(content) + 1)
                    if ((current.st_dev, current.st_ino) ==
                            (info.st_dev, info.st_ino) and
                            len(partial) <= len(content) and
                            content.startswith(partial)):
                        os.unlink(path)
                finally:
                    os.close(read_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(fd)


def _upgrade_temporary_paths(paths, marker_path):
    return ([path.with_suffix(suffix) for path in paths
             for suffix in ('.plist.new', '.plist.rollback', '.plist.recover')] +
            [marker_path.with_suffix(suffix)
             for suffix in ('.json.new', '.json.rollback', '.json.recover')])


def _existing_paths(paths):
    return [path for path in paths if path.exists() or path.is_symlink()]


def _temporary_identity(path, content):
    return _validate_recovery_temporaries([path], {path: {content}})[path]


def _validate_recovery_temporaries(paths, expected):
    """Validate every recovery suffix before recovery can stop a service."""
    present = []
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             not info.st_mode & 0o077 and info.st_nlink == 1 and
             info.st_size <= 65536, 'service_upgrade_recovery_required')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            need(stat.S_ISREG(opened.st_mode) and opened.st_dev == info.st_dev and
                 opened.st_ino == info.st_ino and opened.st_uid == os.getuid() and
                 not opened.st_mode & 0o077 and opened.st_nlink == 1 and
                 opened.st_size == info.st_size,
                 'service_upgrade_recovery_required')
            content = os.read(fd, 65537)
            need(len(content) == info.st_size, 'service_upgrade_recovery_required')
        finally:
            os.close(fd)
        allowed = expected.get(path)
        need(allowed is not None and content in allowed,
             'service_upgrade_recovery_required')
        present.append((path, (info.st_dev, info.st_ino, info.st_mode,
                               info.st_uid, info.st_nlink, info.st_size,
                               hashlib.sha256(content).digest())))
    return dict(present)


def _unlink_revalidated_temporary(path, expected_identity):
    """Refuse cleanup if the validated path changed while launchctl ran.

    A same-user process able to write this private directory can still race the
    final lstat/unlink pair; filesystem path unlink has no portable conditional-
    identity primitive. This narrows, but cannot eliminate, that race.
    """
    try:
        info = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    try:
        opened = os.fstat(fd)
        need((info.st_dev, info.st_ino, info.st_mode, info.st_uid,
              info.st_nlink, info.st_size) == expected_identity[:6] and
             (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid,
              opened.st_nlink, opened.st_size) == expected_identity[:6],
             'service_upgrade_recovery_required')
        content = os.read(fd, 65537)
        need(len(content) == info.st_size and
             hashlib.sha256(content).digest() == expected_identity[6],
             'service_upgrade_recovery_required')
    finally:
        os.close(fd)
    path.unlink()


def _write_recovery_journal(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
         not info.st_mode & 0o022 and not path.parent.is_symlink(),
         'unsafe_launch_directory')
    if path.exists() or path.is_symlink():
        raise OperationsError('service_already_installed')
    fd, temp_name = tempfile.mkstemp(prefix=path.name + '.tmp-', dir=path.parent)
    temporary = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            need(written > 0, 'service_write_failed')
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return _temporary_identity(path, content)
    finally:
        if fd >= 0:
            os.close(fd)
        # Do not hide an interrupted fragment. Later invocations retain it and
        # refuse service operations until it is inspected.


def _owned_plist(path, expected_label):
    try:
        need(path.parent.is_dir() and not path.parent.is_symlink() and
             path.parent.stat().st_uid == os.getuid() and
             not path.parent.stat().st_mode & 0o022, 'foreign_service')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 not info.st_mode & 0o077 and info.st_nlink == 1 and
                 0 < info.st_size <= 16384, 'foreign_service')
            raw = os.read(fd, 16385)
            need(len(raw) == info.st_size, 'foreign_service')
        finally:
            os.close(fd)
        value = plistlib.loads(raw)
        need(type(value) is dict and value.get('Label') == expected_label and
             value.get('GranolaPortableServiceId') == expected_label.split('.')[2] and
             value.get('StandardOutPath') == '/dev/null' and
             value.get('StandardErrorPath') == '/dev/null', 'foreign_service')
        return value
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise OperationsError('foreign_service') from None


def _launchctl(*parts, runner=subprocess.run):
    result = runner(['/bin/launchctl', *parts], stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, check=False, timeout=10)
    return result.returncode, result.stdout.decode('utf-8', errors='replace')[:1048576]


def _matching_brace(output, opening):
    """Find a closing brace while ignoring braces inside quoted launchctl values."""
    depth = 0
    quote = None
    escaped = False
    for index in range(opening, len(output)):
        char = output[index]
        if quote:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
        elif char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth < 0:
                return None
            if depth == 0:
                return index
    return None


def _complete_domain_services(output, domain):
    """Return a complete services body, or None when absence cannot be proven."""
    header = re.match(r'\s*' + re.escape(domain) + r'\s*=\s*\{', output)
    if not header:
        return None
    domain_open = header.end() - 1
    domain_close = _matching_brace(output, domain_open)
    if domain_close is None or output[domain_close + 1:].strip():
        return None
    body = output[domain_open + 1:domain_close]
    services_lines = list(re.finditer(r'^\s*services\s*=', body, re.MULTILINE))
    if not services_lines:
        return None
    direct_blocks = []
    depth = 0
    quote = None
    escaped = False
    scanned = 0
    for match in services_lines:
        for char in body[scanned:match.start()]:
            if quote:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == quote:
                    quote = None
            elif char in ('"', "'"):
                quote = char
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
        if quote or depth < 0 or depth != 0:
            return None
        value = re.match(r'\s*\{', body[match.end():])
        if not value:
            return None
        direct_blocks.append(match.end() + value.end() - 1)
        scanned = match.start()
    if len(direct_blocks) != 1:
        return None
    services_open = domain_open + 1 + direct_blocks[0]
    services_close = _matching_brace(output, services_open)
    if services_close is None or services_close >= domain_close:
        return None
    return output[services_open + 1:services_close]


def _service_state(label, *, runner=subprocess.run):
    """Return loaded/absent/unknown; a failed targeted lookup proves nothing."""
    domain = 'gui/' + str(os.getuid())
    try:
        code, _ = _launchctl('print', domain + '/' + label, runner=runner)
        if code == 0:
            return 'loaded'
        # A nonzero targeted print is ambiguous. Enumerate the domain with a
        # successful read and require its recognizable header before absence.
        code, output = _launchctl('print', domain, runner=runner)
        services = None if len(output) >= 1048576 else _complete_domain_services(output, domain)
        if code != 0 or services is None:
            return 'unknown'
        found = (re.search(r'^\s*label\s*=\s*' + re.escape(label) + r'\s*$',
                           services, re.MULTILINE) or
                 re.search(r'^\s*' + re.escape(label) + r'\s*=\s*\{',
                           services, re.MULTILINE))
        return 'loaded' if found else 'absent'
    except BaseException:
        return 'unknown'


def install(config, *, home=None, runner=subprocess.run):
    need(not installed_identity(config), 'service_already_installed')
    paths = launch_paths(config, home=home)
    values = plists(config)
    need(all(not p.exists() and not p.is_symlink() for p in paths), 'service_already_installed')
    marker = installation_path(config)
    journal_path = upgrade_journal_path(config)
    need(not _existing_paths(_upgrade_temporary_paths(paths, marker)) and
         not list(journal_path.parent.glob(journal_path.name + '.tmp-*')) and
         not journal_path.exists() and not journal_path.is_symlink(),
         'service_upgrade_recovery_required')
    for label in labels(config):
        state = _service_state(label, runner=runner)
        need(state == 'absent', 'service_state_unavailable' if state == 'unknown'
             else 'service_label_in_use')
    made = []
    created = {}
    loaded = []
    try:
        record = {'schema_version': 2, 'service_id': config['service_id'],
                  'plists': _plist_digests(config)}
        marker_bytes = json.dumps(record, sort_keys=True).encode()
        _write_exclusive(marker, marker_bytes)
        created[marker] = _temporary_identity(marker, marker_bytes)
        for path, value in zip(paths, values):
            payload = plistlib.dumps(value)
            _write_exclusive(path, payload)
            created[path] = _temporary_identity(path, payload)
            made.append(path)
        for path in paths:
            code, _ = _launchctl('bootstrap', 'gui/' + str(os.getuid()), str(path), runner=runner)
            need(code == 0, 'service_start_failed')
            loaded.append(path)
    except BaseException:
        rollback_failed = False
        # A bootstrap may load before returning failure or timing out. Reconcile
        # both labels, not just commands that returned success.
        for path, label in zip(paths, labels(config)):
            state = _service_state(label, runner=runner)
            if state == 'unknown':
                rollback_failed = True
                continue
            if state == 'loaded':
                try:
                    code, _ = _launchctl('bootout', 'gui/' + str(os.getuid()), str(path), runner=runner)
                    if code:
                        state = _service_state(label, runner=runner)
                    else:
                        state = _service_state(label, runner=runner)
                    rollback_failed |= state != 'absent'
                except BaseException:
                    rollback_failed = True
        if rollback_failed:
            raise OperationsError('service_rollback_failed') from None
        for path, identity in created.items():
            _unlink_revalidated_temporary(path, identity)
        raise


def stop(config, *, home=None, runner=subprocess.run):
    _recover_interrupted_upgrade(config, home=home, runner=runner)
    paths = launch_paths(config, home=home)
    _validate_installed_set(config, paths)
    for path, label in zip(paths, labels(config)):
        if not path.exists() and not path.is_symlink():
            state = _service_state(label, runner=runner)
            need(state == 'absent', 'service_descriptor_missing' if state == 'absent'
                 else 'service_state_unavailable')
            continue
        _owned_plist(path, label)
        code, _ = _launchctl('bootout', 'gui/' + str(os.getuid()), str(path), runner=runner)
        if code:
            state = _service_state(label, runner=runner)
            need(state == 'absent', 'service_stop_failed' if state == 'loaded'
                 else 'service_state_unavailable')


def start(config, *, home=None, runner=subprocess.run):
    _recover_interrupted_upgrade(config, home=home, runner=runner)
    paths = launch_paths(config, home=home)
    _validate_installed_set(config, paths)
    for path, label in zip(paths, labels(config)):
        _owned_plist(path, label)
        code, _ = _launchctl('bootstrap', 'gui/' + str(os.getuid()), str(path), runner=runner)
        need(code == 0, 'service_start_failed')


def uninstall(config, *, home=None, runner=subprocess.run):
    _recover_interrupted_upgrade(config, home=home, runner=runner)
    paths = launch_paths(config, home=home)
    _validate_installed_set(config, paths)
    removal_ids = {path: _temporary_identity(path, private_file(path, limit=16384))
                   for path in paths if path.exists()}
    marker = installation_path(config)
    marker_identity = _temporary_identity(marker, private_file(marker, limit=1024))
    stop(config, home=home, runner=runner)
    for path, label in zip(paths, labels(config)):
        if path.exists():
            _owned_plist(path, label)
            _unlink_revalidated_temporary(path, removal_ids[path])
    _unlink_revalidated_temporary(marker, marker_identity)
    return {'status': 'uninstalled', 'private_data': 'retained'}


def upgrade(config, *, home=None, runner=subprocess.run):
    _recover_interrupted_upgrade(config, home=home, runner=runner)
    paths = launch_paths(config, home=home)
    _validate_installed_set(config, paths)
    old_bytes = [private_file(path, limit=16384) for path in paths]
    marker = installation_path(config)
    old_marker = private_file(marker, limit=1024)
    desired = [plistlib.dumps(value) for value in plists(config)]
    record = {'schema_version': 2, 'service_id': config['service_id'],
              'plists': _plist_digests(config)}
    new_marker = json.dumps(record, sort_keys=True).encode()
    journal = {'schema_version': 1, 'service_id': config['service_id'],
               'old_plists': {label: base64.b64encode(data).decode('ascii')
                              for label, data in zip(labels(config), old_bytes)},
               'new_plists': {label: base64.b64encode(data).decode('ascii')
                              for label, data in zip(labels(config), desired)},
               'old_marker': base64.b64encode(old_marker).decode('ascii'),
               'new_marker': base64.b64encode(new_marker).decode('ascii')}
    journal_path = upgrade_journal_path(config)
    need(not _existing_paths(_upgrade_temporary_paths(paths, marker)) and
         not list(journal_path.parent.glob(journal_path.name + '.tmp-*')),
         'service_upgrade_recovery_required')
    journal_bytes = json.dumps(journal, sort_keys=True).encode()
    journal_identity = _write_recovery_journal(journal_path, journal_bytes)
    owned_temporaries = {}
    try:
        _validate_installed_set(config, paths)
        for path, label in zip(paths, labels(config)):
            code, _ = _launchctl('bootout', 'gui/' + str(os.getuid()),
                                 str(path), runner=runner)
            if code:
                need(_service_state(label, runner=runner) == 'absent',
                     'service_stop_failed')
        for path, payload in zip(paths, desired):
            _write_replacement(path, payload, '.plist.new', owned=owned_temporaries)
        _write_replacement(marker, new_marker, '.json.new', owned=owned_temporaries)
        for path in paths:
            code, _ = _launchctl('bootstrap', 'gui/' + str(os.getuid()),
                                 str(path), runner=runner)
            need(code == 0, 'service_start_failed')
        _unlink_revalidated_temporary(journal_path, journal_identity)
    except BaseException:
        # Roll back the complete selected set, including a partially loaded new
        # generation. Only exact owner-created descriptors are ever booted out.
        try:
            for temporary, identity in list(owned_temporaries.items()):
                _unlink_revalidated_temporary(temporary, identity)
                owned_temporaries.pop(temporary, None)
            for path, label in zip(paths, labels(config)):
                state = _service_state(label, runner=runner)
                need(state != 'unknown', 'service_state_unavailable')
                if state == 'loaded':
                    code, _ = _launchctl('bootout', 'gui/' + str(os.getuid()),
                                         str(path), runner=runner)
                    need(code == 0 or _service_state(label, runner=runner) == 'absent',
                         'service_stop_failed')
            for path, content in zip(paths, old_bytes):
                _write_replacement(path, content, '.plist.rollback',
                                   owned=owned_temporaries)
            _write_replacement(marker, old_marker, '.json.rollback',
                               owned=owned_temporaries)
            for path in paths:
                code, _ = _launchctl('bootstrap', 'gui/' + str(os.getuid()),
                                     str(path), runner=runner)
                need(code == 0, 'service_start_failed')
            _unlink_revalidated_temporary(journal_path, journal_identity)
        except BaseException:
            for temporary, identity in list(owned_temporaries.items()):
                try:
                    _unlink_revalidated_temporary(temporary, identity)
                    owned_temporaries.pop(temporary, None)
                except BaseException:
                    pass
            raise OperationsError('service_upgrade_recovery_required') from None
        raise
    return {'status': 'upgraded', 'private_data': 'retained'}


def pause(source):
    path = Path(source['state_dir']) / 'paused'
    if path.exists() or path.is_symlink():
        _check_empty_pause(path)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    return {'status': 'paused', 'in_flight': 'may_finish'}


def resume(source):
    path = Path(source['state_dir']) / 'paused'
    if path.exists() or path.is_symlink():
        _check_empty_pause(path)
        path.unlink()
    return {'status': 'resumed'}


def _check_empty_pause(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
         not info.st_mode & 0o077 and info.st_nlink == 1 and info.st_size == 0,
         'unsafe_pause')


def _event_rows(source):
    inbox = Inbox(source['state_dir'])
    uri = 'file:' + urllib.parse.quote(str(inbox.path)) + '?mode=ro'
    with sqlite3.connect(uri, uri=True) as db:
        return db.execute('SELECT note_id,event_type,state,result,attempts FROM events ORDER BY occurred_at,event_id').fetchall()


def operation_status(source, handoff, note_id):
    operation = operation_id(note_id)
    try:
        HoldingStore.for_operation_resolution(source['holding_root']).resolve(
            operation, note_id, source['owner_email'])
        source_state = 'ready'
    except HoldingError:
        note_dir = Path(source['holding_root'], 'transcripts', 'granola', note_id)
        source_state = 'pending' if not note_dir.exists() and not note_dir.is_symlink() else 'held'
    try:
        record = handoff.status(operation)
    except HandoffError:
        record = {'status': 'held'}
    delivery = record['status'] if record else 'not_attempted'
    need(delivery in ('not_attempted', 'uncertain', 'accepted_unobserved',
                      'verified_received', 'held'), 'invalid_delivery_state')
    return {'operation_id': operation, 'source': source_state, 'handoff': delivery}


def status(config, source, handoff, *, home=None, runner=subprocess.run):
    _recover_interrupted_upgrade(config, home=home, runner=runner)
    installed_identity(config)
    paths = launch_paths(config, home=home)
    services = {}
    bindings = {}
    for path, label, desired in zip(paths, labels(config), plists(config)):
        if not path.exists():
            services[label.rsplit('.', 1)[-1]] = 'not_installed'
            continue
        installed = _owned_plist(path, label)
        bindings[label.rsplit('.', 1)[-1]] = ('current' if installed.get('ProgramArguments') ==
                                               desired['ProgramArguments'] else 'upgrade_required')
        code, output = _launchctl('print', 'gui/' + str(os.getuid()) + '/' + label,
                                  runner=runner)
        services[label.rsplit('.', 1)[-1]] = ('running' if code == 0 and 'state = running' in output
                                               else 'loaded_or_unknown' if code == 0 else 'stopped')
    events = _event_rows(source)
    notes = {}
    for note_id, event_type, state, result, attempts in events:
        if not NOTE_ID.fullmatch(note_id):
            continue
        if event_type != 'note.generated' and operation_id(note_id) in notes:
            continue
        item = operation_status(source, handoff, note_id)
        item.update(event='received', journal=state, journal_result=result, attempts=attempts)
        if event_type != 'note.generated':
            item['source'] = 'held'
            item['handoff'] = 'not_attempted'
        if state == 'attention' and result == 'failed':
            item['source'] = 'held' if item['source'] == 'pending' else item['source']
        notes[item['operation_id']] = item
    paused = Path(source['state_dir'], 'paused').exists()
    return {'status': 'paused' if paused else 'active', 'services': services,
            'bindings': bindings, 'events': list(notes.values()),
            'external_webhook': 'manual_readback_required',
            'public_url': config['public_url']}


def preflight(config, source, handoff, *, operation=None, home=None):
    _recover_interrupted_upgrade(config, home=home)
    installed = installed_identity(config)
    handoff.preflight(operation)
    Inbox(source['state_dir'])
    # This confirms local binding only. A running tunnel and provider account
    # registration require separate readback.
    expected = plists(config)[1]['ProgramArguments']
    need(expected[2] == str(config['port']) and '--inspect=false' in expected and
         '--log=false' in expected, 'unsafe_tunnel')
    if installed:
        for path, label, desired in zip(launch_paths(config, home=home), labels(config),
                                        plists(config)):
            current = _owned_plist(path, label)
            need(current.get('ProgramArguments') == desired['ProgramArguments'],
                 'service_upgrade_required')
    # Prove this exact secret can verify a test envelope. Never print it.
    key = private_secret(source['signing_secret_path'])
    event_id = '00000000-0000-4000-8000-000000000000'
    stamp = str(int(time.time()))
    body = json.dumps({'event_id': event_id, 'event_type': 'note.generated',
                       'note_id': 'not_00000000000000',
                       'occurred_at': datetime.now(timezone.utc).isoformat()},
                      separators=(',', ':')).encode()
    signature = base64.b64encode(hmac.new(key, event_id.encode() + b'.' +
                                     stamp.encode() + b'.' + body, hashlib.sha256).digest()).decode()
    verify({'webhook-id': event_id, 'webhook-timestamp': stamp,
            'webhook-signature': 'v1,' + signature}, body, key)
    with socket.socket() as sock:
        sock.settimeout(0.2)
        port_free = sock.connect_ex(('127.0.0.1', config['port'])) != 0
    return {'status': 'ready', 'local_port': 'free' if port_free else 'occupied',
            'destination_id': handoff.config['destination_id'],
            'public_url': config['public_url'],
            'next_action': 'verify_live_tunnel_and_granola_webhook_url_events_scope_signature'}


def recover_exact(source, handoff, note_id):
    pause_path = Path(source['state_dir']) / 'paused'
    need(not (pause_path.exists() or pause_path.is_symlink()), 'paused')
    need(type(note_id) is str and NOTE_ID.fullmatch(note_id), 'invalid_note_id')
    # A held or fenced operation is never replayed. This is the same exact
    # operation identity as the signed event path, with no historical scan.
    event_id = 'manual-exact-' + operation_id(note_id)
    now = datetime.now(timezone.utc).isoformat()
    inbox = Inbox(source['state_dir'])
    inbox.add({'event_id': event_id, 'note_id': note_id,
               'event_type': 'note.generated', 'occurred_at': now})
    event = (event_id, note_id, 'note.generated', now, 0)
    try:
        result = process_event(event, source, handoff=handoff)
    except PushError as error:
        inbox.set_state(event_id, 'pending' if str(error) in ('source_pending', 'runtime_pending')
                        else 'attention', result=str(error) if str(error) in
                        ('source_pending', 'runtime_pending') else 'failed')
        return {'status': str(error), 'operation_id': operation_id(note_id)}
    inbox.set_state(event_id, event_state_for_outcome(result), result=result)
    return {'status': result, 'operation_id': operation_id(note_id)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Portable Granola receiver operations')
    parser.add_argument('--config', required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    check = sub.add_parser('preflight')
    check.add_argument('--operation', help='verify an already held exact source')
    for name in ('install', 'start', 'stop', 'restart', 'status',
                 'pause', 'resume', 'upgrade', 'uninstall'):
        sub.add_parser(name)
    recover = sub.add_parser('recover-note')
    recover.add_argument('--note-id', required=True)
    observe = sub.add_parser('observe')
    observe.add_argument('--operation', required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    config, source, handoff = load_operations(args.config)
    if args.action == 'preflight':
        result = preflight(config, source, handoff, operation=args.operation)
    elif args.action == 'install':
        preflight(config, source, handoff)
        install(config)
        result = status(config, source, handoff)
    elif args.action == 'start':
        start(config)
        result = status(config, source, handoff)
    elif args.action == 'stop':
        stop(config)
        result = status(config, source, handoff)
    elif args.action == 'restart':
        stop(config)
        start(config)
        result = status(config, source, handoff)
    elif args.action == 'status':
        result = status(config, source, handoff)
    elif args.action == 'pause':
        result = pause(source)
    elif args.action == 'resume':
        result = resume(source)
    elif args.action == 'upgrade':
        result = upgrade(config)
    elif args.action == 'uninstall':
        result = uninstall(config)
    elif args.action == 'recover-note':
        result = recover_exact(source, handoff, args.note_id)
    else:
        try:
            result = handoff.observe(args.operation)
        except HandoffError as error:
            result = {'status': str(error)}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OperationsError, HandoffError, HoldingError, PushError) as error:
        raise SystemExit(str(error)) from None
