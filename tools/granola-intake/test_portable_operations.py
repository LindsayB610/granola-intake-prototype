"""Synthetic service and recovery checks; never touches the user's LaunchAgents."""
import base64
import json
import os
from pathlib import Path
import plistlib
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from portable_identity import operation_id
from portable_preservation import preserve_source
from push_webhook import Inbox
import portable_operations as ops

NOTE = 'not_12345678901234'


class OperationsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(os.path.realpath(temp.name))
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.source_state, self.holding, self.command_state, self.receipts = (
            self.private / name for name in ('source-state', 'holding', 'command-state', 'receipts'))
        for path in (self.source_state, self.holding, self.command_state, self.receipts):
            path.mkdir(mode=0o700)
        self.key = self.private / 'key'
        self.secret = self.private / 'secret'
        self.key.write_text('grn_SYNTHETIC\n')
        self.secret.write_text('whsec_' + base64.b64encode(b'synthetic-secret-key').decode())
        for path in (self.key, self.secret):
            path.chmod(0o600)
        self.source_config = self.private / 'source.json'
        self.source_config.write_text(json.dumps({
            'schema_version': 1, 'owner_email': 'owner@example.test',
            'state_dir': str(self.source_state), 'holding_root': str(self.holding),
            'credential_path': str(self.key), 'signing_secret_path': str(self.secret),
            'source_policy': {'max_pages': 2, 'max_page_bytes': 4096,
                              'max_total_bytes': 8192, 'total_timeout': 5},
            'event_types': ['note.generated']}))
        self.source_config.chmod(0o600)
        receiver = Path(__file__).with_name('portable_command_receiver.py')
        self.command_config = self.private / 'command.json'
        self.command_config.write_text(json.dumps({
            'schema_version': 1, 'holding_root': str(self.holding),
            'state_dir': str(self.command_state), 'receipt_root': str(self.receipts),
            'destination_id': 'test-agent',
            'command': [str(receiver), '--config', str(self.command_config)],
            'timeout_seconds': 5}))
        self.command_config.chmod(0o600)
        ngrok = self.private / 'ngrok'
        ngrok.write_text('#!/bin/sh\nexit 0\n')
        ngrok.chmod(0o700)
        self.config = {'schema_version': 1, 'service_id': 'synthetic',
                       'source_config': str(self.source_config),
                       'handoff_config': str(self.command_config), 'port': 47691,
                       'ngrok_executable': str(ngrok),
                       'public_url': 'https://example.ngrok.app/granola'}
        path = self.private / 'operations.json'
        path.write_text(json.dumps(self.config))
        path.chmod(0o600)
        self.loaded, self.source, self.handoff = ops.load_operations(str(path))
        self.calls = []

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1:3] == ['print', 'gui/' + str(os.getuid())]:
            return subprocess.CompletedProcess(argv, 0,
                ('gui/' + str(os.getuid()) + ' = {\n services = {\n }\n}\n').encode())
        if 'print' in argv and not all(path.exists() for path in
                                      ops.launch_paths(self.loaded, home=self.home)):
            return subprocess.CompletedProcess(argv, 113, b'')
        output = b'state = running\n' if 'print' in argv else b''
        return subprocess.CompletedProcess(argv, 0, output)

    def _prepare_interrupted_recovery(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        marker = ops.installation_path(self.loaded)
        old_plists = [path.read_bytes() for path in paths]
        old_marker = marker.read_bytes()
        changed = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')
        new_plists = [plistlib.dumps(value) for value in ops.plists(changed)]
        new_marker = json.dumps({'schema_version': 2, 'service_id': changed['service_id'],
            'plists': ops._plist_digests(changed)}, sort_keys=True).encode()
        journal = {'schema_version': 1, 'service_id': changed['service_id'],
            'old_plists': {label: base64.b64encode(data).decode()
                           for label, data in zip(ops.labels(changed), old_plists)},
            'new_plists': {label: base64.b64encode(data).decode()
                           for label, data in zip(ops.labels(changed), new_plists)},
            'old_marker': base64.b64encode(old_marker).decode(),
            'new_marker': base64.b64encode(new_marker).decode()}
        ops._write_exclusive(ops.upgrade_journal_path(changed),
                             json.dumps(journal, sort_keys=True).encode())
        paths[0].write_bytes(new_plists[0])
        return paths, changed

    def test_install_status_upgrade_uninstall_are_selected_and_preserve_state(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        self.assertTrue(all(path.exists() for path in paths))
        changed = dict(self.loaded, service_id='other')
        with self.assertRaisesRegex(ops.OperationsError, 'installation_identity_changed'):
            ops.install(changed, home=self.home, runner=self.runner)
        self.assertEqual(ops.status(self.loaded, self.source, self.handoff,
                                    home=self.home, runner=self.runner)['services'],
                         {'receiver': 'running', 'tunnel': 'running'})
        stamp = self.source_state / 'identity'
        stamp.write_text('keep')
        moved_url = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')
        with self.assertRaisesRegex(ops.OperationsError, 'service_upgrade_required'):
            ops.preflight(moved_url, self.source, self.handoff, home=self.home)
        self.assertEqual(ops.status(moved_url, self.source, self.handoff,
                                    home=self.home, runner=self.runner)['bindings']['tunnel'],
                         'upgrade_required')
        ops.upgrade(moved_url, home=self.home, runner=self.runner)
        self.assertEqual(ops.status(moved_url, self.source, self.handoff,
                                    home=self.home, runner=self.runner)['bindings']['tunnel'],
                         'current')
        self.assertEqual(stamp.read_text(), 'keep')
        self.assertEqual(ops.uninstall(self.loaded, home=self.home,
                                       runner=self.runner)['private_data'], 'retained')
        self.assertTrue(stamp.exists())
        self.assertFalse(any(path.exists() for path in paths))
        self.assertTrue(all(call[0] == '/bin/launchctl' for call in self.calls))

    def test_upgrade_rolls_back_each_replacement_and_bootstrap_failure(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        marker = ops.installation_path(self.loaded)
        old_plists = [path.read_bytes() for path in paths]
        old_marker = marker.read_bytes()
        changed = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')

        for fail_at in (1, 2, 3):
            with self.subTest(replacement=fail_at):
                calls = 0
                real_replace = ops.os.replace

                def fail_once(source, target):
                    nonlocal calls
                    calls += 1
                    if calls == fail_at:
                        raise OSError('synthetic replacement interruption')
                    return real_replace(source, target)

                with patch('portable_operations.os.replace', side_effect=fail_once):
                    with self.assertRaises(OSError):
                        ops.upgrade(changed, home=self.home, runner=self.runner)
                self.assertEqual([path.read_bytes() for path in paths], old_plists)
                self.assertEqual(marker.read_bytes(), old_marker)
                ops._validate_installed_set(self.loaded, paths)
                # The first injected failure can interrupt journal publication
                # itself. This test harness cleans that synthetic orphan before
                # exercising a separate failure point.
                for orphan in ops.upgrade_journal_path(self.loaded).parent.glob(
                        ops.upgrade_journal_path(self.loaded).name + '.tmp-*'):
                    orphan.unlink()

        loaded = set(ops.labels(self.loaded))
        domain = 'gui/' + str(os.getuid())

        def fail_new_bootstrap(argv, **_kwargs):
            if argv[1] == 'print':
                if argv[2] == domain:
                    body = ''.join(' label = ' + label + '\n' for label in loaded)
                    return subprocess.CompletedProcess(argv, 0,
                        (domain + ' = {\n services = {\n' + body + ' }\n}\n').encode())
                label = argv[2].split('/')[-1]
                return subprocess.CompletedProcess(argv, 0 if label in loaded else 113, b'')
            if argv[1] == 'bootout':
                descriptor = plistlib.loads(Path(argv[3]).read_bytes())
                loaded.discard(descriptor['Label'])
                return subprocess.CompletedProcess(argv, 0, b'')
            if argv[1] == 'bootstrap':
                descriptor = plistlib.loads(Path(argv[3]).read_bytes())
                if descriptor['ProgramArguments'] != ops.plists(self.loaded)[
                        ops.labels(self.loaded).index(descriptor['Label'])]['ProgramArguments']:
                    return subprocess.CompletedProcess(argv, 1, b'')
                loaded.add(descriptor['Label'])
                return subprocess.CompletedProcess(argv, 0, b'')
            self.fail('unexpected launchctl operation')

        with self.assertRaisesRegex(ops.OperationsError, 'service_start_failed'):
            ops.upgrade(changed, home=self.home, runner=fail_new_bootstrap)
        self.assertEqual([path.read_bytes() for path in paths], old_plists)
        self.assertEqual(marker.read_bytes(), old_marker)
        ops._validate_installed_set(self.loaded, paths)

    def test_upgrade_refuses_preexisting_foreign_suffix_before_journal_or_launchctl(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        old_plists = [path.read_bytes() for path in paths]
        temporary = paths[0].with_suffix('.plist.new')
        temporary.write_bytes(b'foreign owner-private bytes')
        temporary.chmod(0o600)
        calls_before = len(self.calls)
        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.upgrade(dict(self.loaded,
                             public_url='https://new.example.ngrok.app/granola'),
                        home=self.home, runner=self.runner)
        self.assertFalse(any(call[1] in ('bootout', 'bootstrap')
                             for call in self.calls[calls_before:]))
        self.assertTrue(temporary.exists())
        self.assertFalse(ops.upgrade_journal_path(self.loaded).exists())
        self.assertEqual([path.read_bytes() for path in paths], old_plists)

    def test_start_refuses_orphan_suffix_before_service_state_or_mutation(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        temporary = paths[0].with_suffix('.plist.rollback')
        temporary.write_bytes(b'ambiguous previous rollback')
        temporary.chmod(0o600)
        calls_before = len(self.calls)
        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.start(self.loaded, home=self.home, runner=self.runner)
        self.assertEqual(self.calls[calls_before:], [])
        self.assertTrue(temporary.exists())

    def test_upgrade_reconciles_nonzero_bootout_that_left_service_absent(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        loaded = set(ops.labels(self.loaded))
        domain = 'gui/' + str(os.getuid())
        failed = False

        def runner(argv, **_kwargs):
            nonlocal failed
            if argv[1] == 'print':
                if argv[2] == domain:
                    body = ''.join(' label = ' + label + '\n' for label in loaded)
                    output = domain + ' = {\n services = {\n' + body + ' }\n}\n'
                    return subprocess.CompletedProcess(argv, 0, output.encode())
                label = argv[2].split('/')[-1]
                return subprocess.CompletedProcess(argv, 0 if label in loaded else 113, b'')
            if argv[1] == 'bootout':
                label = plistlib.loads(Path(argv[3]).read_bytes())['Label']
                loaded.discard(label)
                if not failed:
                    failed = True
                    return subprocess.CompletedProcess(argv, 1, b'')
                return subprocess.CompletedProcess(argv, 0, b'')
            if argv[1] == 'bootstrap':
                label = plistlib.loads(Path(argv[3]).read_bytes())['Label']
                loaded.add(label)
                return subprocess.CompletedProcess(argv, 0, b'')
            self.fail('unexpected launchctl operation')

        changed = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')
        self.assertEqual(ops.upgrade(changed, home=self.home, runner=runner)['status'],
                         'upgraded')
        self.assertTrue(failed)
        self.assertEqual(loaded, set(ops.labels(self.loaded)))
        self.assertFalse(ops.upgrade_journal_path(self.loaded).exists())
        self.assertEqual(ops.status(changed, self.source, self.handoff,
                                    home=self.home, runner=runner)['bindings']['tunnel'],
                         'current')

    def test_next_management_command_recovers_crash_after_marker_replacement(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        marker = ops.installation_path(self.loaded)
        old_plists = [path.read_bytes() for path in paths]
        old_marker = marker.read_bytes()
        changed = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')
        new_plists = [plistlib.dumps(value) for value in ops.plists(changed)]
        new_marker = json.dumps({'schema_version': 2, 'service_id': changed['service_id'],
            'plists': ops._plist_digests(changed)}, sort_keys=True).encode()
        journal = {'schema_version': 1, 'service_id': changed['service_id'],
            'old_plists': {label: base64.b64encode(data).decode()
                           for label, data in zip(ops.labels(changed), old_plists)},
            'new_plists': {label: base64.b64encode(data).decode()
                           for label, data in zip(ops.labels(changed), new_plists)},
            'old_marker': base64.b64encode(old_marker).decode(),
            'new_marker': base64.b64encode(new_marker).decode()}
        ops._write_exclusive(ops.upgrade_journal_path(changed),
                             json.dumps(journal, sort_keys=True).encode())
        for path, content in zip(paths, new_plists):
            ops._write_replacement(path, content, '.plist.new')
        ops._write_replacement(marker, new_marker, '.json.new')

        # Simulate a process death: the transaction journal and new generation
        # remain, then a normal management command must restore the old set.
        ops.start(self.loaded, home=self.home, runner=self.runner)
        self.assertEqual([path.read_bytes() for path in paths], old_plists)
        self.assertEqual(marker.read_bytes(), old_marker)
        self.assertFalse(ops.upgrade_journal_path(self.loaded).exists())
        ops._validate_installed_set(self.loaded, paths)
        ops.upgrade(changed, home=self.home, runner=self.runner)
        self.assertEqual(ops.status(changed, self.source, self.handoff,
                                    home=self.home, runner=self.runner)['bindings']['tunnel'],
                         'current')

    def test_recovery_suffixes_fail_before_bootout(self):
        for kind in ('group_readable', 'symlink', 'hardlink', 'foreign_content'):
            with self.subTest(kind=kind):
                paths, _ = self._prepare_interrupted_recovery()
                temporary = paths[0].with_suffix('.plist.new')
                if kind == 'group_readable':
                    temporary.write_bytes(paths[0].read_bytes())
                    temporary.chmod(0o640)
                elif kind == 'foreign_content':
                    temporary.write_bytes(b'foreign temporary descriptor')
                    temporary.chmod(0o600)
                elif kind == 'symlink':
                    target = self.private / 'symlink-target'
                    target.write_bytes(b'not a descriptor')
                    temporary.symlink_to(target)
                else:
                    target = self.private / 'hardlink-target'
                    target.write_bytes(paths[0].read_bytes())
                    target.chmod(0o600)
                    os.link(target, temporary)
                calls_before = len(self.calls)
                with self.assertRaisesRegex(ops.OperationsError,
                                            'service_upgrade_recovery_required'):
                    ops.status(self.loaded, self.source, self.handoff,
                               home=self.home, runner=self.runner)
                self.assertFalse(any(call[1] == 'bootout'
                                     for call in self.calls[calls_before:]))
                self.assertTrue(temporary.is_symlink() if kind == 'symlink'
                                else temporary.exists())
                self.assertTrue(ops.upgrade_journal_path(self.loaded).exists())
                temporary.unlink()
                ops.upgrade_journal_path(self.loaded).unlink()
                ops.installation_path(self.loaded).unlink()
                for path in paths:
                    path.unlink()

    def test_committed_journal_rejects_and_retains_unexpected_journal_temp(self):
        _, _ = self._prepare_interrupted_recovery()
        temporary = ops.upgrade_journal_path(self.loaded).with_name(
            'portable-upgrade-recovery.json.tmp-foreign')
        temporary.write_text('foreign temporary journal content')
        temporary.chmod(0o600)
        calls_before = len(self.calls)
        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.status(self.loaded, self.source, self.handoff,
                       home=self.home, runner=self.runner)
        self.assertFalse(any(call[1] in ('bootout', 'bootstrap')
                             for call in self.calls[calls_before:]))
        self.assertTrue(temporary.exists())
        self.assertTrue(ops.upgrade_journal_path(self.loaded).exists())

    def test_recovery_refuses_preexisting_temporary_before_service_queries(self):
        paths, _ = self._prepare_interrupted_recovery()
        temporary = paths[0].with_suffix('.plist.new')
        temporary.write_bytes(paths[0].read_bytes())
        temporary.chmod(0o600)
        def swapping_runner(argv, **kwargs):
            self.fail('service state must not be queried when a suffix pre-exists')

        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.status(self.loaded, self.source, self.handoff,
                       home=self.home, runner=swapping_runner)
        self.assertTrue(temporary.exists())
        self.assertTrue(ops.upgrade_journal_path(self.loaded).exists())

    def test_process_death_during_journal_write_leaves_recoverable_temp_only(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        before = [path.read_bytes() for path in paths]
        marker_before = ops.installation_path(self.loaded).read_bytes()
        journal_path = ops.upgrade_journal_path(self.loaded)
        module_dir = str(Path(ops.__file__).parent)
        child = r'''
import os, signal, sys
sys.path.insert(0, sys.argv[1])
import portable_operations as ops
real_write = os.write
def partial_then_die(fd, data):
    real_write(fd, bytes(data[:max(1, len(data) // 2)]))
    os.kill(os.getpid(), signal.SIGKILL)
ops.os.write = partial_then_die
ops._write_recovery_journal(__import__('pathlib').Path(sys.argv[2]), b'{"incomplete": true}')
'''
        killed = subprocess.run([sys.executable, '-c', child, module_dir,
                                 str(journal_path)], check=False,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(killed.returncode, -signal.SIGKILL)
        self.assertFalse(journal_path.exists())
        temps = list(journal_path.parent.glob(journal_path.name + '.tmp-*'))
        self.assertEqual(len(temps), 1)
        self.assertLess(temps[0].stat().st_size, len(b'{"incomplete": true}'))

        # A later invocation cannot claim ownership of the orphaned temp.
        # Keep it and refuse before probing or changing services.
        calls_before = len(self.calls)
        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.status(self.loaded, self.source, self.handoff,
                       home=self.home, runner=self.runner)
        self.assertFalse(any(call[1] in ('bootout', 'bootstrap')
                             for call in self.calls[calls_before:]))
        self.assertTrue(temps[0].exists())
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertEqual(ops.installation_path(self.loaded).read_bytes(), marker_before)

    def test_process_death_immediately_after_journal_publication_recovers(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        before = [path.read_bytes() for path in paths]
        marker_before = ops.installation_path(self.loaded).read_bytes()
        changed = dict(self.loaded, public_url='https://new.example.ngrok.app/granola')
        real_replace = ops.os.replace

        def publish_then_die(source, target):
            real_replace(source, target)
            if Path(target) == ops.upgrade_journal_path(self.loaded):
                raise SystemExit('simulated death immediately after atomic publication')

        with patch('portable_operations.os.replace', side_effect=publish_then_die):
            with self.assertRaisesRegex(SystemExit, 'simulated death'):
                ops.upgrade(changed, home=self.home, runner=self.runner)
        journal_path = ops.upgrade_journal_path(self.loaded)
        self.assertTrue(json.loads(journal_path.read_text())['old_plists'])
        ops.status(self.loaded, self.source, self.handoff,
                   home=self.home, runner=self.runner)
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertEqual(ops.installation_path(self.loaded).read_bytes(), marker_before)
        self.assertFalse(journal_path.exists())

    def test_partial_temp_cleanup_fails_closed_on_foreign_plist(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        journal_path = ops.upgrade_journal_path(self.loaded)
        fragment = journal_path.with_name(journal_path.name + '.tmp-synthetic')
        fragment.write_bytes(b'{partial')
        fragment.chmod(0o600)
        paths[0].write_bytes(b'foreign descriptor')

        with self.assertRaisesRegex(ops.OperationsError,
                                    'service_upgrade_recovery_required'):
            ops.status(self.loaded, self.source, self.handoff,
                       home=self.home, runner=self.runner)
        self.assertTrue(fragment.exists())
        self.assertEqual(fragment.read_bytes(), b'{partial')

    def test_malformed_committed_journal_is_never_deleted(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        before = [path.read_bytes() for path in paths]
        journal_path = ops.upgrade_journal_path(self.loaded)
        journal_path.write_bytes(b'{malformed')
        journal_path.chmod(0o600)

        with self.assertRaisesRegex(ops.OperationsError, 'service_upgrade_recovery_required'):
            ops.status(self.loaded, self.source, self.handoff,
                       home=self.home, runner=self.runner)
        self.assertEqual(journal_path.read_bytes(), b'{malformed')
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_pause_retains_event_and_resume_releases_it(self):
        inbox = Inbox(str(self.source_state))
        inbox.add({'event_id': 'f29c3a9d-9892-4620-af1b-c65e00a51234',
                   'note_id': NOTE, 'event_type': 'note.generated',
                   'occurred_at': '2026-09-30T00:00:00Z'})
        self.assertIsNotNone(inbox.due())
        ops.pause(self.source)
        self.assertIsNone(Inbox(str(self.source_state)).due())
        result = ops.status(self.loaded, self.source, self.handoff,
                            home=self.home, runner=self.runner)
        self.assertEqual(result['events'][0]['source'], 'pending')
        self.assertEqual(result['events'][0]['handoff'], 'not_attempted')
        ops.resume(self.source)
        self.assertIsNotNone(inbox.due())

    def test_exact_recovery_uses_existing_operation_and_never_reinvokes(self):
        segment = {'speaker': {'source': 'microphone'}, 'text': 'Synthetic only.'}
        representation = json.dumps({'transcript': [segment]}, separators=(',', ':')).encode()
        metadata = {'id': NOTE, 'object': 'note', 'owner': {'email': 'owner@example.test'},
                    'created_at': '2026-09-30T00:00:00Z', 'updated_at': '2026-09-30T00:00:00Z'}
        import hashlib
        item = {'status': 'ready', 'note_id': NOTE, 'owner_email': 'owner@example.test',
                'metadata': metadata, 'updated_at': metadata['updated_at'],
                'segments': [segment], 'representation': representation,
                'sha256': hashlib.sha256(representation).hexdigest(),
                'raw_pages': [json.dumps({'transcript': [segment], 'hasMore': False,
                                          'cursor': None}).encode()],
                'raw_metadata': json.dumps(metadata).encode(), 'page_count': 1,
                'representation_kind': 'canonical-json-transcript-v1'}
        item['raw_page_sha256'] = [hashlib.sha256(item['raw_pages'][0]).hexdigest()]
        preserve_source(item, str(self.holding), operation_id=operation_id(NOTE),
                        retrieved_at='2026-09-30T00:01:00Z', markdown=True)
        with patch('portable_source._fetch', side_effect=AssertionError('refetched')):
            first = ops.recover_exact(self.source, self.handoff, NOTE)
            second = ops.recover_exact(self.source, self.handoff, NOTE)
        self.assertEqual(first['status'], 'handoff_accepted_unobserved')
        self.assertEqual(second['status'], 'handoff_accepted_unobserved')
        self.assertEqual(len(list(self.command_state.glob('*.json'))), 1)
        self.assertEqual(ops.preflight(self.loaded, self.source, self.handoff,
                                       operation=operation_id(NOTE))['status'], 'ready')
        snapshot = ops.status(self.loaded, self.source, self.handoff,
                              home=self.home, runner=self.runner)
        self.assertEqual(snapshot['events'][0]['source'], 'ready')
        self.assertEqual(snapshot['events'][0]['handoff'], 'accepted_unobserved')
        self.assertEqual(self.handoff.observe(operation_id(NOTE))['status'], 'verified_received')
        self.assertEqual(ops.status(self.loaded, self.source, self.handoff,
                                    home=self.home, runner=self.runner)['events'][0]['handoff'],
                         'verified_received')

    def test_foreign_service_and_unsafe_config_fail_closed(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        paths[0].parent.mkdir(parents=True)
        paths[0].write_text('foreign')
        paths[0].chmod(0o600)
        with self.assertRaises(ops.OperationsError):
            ops.install(self.loaded, home=self.home, runner=self.runner)
        with self.assertRaises(ops.OperationsError):
            ops.uninstall(self.loaded, home=self.home, runner=self.runner)

    def test_same_label_foreign_program_is_rejected_before_any_stop_or_unlink(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        ops.install(self.loaded, home=self.home, runner=self.runner)
        foreign = plistlib.loads(paths[0].read_bytes())
        foreign['ProgramArguments'] = ['/bin/sleep', '120']
        paths[0].write_bytes(plistlib.dumps(foreign))
        calls_before = len(self.calls)
        with self.assertRaisesRegex(ops.OperationsError, 'foreign_service'):
            ops.uninstall(self.loaded, home=self.home, runner=self.runner)
        self.assertEqual(self.calls[calls_before:], [])
        self.assertTrue(all(path.exists() for path in paths))

    def test_failed_bootstrap_reconciles_loaded_label_and_keeps_recovery_metadata(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        for failure in ('nonzero', 'timeout'):
            with self.subTest(failure=failure):
                loaded = set()

                def uncertain(argv, **_kwargs):
                    action = argv[1]
                    if action == 'print':
                        if argv[2] == 'gui/' + str(os.getuid()):
                            domain = 'gui/' + str(os.getuid()) + ' = {\n services = {\n'
                            domain += ''.join(' label = ' + item + '\n' for item in loaded)
                            return subprocess.CompletedProcess(argv, 0, (domain + '}\n}\n').encode())
                        label = argv[2].split('/')[-1]
                        return subprocess.CompletedProcess(argv, 0 if label in loaded else 113, b'')
                    if action == 'bootstrap':
                        descriptor = plistlib.loads(Path(argv[3]).read_bytes())
                        loaded.add(descriptor['Label'])
                        if failure == 'timeout':
                            raise subprocess.TimeoutExpired(argv, 10)
                        return subprocess.CompletedProcess(argv, 1, b'')
                    if action == 'bootout':
                        return subprocess.CompletedProcess(argv, 1, b'')
                    self.fail('unexpected launchctl operation')

                with self.assertRaisesRegex(ops.OperationsError, 'service_rollback_failed'):
                    ops.install(self.loaded, home=self.home, runner=uncertain)
                self.assertIn(ops.labels(self.loaded)[0], loaded)
                marker = ops.installation_path(self.loaded)
                self.assertTrue(marker.exists())
                self.assertTrue(all(path.exists() for path in paths))
                record = json.loads(marker.read_text())
                self.assertEqual(set(record['plists']), set(ops.labels(self.loaded)))
                marker.unlink()
                for path in paths:
                    path.unlink()

    def test_uncertain_bootstrap_and_unavailable_state_observation_retain_all_metadata(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        loaded = set()
        bootout_attempted = []
        bootstrap_seen = False
        rollback_probe_count = 0

        def uncertain(argv, **_kwargs):
            nonlocal bootstrap_seen, rollback_probe_count
            action = argv[1]
            if action == 'print':
                if argv[2] == 'gui/' + str(os.getuid()):
                    # Installation's initial checks prove an empty domain;
                    # rollback readback then becomes unavailable.
                    if not bootstrap_seen:
                        return subprocess.CompletedProcess(argv, 0,
                            ('gui/' + str(os.getuid()) + ' = {\n services = {\n }\n}').encode())
                    return subprocess.CompletedProcess(argv, 113, b'')
                rollback_probe_count += 1
                return subprocess.CompletedProcess(argv,
                    0 if bootstrap_seen and rollback_probe_count == 1 else 113, b'')
            if action == 'bootstrap':
                bootstrap_seen = True
                value = plistlib.loads(Path(argv[3]).read_bytes())
                loaded.add(value['Label'])
                raise subprocess.TimeoutExpired(argv, 10)
            if action == 'bootout':
                bootout_attempted.append(argv)
                return subprocess.CompletedProcess(argv, 1, b'')
            self.fail('unexpected launchctl operation')

        with self.assertRaisesRegex(ops.OperationsError, 'service_rollback_failed'):
            ops.install(self.loaded, home=self.home, runner=uncertain)
        self.assertTrue(loaded)
        self.assertFalse(bootout_attempted)  # Unknown is not permission to mutate.
        marker = ops.installation_path(self.loaded)
        self.assertTrue(marker.exists())
        self.assertTrue(all(path.exists() for path in paths))
        record = json.loads(marker.read_text())
        self.assertEqual(set(record['plists']), set(ops.labels(self.loaded)))

    def test_nonzero_targeted_lookup_requires_positive_domain_absence(self):
        calls = []
        domain = 'gui/' + str(os.getuid())

        def unavailable(argv, **_kwargs):
            calls.append(argv)
            if argv[1:3] == ['print', domain]:
                return subprocess.CompletedProcess(argv, 113, b'')
            return subprocess.CompletedProcess(argv, 113, b'')

        with self.assertRaisesRegex(ops.OperationsError, 'service_state_unavailable'):
            ops.install(self.loaded, home=self.home, runner=unavailable)
        self.assertFalse(ops.installation_path(self.loaded).exists())
        self.assertTrue(any(argv[1:3] == ['print', domain] for argv in calls))

    def test_timeout_with_positive_absence_cleans_rollback_metadata(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        domain = 'gui/' + str(os.getuid())
        bootstrapped = False

        def absent(argv, **_kwargs):
            nonlocal bootstrapped
            if argv[1] == 'print':
                if argv[2] == domain:
                    return subprocess.CompletedProcess(argv, 0,
                        (domain + ' = {\n services = {\n }\n}').encode())
                return subprocess.CompletedProcess(argv, 113, b'')
            if argv[1] == 'bootstrap':
                bootstrapped = True
                raise subprocess.TimeoutExpired(argv, 10)
            self.fail('unexpected launchctl operation')

        with self.assertRaises(subprocess.TimeoutExpired):
            ops.install(self.loaded, home=self.home, runner=absent)
        self.assertTrue(bootstrapped)
        self.assertFalse(ops.installation_path(self.loaded).exists())
        self.assertTrue(all(not path.exists() for path in paths))

    def test_incomplete_successful_domain_listing_retains_rollback_metadata(self):
        paths = ops.launch_paths(self.loaded, home=self.home)
        domain = 'gui/' + str(os.getuid())
        bootstrapped = False

        def clipped(argv, **_kwargs):
            nonlocal bootstrapped
            if argv[1] == 'print':
                if argv[2] == domain:
                    output = (domain + ' = {\n services = {\n' if bootstrapped else
                              domain + ' = {\n services = {\n }\n}')
                    return subprocess.CompletedProcess(argv, 0, output.encode())
                return subprocess.CompletedProcess(argv, 113, b'')
            if argv[1] == 'bootstrap':
                bootstrapped = True
                raise subprocess.TimeoutExpired(argv, 10)
            self.fail('unexpected launchctl operation')

        with self.assertRaisesRegex(ops.OperationsError, 'service_rollback_failed'):
            ops.install(self.loaded, home=self.home, runner=clipped)
        self.assertTrue(bootstrapped)
        self.assertTrue(ops.installation_path(self.loaded).exists())
        self.assertTrue(all(path.exists() for path in paths))
        def incomplete_read(argv, **_kwargs):
            if argv[2] == domain:
                return subprocess.CompletedProcess(argv, 0,
                    (domain + ' = {\n services = {\n').encode())
            return subprocess.CompletedProcess(argv, 113, b'')

        self.assertEqual(ops._service_state(ops.labels(self.loaded)[0], runner=incomplete_read),
                         'unknown')

    def test_nested_services_block_cannot_prove_service_absence(self):
        domain = 'gui/' + str(os.getuid())

        def nested(argv, **_kwargs):
            if argv[2] == domain:
                return subprocess.CompletedProcess(argv, 0,
                    (domain + ' = {\n other = {\n services = {\n }\n }\n}\n').encode())
            return subprocess.CompletedProcess(argv, 113, b'')

        self.assertEqual(ops._service_state(ops.labels(self.loaded)[0], runner=nested), 'unknown')

    def test_duplicate_services_blocks_cannot_prove_service_absence(self):
        domain = 'gui/' + str(os.getuid())
        label = ops.labels(self.loaded)[0]

        def duplicate(argv, **_kwargs):
            if argv[2] == domain:
                output = (domain + ' = {\n services = {\n }\n services = {\n' +
                          ' label = ' + label + '\n }\n}\n')
                return subprocess.CompletedProcess(argv, 0, output.encode())
            return subprocess.CompletedProcess(argv, 113, b'')

        self.assertEqual(ops._service_state(label, runner=duplicate), 'unknown')

    def test_nested_services_plus_direct_services_is_ambiguous(self):
        domain = 'gui/' + str(os.getuid())

        def mixed(argv, **_kwargs):
            if argv[2] == domain:
                output = (domain + ' = {\n other = {\n services = {\n }\n }\n' +
                          ' services = {\n }\n}\n')
                return subprocess.CompletedProcess(argv, 0, output.encode())
            return subprocess.CompletedProcess(argv, 113, b'')

        self.assertEqual(ops._service_state(ops.labels(self.loaded)[0], runner=mixed), 'unknown')

    def test_malformed_services_value_cannot_prove_service_absence(self):
        domain = 'gui/' + str(os.getuid())

        def malformed(argv, **_kwargs):
            if argv[2] == domain:
                output = domain + ' = {\n services = not-a-dictionary\n}\n'
                return subprocess.CompletedProcess(argv, 0, output.encode())
            return subprocess.CompletedProcess(argv, 113, b'')

        self.assertEqual(ops._service_state(ops.labels(self.loaded)[0], runner=malformed), 'unknown')

    def test_manual_recovery_respects_pause(self):
        ops.pause(self.source)
        with self.assertRaisesRegex(ops.OperationsError, 'paused'):
            ops.recover_exact(self.source, self.handoff, NOTE)
        self.assertEqual(list(self.command_state.glob('*.json')), [])

    def test_isolated_receiver_process_start_restart_and_no_orphans(self):
        # Fake launchctl controls only processes created inside this test.
        # The tunnel is a sleep stub; no provider or GUI browser is touched.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.loaded['port'] = sock.getsockname()[1]
        children = {}

        def manager(argv, **_kwargs):
            action = argv[1]
            if action == 'bootstrap':
                value = plistlib.loads(Path(argv[3]).read_bytes())
                label = value['Label']
                program = value['ProgramArguments']
                if label.endswith('.tunnel'):
                    program = ['/bin/sleep', '120']
                children[label] = subprocess.Popen(program, stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.PIPE)
                return subprocess.CompletedProcess(argv, 0, b'')
            if action == 'bootout':
                value = plistlib.loads(Path(argv[3]).read_bytes())
                child = children.pop(value['Label'], None)
                if child:
                    child.terminate()
                    child.wait(timeout=5)
                    child.stderr.close()
                return subprocess.CompletedProcess(argv, 0, b'')
            label = argv[2].split('/')[-1]
            if argv[2] == 'gui/' + str(os.getuid()):
                running_labels = [name for name, child in children.items()
                                  if child is not None and child.poll() is None]
                output = ('gui/' + str(os.getuid()) + ' = {\n services = {\n' +
                          ''.join(' label = ' + name + '\n' for name in running_labels) +
                          ' }\n}')
                return subprocess.CompletedProcess(argv, 0, output.encode())
            child = children.get(label)
            running = child is not None and child.poll() is None
            return subprocess.CompletedProcess(argv, 0 if running else 113,
                                               b'state = running\n' if running else b'')

        def wait_port():
            for _ in range(30):
                with socket.socket() as sock:
                    if sock.connect_ex(('127.0.0.1', self.loaded['port'])) == 0:
                        return
                time.sleep(0.05)
            receiver = children[ops.labels(self.loaded)[0]]
            self.fail('receiver did not bind; exit=' + str(receiver.poll()) +
                      (' stderr=' + receiver.stderr.read().decode(errors='replace')[:300]
                       if receiver.poll() is not None else ''))

        try:
            ops.install(self.loaded, home=self.home, runner=manager)
            wait_port()
            first = children[ops.labels(self.loaded)[0]].pid
            ops.stop(self.loaded, home=self.home, runner=manager)
            self.assertFalse(children)
            ops.start(self.loaded, home=self.home, runner=manager)
            wait_port()
            self.assertNotEqual(first, children[ops.labels(self.loaded)[0]].pid)
        finally:
            ops.uninstall(self.loaded, home=self.home, runner=manager)
            for child in children.values():
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stderr.close()
        self.assertFalse(children)


if __name__ == '__main__':
    unittest.main()
