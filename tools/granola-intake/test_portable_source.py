"""Clean private setup and signed exact-source flow using synthetic data only."""
import base64
import hashlib
import hmac
import http.client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import portable_identity as detector
from portable_holding import HoldingStore
import portable_source
from push_webhook import Inbox, handler_for, verify
import portable_source_api as source


NOTE = 'not_12345678901234'
OWNER = 'owner@example.test'


class Response:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def read(self, size):
        return self.body[:size]


class PortableSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        private = Path(os.path.realpath(self.temp.name), 'private')
        private.mkdir(mode=0o700)
        self.state = private / 'state'
        self.holding = private / 'holding'
        self.state.mkdir(mode=0o700)
        self.holding.mkdir(mode=0o700)
        self.key = private / 'api-key'
        self.secret = private / 'webhook-secret'
        self.key.write_text('grn_SYNTHETIC\n')
        self.secret.write_text('whsec_' + base64.b64encode(b'synthetic-webhook-secret').decode())
        self.key.chmod(0o600)
        self.secret.chmod(0o600)
        self.config_path = private / 'config.json'
        self.config = {
            'schema_version': 1, 'owner_email': OWNER,
            'state_dir': str(self.state), 'holding_root': str(self.holding),
            'credential_path': str(self.key), 'signing_secret_path': str(self.secret),
            'source_policy': {'max_pages': 2, 'max_page_bytes': 4096,
                              'max_total_bytes': 8192, 'total_timeout': 5},
            'event_types': ['note.generated']}
        self.config_path.write_text(json.dumps(self.config))
        self.config_path.chmod(0o600)
        self.event = {'event_id': '8f1c2a4e-6b3d-4e8f-9a2b-1c5d7e9f0a3b',
                      'event_type': 'note.generated', 'note_id': NOTE,
                      'occurred_at': '2026-09-29T12:00:00Z'}

    def signed(self, event=None, *, timestamp=None):
        event = self.event if event is None else event
        body = json.dumps(event, separators=(',', ':')).encode()
        timestamp = str(int(time.time()) if timestamp is None else timestamp)
        key = b'synthetic-webhook-secret'
        signature = base64.b64encode(hmac.new(
            key, event['event_id'].encode() + b'.' + timestamp.encode() + b'.' + body,
            hashlib.sha256).digest()).decode()
        return body, {'webhook-id': event['event_id'], 'webhook-timestamp': timestamp,
                      'webhook-signature': 'v1,' + signature}

    def send(self, server, body, headers):
        conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        conn.request('POST', '/granola', body=body, headers=headers)
        response = conn.getresponse()
        status = response.status
        response.read()
        conn.close()
        return status

    def fixture_source(self):
        metadata = {'id': NOTE, 'object': 'note', 'owner': {'email': OWNER},
                    'created_at': '2026-09-29T12:00:00Z',
                    'updated_at': '2026-09-29T12:01:00Z', 'title': 'synthetic'}
        page = {'transcript': [{'speaker': {'source': 'microphone'},
                                'text': 'Synthetic exact source.'}],
                'hasMore': False, 'cursor': None}
        opener = Mock()
        opener.open.side_effect = [Response(metadata), Response(page), Response(metadata)]
        item = source._retrieve_source(
            NOTE, OWNER, lambda: 'grn_SYNTHETIC', opener, None,
            2, 4096, 8192, deadline=time.monotonic() + 5)
        self.assertEqual(opener.open.call_count, 3)
        return item

    def test_signed_event_preserves_complete_source_without_http_listener(self):
        config = portable_source.load_config(str(self.config_path))
        body, headers = self.signed()
        event = verify(headers, body, b'synthetic-webhook-secret')
        inbox = Inbox(config['state_dir'])
        inbox.add(event)
        item = self.fixture_source()
        row = inbox.due()
        self.assertEqual(portable_source.process_event(row, config,
                         retrieve=lambda *_: item), 'sent')
        resolved = HoldingStore.for_operation_resolution(str(self.holding)).resolve(
            detector.operation_id(NOTE), NOTE, OWNER)
        bundle = self.holding / resolved['relative_path']
        self.assertEqual((bundle / 'transcript.json').read_bytes(), item['representation'])
        self.assertEqual((bundle / 'metadata.json').read_bytes(), item['raw_metadata'])
        self.assertEqual((bundle / 'page-0001.json').read_bytes(), item['raw_pages'][0])
        self.assertEqual(portable_source.process_event(row, config,
                         retrieve=lambda *_: self.fail('duplicate fetched source')), 'existing')

    def test_config_is_user_selected_private_and_rejects_unsafe_modes(self):
        self.assertEqual(portable_source.load_config(str(self.config_path))['owner_email'], OWNER)
        self.config_path.chmod(0o644)
        with self.assertRaises(portable_source.PortableError):
            portable_source.load_config(str(self.config_path))
        self.config_path.chmod(0o600)
        self.key.chmod(0o644)
        with self.assertRaises(portable_source.PortableError):
            portable_source.load_config(str(self.config_path))

    def test_config_rejects_checkout_paths_unsafe_secret_and_event_scope(self):
        self.config['event_types'] = ['note.generated', 'note.access_granted']
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(portable_source.PortableError):
            portable_source.load_config(str(self.config_path))
        self.config['event_types'] = ['note.generated']
        self.config_path.write_text(json.dumps(self.config))
        self.secret.chmod(0o644)
        with self.assertRaises(portable_source.PortableError):
            portable_source.load_config(str(self.config_path))
        self.secret.chmod(0o600)
        self.config['state_dir'] = str(Path(__file__).resolve().parent)
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaises(portable_source.PortableError):
            portable_source.load_config(str(self.config_path))

    def test_signed_local_delivery_journals_then_preserves_once_across_restart(self):
        config = portable_source.load_config(str(self.config_path))
        inbox = Inbox(config['state_dir'])
        changed = threading.Event()
        server = ThreadingHTTPServer(('127.0.0.1', 0),
                                     handler_for(inbox, b'synthetic-webhook-secret', changed))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body, headers = self.signed()
            self.assertEqual(self.send(server, body, headers), 204)
            self.assertTrue(changed.wait(1))
            row = inbox.due()
            self.assertEqual(row[1:3], (NOTE, 'note.generated'))
            item = self.fixture_source()
            calls = []
            def retrieve(note_id, _config):
                calls.append(note_id)
                return item
            self.assertEqual(portable_source.process_event(row, config, retrieve=retrieve), 'sent')
            inbox.set_state(row[0], 'accepted', result='sent')
            resolved = HoldingStore.for_operation_resolution(str(self.holding)).resolve(
                detector.operation_id(NOTE), NOTE, OWNER)
            saved = self.holding / resolved['relative_path'] / 'transcript.json'
            self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), item['sha256'])
            self.assertEqual(self.send(server, body, headers), 204)
            self.assertIsNone(Inbox(config['state_dir']).due())
            repeat = dict(self.event, event_id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
            body2, headers2 = self.signed(repeat)
            self.assertEqual(self.send(server, body2, headers2), 204)
            row2 = Inbox(config['state_dir']).due()
            self.assertEqual(portable_source.process_event(row2, config, retrieve=retrieve), 'existing')
            self.assertEqual(calls, [NOTE])
            self.assertEqual(len(list((self.holding / 'transcripts' / 'granola' / NOTE).iterdir())), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_forged_stale_malformed_and_access_granted_have_no_source_effect(self):
        config = portable_source.load_config(str(self.config_path))
        inbox = Inbox(config['state_dir'])
        changed = threading.Event()
        server = ThreadingHTTPServer(('127.0.0.1', 0),
                                     handler_for(inbox, b'synthetic-webhook-secret', changed))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body, headers = self.signed()
            self.assertEqual(self.send(server, body + b' ', headers), 400)
            old_body, old_headers = self.signed(timestamp=int(time.time()) - 301)
            self.assertEqual(self.send(server, old_body, old_headers), 400)
            malformed = dict(self.event, note_id='wrong')
            bad_body, bad_headers = self.signed(malformed)
            self.assertEqual(self.send(server, bad_body, bad_headers), 400)
            access = dict(self.event, event_type='note.access_granted')
            access_body, access_headers = self.signed(access)
            self.assertEqual(self.send(server, access_body, access_headers), 204)
            self.assertEqual(portable_source.process_event(inbox.due(), config,
                             retrieve=lambda *_: self.fail('access grant fetched source')), 'existing')
            self.assertFalse((self.holding / 'transcripts').exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_interrupted_stage_holds_attention_across_restart_without_refetch(self):
        config = portable_source.load_config(str(self.config_path))
        inbox = Inbox(config['state_dir'])
        inbox.add(self.event)
        note_dir = self.holding / 'transcripts' / 'granola' / NOTE
        note_dir.mkdir(parents=True, mode=0o700)
        stage = note_dir / '.stage-interrupted'
        stage.mkdir(mode=0o700)
        staged_bytes = b'synthetic incomplete evidence'
        (stage / 'partial').write_bytes(staged_bytes)
        with self.assertRaisesRegex(portable_source.PushError, '^source_unavailable$'):
            portable_source.process_event(inbox.due(), config,
                retrieve=lambda *_: self.fail('interrupted source refetched'))
        inbox.set_state(self.event['event_id'], 'attention', result='failed')
        self.assertIsNone(Inbox(config['state_dir']).due())
        self.assertEqual((stage / 'partial').read_bytes(), staged_bytes)
        self.assertEqual([item.name for item in note_dir.iterdir()], ['.stage-interrupted'])

    def test_wrong_owner_note_and_provider_limits_never_preserve(self):
        config = portable_source.load_config(str(self.config_path))
        row = (self.event['event_id'], NOTE, 'note.generated', self.event['occurred_at'], 0)
        for changed in ({'note_id': 'not_99999999999999'}, {'owner_email': 'other@example.test'}):
            item = dict(self.fixture_source(), **changed)
            with self.assertRaisesRegex(portable_source.PushError, '^source_unavailable$'):
                portable_source.process_event(row, config, retrieve=lambda *_: item)
        self.assertFalse((self.holding / 'transcripts').exists())
        metadata = {'id': NOTE, 'object': 'note', 'owner': {'email': 'other@example.test'},
                    'created_at': '2026-09-29T12:00:00Z', 'updated_at': '2026-09-29T12:01:00Z'}
        opener = Mock()
        opener.open.return_value = Response(metadata)
        with self.assertRaisesRegex(source.SourceError, 'wrong_owner'):
            source._retrieve_source(NOTE, OWNER, lambda: 'grn_SYNTHETIC', opener,
                                    None, 2, 4096, 8192, deadline=time.monotonic() + 5)
        self.assertEqual(opener.open.call_count, 1)
        metadata['owner']['email'] = OWNER
        page = {'transcript': [{'speaker': {'source': 'microphone'}, 'text': 'x' * 5000}],
                'hasMore': False, 'cursor': None}
        opener.open.side_effect = [Response(metadata), Response(page)]
        with self.assertRaisesRegex(source.SourceError, 'oversize'):
            source._retrieve_source(NOTE, OWNER, lambda: 'grn_SYNTHETIC', opener,
                                    None, 2, 4096, 8192, deadline=time.monotonic() + 5)
        self.assertFalse((self.holding / 'transcripts').exists())

    def test_shared_note_not_owned_by_configured_user_never_reaches_owner_command(self):
        """A synthetic shared note owned by someone else must stop before handoff."""
        config = portable_source.load_config(str(self.config_path))
        row = (self.event['event_id'], NOTE, 'note.generated', self.event['occurred_at'], 0)
        shared_note = dict(self.fixture_source(), owner_email='other-owner@example.test')

        class OwnerCommand:
            def status(self, _operation):
                raise AssertionError('shared note reached owner command status')

            def deliver(self, _operation):
                raise AssertionError('shared note reached owner command delivery')

        with self.assertRaisesRegex(portable_source.PushError, '^source_unavailable$'):
            portable_source.process_event(row, config,
                retrieve=lambda *_: shared_note, handoff=OwnerCommand())
        self.assertFalse((self.holding / 'transcripts').exists())

    def test_retryable_source_failures_remain_pending_and_permanent_failures_hold(self):
        config = portable_source.load_config(str(self.config_path))
        row = (self.event['event_id'], NOTE, 'note.generated', self.event['occurred_at'], 0)
        for code in ('not_ready_or_unavailable', 'temporarily_unavailable',
                     'rate_limited', 'source_changed'):
            with self.assertRaisesRegex(portable_source.PushError, '^source_pending$'):
                portable_source.process_event(row, config,
                    retrieve=lambda *_: (_ for _ in ()).throw(source.SourceError(code)))
        with self.assertRaisesRegex(portable_source.PushError, '^source_unavailable$'):
            portable_source.process_event(row, config,
                retrieve=lambda *_: (_ for _ in ()).throw(source.SourceError('wrong_owner')))
        self.assertFalse((self.holding / 'transcripts').exists())

    def test_worker_boundary_sends_exact_note_and_restores_source_bytes(self):
        config = portable_source.load_config(str(self.config_path))
        item = self.fixture_source()
        encoded = dict(item)
        for key in ('representation', 'raw_metadata'):
            encoded[key] = base64.b64encode(item[key]).decode()
        encoded['raw_pages'] = [base64.b64encode(page).decode() for page in item['raw_pages']]
        response = Mock(stdout=json.dumps({'status': 'ready', 'item': encoded}).encode())
        with patch.object(portable_source.subprocess, 'run', return_value=response) as run:
            restored = portable_source._fetch(NOTE, config)
        self.assertEqual(restored['representation'], item['representation'])
        self.assertEqual(restored['raw_pages'], item['raw_pages'])
        args, kwargs = run.call_args
        self.assertEqual(args[0][1:4], ['-I', '-S', '-B'])
        self.assertEqual(json.loads(kwargs['input'])['note_id'], NOTE)
        self.assertNotIn('grn_', ' '.join(args[0]))


if __name__ == '__main__':
    unittest.main()
