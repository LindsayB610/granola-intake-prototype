import json
import fcntl
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from detector import run_once, run_exact, status, reconcile, retry_not_sent_held


OWNER = "owner@example.test"
CUTOFF = "2026-09-24T00:00:00Z"
NOW = "2026-09-25T00:00:00Z"
NOTE = "not_1234567890abcd"


def note(identifier=NOTE, owner=OWNER, created="2026-09-24T10:00:00Z"):
    return {"id": identifier, "owner": {"email": owner}, "created_at": created,
            "updated_at": created, "title": "PRIVATE TITLE MUST NOT PERSIST"}


class API:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def list_notes(self, params):
        self.calls.append(params.copy())
        return self.pages.pop(0)


def page(notes=(), cursor=None):
    return {"notes": list(notes), "hasMore": cursor is not None, "cursor": cursor}


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.config = {"owner_email": OWNER, "activation_cutoff": CUTOFF,
                       "dispatcher_thread": "00000000-0000-4000-8000-000000000001",
                       "dispatcher_host": "local", "codex_path": "/usr/bin/true",
                       "state_dir": str(self.root / "state"),
                       "keychain_service": "test.granola", "keychain_account": OWNER,
                       "max_pages": 2, "max_wakes": 2}
        self.sent = []

    def tearDown(self):
        self.tmp.cleanup()

    def queue(self, operation):
        self.sent.append(operation)

    def rows(self):
        with sqlite3.connect(self.root / "state" / "ledger.sqlite3") as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT * FROM operations")]

    def test_empty_and_owned_discovery_wakes_once(self):
        empty = run_once(self.config, API([page()]), self.queue, NOW)
        self.assertEqual(empty["accepted"], 0)
        self.assertEqual(self.sent, [])
        first = run_once(self.config, API([page([note()])]), self.queue, NOW)
        self.assertEqual(first["discovered"], 1)
        self.assertEqual(first["accepted"], 1)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.rows()[0]["state"], "accepted")
        self.assertEqual(self.rows()[0]["note_id"], NOTE)
        again = run_once(self.config, API([page([note()])]), self.queue, NOW)
        self.assertEqual(again["discovered"], 0)
        self.assertEqual(len(self.sent), 1)
        self.assertNotIn("PRIVATE TITLE", json.dumps(self.rows()))

    def test_two_exact_recoveries_keep_separate_operations_and_cutoff(self):
        self.config['activation_cutoff'] = NOW
        first = NOTE
        second = 'not_1234567890abce'
        for identifier in (first,second):
            result = run_exact(self.config,identifier,'2026-09-24T10:00:00Z',
                               self.queue,NOW,recovery=True)
            self.assertEqual(result['accepted'],1)
        self.assertEqual(len(self.rows()),2)
        self.assertEqual(len(self.sent),2)
        self.assertNotEqual(self.sent[0]['operation_id'],self.sent[1]['operation_id'])
        self.assertEqual(run_exact(self.config,first,'2026-09-24T10:00:00Z',
                         self.queue,NOW,recovery=True)['outcome'],'existing')
        self.assertEqual(len(self.sent),2)
        self.assertEqual(self.config['activation_cutoff'],NOW)

    def test_exact_recovery_rejects_post_cutoff_without_attempt(self):
        self.config['activation_cutoff'] = CUTOFF
        with self.assertRaisesRegex(Exception,'outside selected window'):
            run_exact(self.config,NOTE,NOW,self.queue,NOW,recovery=True)
        self.assertEqual(self.sent,[])
        self.assertFalse((self.root/'state'/'ledger.sqlite3').exists())

    def test_pages_resume_then_rescan_for_late_summary(self):
        self.config["max_pages"] = 1
        first = API([page([note()], "page2")])
        run_once(self.config, first, self.queue, NOW)
        second = API([page([note("not_1234567890abce")])])
        run_once(self.config, second, self.queue, "2026-09-26T00:00:00Z")
        self.assertEqual(second.calls[0]["cursor"], "page2")
        self.assertEqual(second.calls[0]["created_before"], NOW)
        late = API([page([note("not_1234567890abcf", created=CUTOFF)])])
        run_once(self.config, late, self.queue, "2026-09-27T00:00:00Z")
        self.assertNotIn("cursor", late.calls[0])
        self.assertLess(late.calls[0]["created_after"], CUTOFF)
        self.assertEqual(len(self.rows()), 3)
        self.assertEqual(len(self.sent), 3)

    def test_owner_and_time_exclusions(self):
        items = [note(owner="shared@example.test"),
                 note("not_1234567890abce", created="2026-09-23T23:59:59Z"),
                 note("not_1234567890abcf", created="2026-09-26T00:00:00Z")]
        run_once(self.config, API([page(items)]), self.queue, NOW)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.sent, [])

    def test_malformed_page_is_atomic_and_content_free(self):
        bad = note("not_1234567890abce")
        bad["created_at"] = "SECRET SOURCE TEXT"
        with self.assertRaisesRegex(Exception, "invalid API page") as caught:
            run_once(self.config, API([page([note(), bad], "page2")]), self.queue, NOW)
        self.assertNotIn("SECRET", str(caught.exception))
        self.assertEqual(self.rows(), [])
        fresh = API([page()])
        run_once(self.config, fresh, self.queue, NOW)
        self.assertNotIn("cursor", fresh.calls[0])

    def test_cursor_loop_does_not_advance_or_wake(self):
        self.config["max_pages"] = 1
        run_once(self.config, API([page([], "same")]), self.queue, NOW)
        with self.assertRaisesRegex(Exception, "cursor loop"):
            run_once(self.config, API([page([note()], "same")]), self.queue, NOW)
        self.assertEqual(self.rows(), [])
        retry = API([page()])
        run_once(self.config, retry, self.queue, NOW)
        self.assertEqual(retry.calls[0]["cursor"], "same")

    def test_database_rollback_preserves_page_position(self):
        run_once(self.config, API([page()]), self.queue, NOW)
        with sqlite3.connect(self.root / "state" / "ledger.sqlite3") as db:
            db.execute("CREATE TRIGGER reject_fixture BEFORE INSERT ON operations "
                       "WHEN NEW.note_id='not_1234567890abce' BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(Exception):
            run_once(self.config, API([page([note(), note("not_1234567890abce")], "next")]), self.queue, NOW)
        self.assertEqual(self.rows(), [])
        fresh = API([page()])
        run_once(self.config, fresh, self.queue, NOW)
        self.assertNotIn("cursor", fresh.calls[0])

    def test_bounded_pages_and_wakes(self):
        self.config.update(max_pages=1, max_wakes=1)
        api = API([page([note(), note("not_1234567890abce")], "next")])
        run_once(self.config, api, self.queue, NOW)
        self.assertEqual(len(api.calls), 1)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(sorted(r["state"] for r in self.rows()), ["accepted", "pending"])

    def test_timeout_is_held_until_attested_reconciliation(self):
        def timeout(operation):
            self.assertEqual(self.rows()[0]["state"], "uncertain")
            raise TimeoutError("SECRET provider details")
        with self.assertRaisesRegex(Exception, "wake outcome uncertain") as caught:
            run_once(self.config, API([page([note()])]), timeout, NOW)
        self.assertNotIn("SECRET", str(caught.exception))
        operation = self.rows()[0]["operation_id"]
        self.assertEqual(status(self.config)["operations"][0]["state"], "uncertain")
        run_once(self.config, API([page([note()])]), self.queue, NOW)
        self.assertEqual(self.sent, [])
        evidence = {"schema_version": 1, "operation_id": operation,
                    "attempt_id": self.rows()[0].get("attempt_id", "missing"),
                    "dispatcher_thread": self.config["dispatcher_thread"],
                    "outcome": "accepted", "observed_at": NOW,
                    "turn_id": "00000000-0000-4000-8000-000000000002",
                    "reference": "codex://threads/" + self.config["dispatcher_thread"]}
        target = self.root / "evidence.json"
        target.write_text(json.dumps(evidence))
        target.chmod(0o600)
        self.assertTrue(reconcile(self.config, operation, target, confirmed=True, now=NOW))
        self.assertEqual(self.rows()[0]["state"], "accepted")
        self.assertIn("operator-attested", self.rows()[0]["evidence"])
        with self.assertRaisesRegex(Exception, "invalid transition"):
            reconcile(self.config, operation, target, confirmed=True, now=NOW)

    def test_crash_after_acceptance_holds_without_replay(self):
        def crash(operation):
            self.sent.append(operation)
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            run_once(self.config, API([page([note()])]), crash, NOW)
        self.assertEqual(self.rows()[0]["state"], "uncertain")
        run_once(self.config, API([page([note()])]), self.queue, NOW)
        self.assertEqual(len(self.sent), 1)

    def test_locked_worker_has_no_api_or_queue_effect(self):
        run_once(self.config, API([page()]), self.queue, NOW)
        with open(self.root / "state" / "worker.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            api = API([page([note()])])
            result = run_once(self.config, api, self.queue, NOW)
            self.assertEqual(result["outcome"], "already-running")
            self.assertEqual(api.calls, [])
            self.assertEqual(self.rows(), [])

    def test_bad_configuration_has_no_effects(self):
        for key, value in [("dispatcher_host", "remote"), ("max_pages", 0),
                           ("max_wakes", True), ("activation_cutoff", "yesterday"),
                           ("dispatcher_thread", "meeting text"), ("owner_email", ""),
                           ("codex_path", "/nonexistent"), ("unexpected", "key")]:
            with self.subTest(key=key):
                config = dict(self.config, **{key: value})
                api = API([page()])
                with self.assertRaisesRegex(Exception, "invalid configuration"):
                    run_once(config, api, self.queue, NOW)
                self.assertEqual(api.calls, [])
                self.assertFalse((self.root / "state").exists())

    def test_private_files_and_binding(self):
        run_once(self.config, API([page()]), self.queue, NOW)
        for path in (self.root / "state").iterdir():
            self.assertEqual(path.stat().st_mode & 0o077, 0)
        changed = dict(self.config, owner_email="changed@example.test")
        with self.assertRaisesRegex(Exception, "configuration binding changed"):
            run_once(changed, API([page()]), self.queue, NOW)
        (self.root / "state" / "ledger.sqlite3").chmod(0o644)
        with self.assertRaisesRegex(Exception, "unsafe state"):
            status(self.config)

    def test_symlink_state_and_parent_are_rejected(self):
        actual = self.root / "actual"
        actual.mkdir(mode=0o700)
        (self.root / "state").symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(Exception, "unsafe state"):
            run_once(self.config, API([page()]), self.queue, NOW)
        self.assertEqual(list(actual.iterdir()), [])

    def test_wrong_attempt_cannot_reconcile(self):
        def timeout(_):
            raise TimeoutError()
        with self.assertRaises(Exception):
            run_once(self.config, API([page([note()])]), timeout, NOW)
        row = self.rows()[0]
        evidence = {"schema_version": 1, "operation_id": row["operation_id"],
                    "attempt_id": "00000000-0000-4000-8000-000000000099",
                    "dispatcher_thread": self.config["dispatcher_thread"],
                    "outcome": "accepted", "observed_at": NOW,
                    "turn_id": "00000000-0000-4000-8000-000000000002",
                    "reference": "codex://threads/" + self.config["dispatcher_thread"]}
        target = self.root / "evidence.json"
        target.write_text(json.dumps(evidence))
        target.chmod(0o600)
        with self.assertRaisesRegex(Exception, "attempt mismatch"):
            reconcile(self.config, row["operation_id"], target, confirmed=True, now=NOW)
        self.assertEqual(self.rows()[0]["state"], "uncertain")

    def mark_not_sent(self):
        def timeout(_):
            raise TimeoutError()
        with self.assertRaises(Exception):
            run_once(self.config, API([page([note()])]), timeout, NOW)
        row = self.rows()[0]
        evidence = {"schema_version": 1, "operation_id": row["operation_id"],
                    "attempt_id": row["attempt_id"],
                    "dispatcher_thread": self.config["dispatcher_thread"],
                    "outcome": "not_sent", "observed_at": NOW,
                    "turn_id": "00000000-0000-4000-8000-000000000002",
                    "reference": "codex://threads/" + self.config["dispatcher_thread"]}
        target = self.root / "evidence.json"
        target.write_text(json.dumps(evidence))
        target.chmod(0o600)
        reconcile(self.config, row["operation_id"], target, confirmed=True, now=NOW)
        return row["operation_id"]

    def test_held_retry_requires_matching_durable_current_attempt_proof(self):
        operation = self.mark_not_sent()
        row = self.rows()[0]
        self.assertEqual(json.loads(row["evidence"])["attempt_id"], row["attempt_id"])
        self.assertEqual(retry_not_sent_held(self.config, operation, self.queue, NOW)["accepted"], 1)
        self.assertEqual(len(self.sent), 1)
        self.assertNotEqual(row["attempt_id"], self.sent[0]["attempt_id"])

    def test_held_retry_rejects_attestation_for_another_attempt_before_callback(self):
        operation = self.mark_not_sent()
        with sqlite3.connect(self.root / "state" / "ledger.sqlite3") as db:
            db.execute("UPDATE operations SET evidence=? WHERE operation_id=?",
                       (json.dumps({"kind":"operator-attested","outcome":"not_sent",
                                    "attempt_id":"00000000-0000-4000-8000-000000000099"}),
                        operation))
        called = []
        with self.assertRaisesRegex(Exception, "held retry unverified"):
            retry_not_sent_held(self.config, operation, lambda payload: called.append(payload), NOW)
        self.assertEqual(called, [])

    def test_timezone_boundary_and_future_activation(self):
        run_once(self.config, API([page([note(created="2026-09-23T17:00:00-07:00")])]), self.queue, NOW)
        self.assertEqual(len(self.rows()), 1)
        other = dict(self.config, state_dir=str(self.root / "future"), activation_cutoff="2026-10-01T00:00:00Z")
        api = API([])
        result = run_once(other, api, self.queue, NOW)
        self.assertEqual(result["outcome"], "before-activation")
        self.assertEqual(api.calls, [])
        self.assertFalse((self.root / "future").exists())

    def test_contradictory_page_and_sidecar_symlink_rejected(self):
        for value in [dict(page(), hasMore=1), dict(page(), hasMore=True),
                      dict(page(), cursor="cursor"), page([note(created="2026-09-24")])]:
            with self.assertRaisesRegex(Exception, "invalid API page"):
                run_once(self.config, API([value]), self.queue, NOW)
        outside = self.root / "outside"
        outside.write_text("untouched")
        (self.root / "state" / "ledger.sqlite3-wal").symlink_to(outside)
        with self.assertRaisesRegex(Exception, "unsafe state"):
            run_once(self.config, API([]), self.queue, NOW)
        self.assertEqual(outside.read_text(), "untouched")

    def test_missing_cursor_field_is_atomic_failure(self):
        with self.assertRaisesRegex(Exception, "invalid API page"):
            run_once(self.config, API([{"notes": [note()], "hasMore": False}]), self.queue, NOW)
        self.assertEqual(self.rows(), [])

    def test_non_rfc3339_timestamp_is_rejected(self):
        with self.assertRaisesRegex(Exception, "invalid API page"):
            run_once(self.config, API([page([note(created="2026-09-24\n10:00:00Z")])]), self.queue, NOW)
        self.assertEqual(self.rows(), [])

    def test_uncertain_operations_remain_inspectable_after_history(self):
        run_once(self.config, API([page()]), self.queue, NOW)
        with sqlite3.connect(self.root / "state" / "ledger.sqlite3") as db:
            for index in range(101):
                db.execute("INSERT INTO operations VALUES (?,?,?,'accepted',NULL,NULL,NULL)",
                           (str(index).zfill(64), "not_" + str(index).zfill(14), CUTOFF))
        def timeout(_):
            raise TimeoutError()
        with self.assertRaises(Exception):
            run_once(self.config, API([page([note()])]), timeout, NOW)
        report = status(self.config)
        self.assertEqual(report["operations"][0]["state"], "uncertain")
        self.assertEqual(report["counts"]["uncertain"], 1)
        operation = report["operations"][0]["operation_id"]
        exact = status(self.config, operation=operation)
        self.assertEqual(len(exact["operations"]), 1)
        self.assertEqual(exact["operations"][0]["attempt_id"], report["operations"][0]["attempt_id"])
        self.assertEqual(len(status(self.config, offset=100)["operations"]), 2)


if __name__ == "__main__":
    unittest.main()
