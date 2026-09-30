# Operations and recovery

Run commands from the release root and use the same absolute private operations config each time:

```sh
python3 tools/granola-intake/portable_operations.py --config /ABSOLUTE/PRIVATE/operations.json status
```

## Status and pause

Status reports receiver/tunnel state, the external webhook as requiring manual dashboard readback, event count/status, source state, command status, and receipt outcome without printing source. `pause` blocks admission of new pending events; in-flight work can finish. `resume` reopens admission. `stop` unloads only the two agents selected by the configured service identity. `start` and `restart` affect those same selected agents.

## Uncertain delivery

For `accepted_unobserved` or `uncertain`, first run `observe --operation EXACT_64_HEX_OPERATION_ID` using the command handoff CLI and inspect the receiving process under your own control. Do not clear the reservation, delete the record, or call `deliver` again to guess. A timeout or missing receipt does not prove that the command did nothing. If a later valid receipt exists, observe can verify it without another invocation.

## Sleep, tunnel, and missed event

After sleep or a crash, run status, check ngrok's URL/connection and Granola's webhook enabled state, then restart the selected service if needed. If the URL changed, update operations config and the Granola webhook together, run `upgrade`, re-check the route, and send a fresh synthetic test. Granola may not replay events missed while offline or while a webhook was disabled.

For a single known missing note, verify the note ID and account ownership in Granola, then run:

```sh
python3 tools/granola-intake/portable_operations.py --config /ABSOLUTE/PRIVATE/operations.json recover-note --note-id not_1234567890abcd
```

The ID above is illustrative only. The command fetches only that exact note and reuses the operation/source/delivery fences. Do not guess IDs or use this command for bulk history.

## Upgrade and uninstall

Use a reviewed new clone at the same location for an in-place upgrade. Run `preflight`, then `upgrade`; it rewrites only the two selected service plists and preserves private identity/history. Before publishing a recovery journal or querying/stopping services, install and upgrade check every descriptor/marker `.new`, `.rollback`, and `.recover` suffix plus any recovery-journal temporary. A pre-existing suffix is ambiguous and is retained; the command stops without publishing a journal or mutating services. Each invocation writes replacement data exclusively and removes a failed temporary only while its inode, owner, mode, link count, size, and digest still match what that invocation wrote. Successful `os.replace` consumes the temporary. A crash can therefore leave an ambiguous suffix; later invocations retain it and require manual inspection rather than claiming ownership from private mode or matching content. The upgrade journal itself is written to an owner-only random temporary file, fsynced, atomically published, and the containing directory is synced before services stop. A journal temp left by a crashed writer is likewise retained and causes management commands to stop before service queries. A committed journal with any remaining suffix is treated as ambiguous and retained before either service is touched. The journal records both generations so a normal interrupted upgrade with no leftover suffix can restore the old descriptors and marker. A same-user process with write access can still race the final identity check and unlink/replace boundary; ordinary filesystem unlink has no portable compare-and-delete operation. A malformed journal or any ambiguous ownership/state check fails closed and remains in place for inspection. Check status and one exact held operation before removing the old code.

`uninstall` removes those selected plists and unloads their services. Private configs, credentials, transcripts, journals, command state, and receipts stay on disk. Retain or securely remove each private root according to your own retention requirements after uncertainty is reconciled.
