# Architecture and implementation gaps

This is a prototype boundary map, not an operational runbook.

1. **Discovery and identity:** the detector queries bounded pages of owned notes after an explicit cutoff. It derives one stable operation ID per provider note and records every wake attempt separately in SQLite. It preserves ambiguous delivery rather than retrying blindly.
2. **Source retrieval:** the source reader fetches a selected note and transcript pages with byte and time limits. Exact provider note IDs are the source identity. Real transcript completeness and retention behavior still need live validation.
3. **Private custody (to implement):** store exact provider evidence and a readable Markdown transcript under a private, owner-only path. Hash and read back the artifact before notifying a coordinator. Keep content out of task prompts and logs.
4. **Adjudication (to implement):** a trusted coordinator must read the complete source, decide whether it belongs to any project, and record one durable review item per note. A notice acceptance is separate from observed processing.
5. **Project handoff (to implement):** use verified project bindings and explicit source scopes. Reserve a stable new-task intent for each destination; read back task creation and each project-local source/intake receipt before closing the review item. Never route from a title or attendee guess.
6. **Unattended operation (to prove):** show that a scheduled run can access the private state, resolve the correct current task, deliver the notice, observe a completed processing turn, and reconcile the review item. Scheduling must remain off until that proof and an activation decision.

The detector CLI's `run-once` is live and platform-specific; it is not an end-to-end demonstration. `scheduler-definition` only prints a macOS launchd definition. Neither command installs a scheduler. The `.granola-api-key` path is local to a user installation and ignored by Git; no credential is included in this export.

Design constraints: preserve exact source bytes and hashes, bound reads and retries, do not replay uncertain sends, keep raw meeting content inside private project boundaries, and never treat a successful send as a completed intake.
