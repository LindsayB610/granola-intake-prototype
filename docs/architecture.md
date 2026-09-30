# Architecture and acceptance boundary

## Data path

1. Granola posts a small signed event to the public HTTPS endpoint. The receiver checks timestamp, signature over raw bytes, event ID, event kind, and note ID before accepting JSON-derived work.
2. The local journal deduplicates the event. The worker fetches only that note ID from the Granola API using the owner's key. It requires the configured owner and a stable note version across metadata reads, and bounds pages, bytes, and time.
3. The complete transcript representation, raw metadata, raw pages, rendered Markdown, hashes, and provenance are written as a private owner-only bundle outside the clone. Source text is not logged or sent as command arguments.
4. One configured absolute executable receives a versioned opaque request on stdin. A durable reservation is written before invocation. The receiver process reads and hashes the complete source and writes a private source-bound receipt. The sender independently reopens the receipt and verifies the source hashes.
5. `verified_received` means that the configured local receiving process demonstrated access to this source. It does not establish semantic understanding, downstream completion, or external delivery.

## Trust boundaries

Only signed event fields select the exact note ID. Transcript text cannot select a command, destination label, or file permission. The configured command is trusted owner code, and any agent it starts runs with whatever permissions the owner grants. This release does not enforce the downstream agent's network, filesystem, or publication behavior. Protect the Mac account, executable, configs, and private state accordingly.

Shared-note access is outside v1 even if the Granola API key can see shared notes: the configured account owner check and supported event path reject it. Other event types are never fetched for handoff. Granola documentation says webhook event availability depends on plan/scope and that disabled endpoints do not replay missed events; see its [webhook delivery behavior](https://docs.granola.ai/webhooks).

## Failure semantics

- Event journal acknowledgement is not source readiness.
- `accepted_unobserved` means the command exited successfully, not that it read source.
- `uncertain` means the command may have acted. The operation stays fenced; observe before manual reconciliation. No automatic reinvocation.
- `verified_received` is a source-access receipt from that process, not downstream success.
- A missed webhook may require exact-note recovery after confirming ownership. Recovery is not a scan or bulk import.

## Release evidence

**Status: BETA. LIVE END-TO-END HANDOFF UNVERIFIED.** Local and synthetic evidence covers a clean extracted install, signed synthetic source delivery, a real local configured-command receiving process reading the complete source and writing a source-bound receipt that the intake process independently reads back, a shared-note hold, and duplicate, restart, pause/resume, and recovery safeguards. The example receiver proves its local interface only.

The beta gate does not include an independent user's account or machine setup, actual Granola/ngrok provider delivery, a fresh live owned note, or an independently verified live receiver receipt. Those are deferred evidence, not completed or waived criteria. No downstream orchestrator behavior or completion is established by the receipt. This evidence permits the Slice 06 public diff/history/security audit only; it does not establish a live-working-tool claim or authorize publication.
