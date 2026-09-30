# Invented handoff example

These values are made up and are not a live account, source, operation, or receipt. The real source bundle is private and contains `transcript.json`, `metadata.json`, one or more `page-NNNN.json` files, `provenance.json`, and `transcript.md`. Each component is hashed and stored owner-only.

A command receives an opaque request resembling:

```json
{
  "schema_version": 1,
  "operation_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "source_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "source_evidence_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "destination_id": "demo-orchestrator",
  "attempt_id": "dddddddddddddddddddddddddddddddd"
}
```

The sample receiver resolves that operation through the private holding root, opens and hashes the complete bundle, then writes an exclusive private receipt. The receipt repeats the request fields and includes a source evidence hash. These example digests are placeholders and are not valid evidence. Use the shipped receiver and tests for real synthetic verification; never copy invented hashes into a live receipt.
