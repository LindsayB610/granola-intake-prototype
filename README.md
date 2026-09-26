# Granola Intake (development prototype)

**Status: in development. This does not work as an automatic end-to-end intake system yet. Do not install the scheduler or rely on it for meeting records.**

This repository shares a small, standard-library Python core for discovering owned Granola notes, preserving stable note and attempt identities, retrieving a bounded transcript representation, and tracking delivery uncertainty. It is a starting point for someone building their own private intake workflow, not a configured integration or hosted service.

The code under `tools/granola-intake/` includes a detector, a REST adapter, a selected-note source reader, a local metadata ledger, a CLI, and synthetic tests. It contains no API key, OAuth or MCP data, real meeting content, task IDs, client routing, or private runtime configuration. Granola is a third-party service; this project is independent and unaffiliated.

## Try the safe parts

Python 3.9+ and macOS are the current test target. No package install is needed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools/granola-intake -p 'test_*.py'
python3 tools/granola-intake/cli.py --help
```

Tests use synthetic responses and temporary private files. They do not contact Granola, Codex, a browser, or a scheduler. The example configuration is intentionally invalid. Do not run `run-once` until you have independently built and reviewed a private destination and credential setup; it performs live REST requests and can queue a task.

## What still needs implementation

See [architecture and gaps](docs/architecture.md). The core does not supply a portable Codex task destination, per-project routing, private transcript staging, verified handoff, or unattended scheduling. The original local workflow has synthetic coverage for some of those pieces, but no successful live end-to-end proof. A queued task is only a delivery attempt; it is not evidence that a transcript was read or filed.

This export is deliberately narrower than the private development repository. It excludes local work plans, review packets, client-specific contracts, configured bridges, and all source data. Contributions should use synthetic fixtures only. Never submit credentials, transcripts, attendee details, meeting titles, or private task output in issues or pull requests.

## License

[MIT](LICENSE). Copyright (c) 2026 Lindsay Brunner.
