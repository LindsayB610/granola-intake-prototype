# Version and support matrix

**Status: BETA. LIVE END-TO-END HANDOFF UNVERIFIED.** Candidate version **0.1.0-beta.1** (September 2026); this is a local macOS beta, not a hosted service. Local and synthetic checks cover the configured-command interface and safeguards. Independent user/account or machine setup, actual Granola/ngrok delivery, and a fresh live owned-note handoff remain unverified. No downstream orchestrator behavior or completion is claimed. See [release evidence](architecture.md#release-evidence).

| Surface | Support status |
| --- | --- |
| macOS 26.6.2, Apple silicon, logged-in user session | Local verification environment. LaunchAgent lifecycle tests use fake launchctl; clean-room live service proof pending. Other macOS releases and Intel hardware have not been independently tested. |
| Python 3.14.6 standard library | Exact Python version used for the local extracted-package checks. Python 3.9 is the declared minimum, but has not been exercised in this audit. |
| Granola personal API key and signed webhook | Requires an eligible Business or Enterprise workspace and permitted personal scope. Real account proof is pending. |
| ngrok HTTPS endpoint | Owner-provided, reserved, public endpoint. Real external route proof is pending. |
| One owner-configured local executable | Implemented as argv + stdin request, source-bound receipt, and uncertainty fence. Example receiver proves the interface only. |
| Downstream AI/orchestrator, routing, tasks, publishing | User-owned and outside this release's support boundary. |
| Windows, Linux, shared notes, team routing | Not supported. |

Report bugs with synthetic IDs and invented payloads only. Never include a real transcript, meeting title, attendee, credential, local private path, webhook URL, or state database. Provider plan requirements and pricing can change; use the official Granola and ngrok links in the README.
