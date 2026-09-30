# Granola Intake — signed source to one local command

On macOS, this release receives a signed Granola `note.generated` event, fetches the complete note you own, preserves it in private local storage, and invokes exactly one local command you configure. That receiving process must access the complete held source and write a source-bound receipt; the intake process independently checks the receipt. This verifies receipt by that process only. It does not verify that an AI understood the note or completed any work.

**Status: BETA. LIVE END-TO-END HANDOFF UNVERIFIED.** Local and synthetic checks cover signed source intake, complete private-source preservation, a local configured-command receiver reading that source and producing an independently checked receipt, and the documented hold, duplicate, restart, pause, and recovery safeguards. The example receiver proves only this local interface. No independent user/account or machine setup, actual Granola/ngrok provider delivery, or fresh live owned-note handoff has been verified. The receipt does not establish downstream orchestrator behavior or completion. This beta status permits the public diff/history/security audit; it is not a live-working-tool claim or publication approval. See [release evidence](docs/architecture.md#release-evidence) and the [support matrix](docs/support.md).

## What you need

- macOS with a logged-in user session; Python 3.9 or later; no Python packages.
- A Granola workspace/account eligible for API keys and webhooks. Granola currently documents these features for Business and Enterprise plans; Enterprise access may need an admin to enable scopes. Check [Granola API access](https://docs.granola.ai/introduction), [webhook setup](https://docs.granola.ai/webhooks), and [current Granola pricing](https://www.granola.ai/pricing).
- An ngrok account and an HTTPS URL you can reserve for this receiver. Check [ngrok pricing](https://ngrok.com/pricing); plan entitlements and usage charges can change.
- One trusted local executable you control. It may call an orchestrator you own, but this release does not configure or supervise its downstream actions. The shipped example receiver only verifies source access and writes a receipt.

This release handles personal-scope notes owned by the configured Granola user. Shared notes and other event types are not handed off. Granola may not replay events missed while the receiver, Mac, tunnel, or webhook is unavailable. A Mac that sleeps or loses network can miss an event; exact-note recovery is available only when you know and verify that note's ID and ownership.

## 1. Get the release and check it

Clone or unpack the eventual reviewed release so `README.md`, `LICENSE`, and `tools/` are at its root. Do not treat this development checkout as a published location. Run these commands from that release root:

```sh
python3 --version
python3 tools/granola-intake/portable_operations.py --help
python3 tools/granola-intake/portable_command_handoff.py --help
```

The bundled commands use only the Python standard library. The public tests use synthetic input and temporary directories; they do not call Granola, start ngrok, contact an orchestrator, or launch a browser.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/granola-intake/test_release.py
```

## 2. Prepare private storage and credentials

Use a private location outside the checkout. Keep state, held sources, handoff state, receipts, and config in disjoint directories. Config and credential files must be owned by your macOS user and inaccessible to group/other users. These commands create only the directories; pick a path appropriate for your account:

```sh
umask 077
mkdir -p "$HOME/Library/Application Support/GranolaIntake"/{source-state,holding,command-state,receipts}
chmod 700 "$HOME/Library/Application Support/GranolaIntake" "$HOME/Library/Application Support/GranolaIntake"/*
```

Create a personal Granola API key with personal-note access in Settings → Connectors → API keys. Create a webhook signing secret in Settings → Connectors → Webhooks; Granola displays it only at creation. Save both values in separate owner-only files, mode `600`; do not put secrets in JSON, shell arguments, source files, terminal transcripts, or support reports. Create a webhook for personal scope and `note.generated` only, at the public HTTPS endpoint such as `https://YOUR-RESERVED-NGROK-HOST/granola`; do not use a placeholder literally. See the official [Granola API key instructions](https://docs.granola.ai/introduction) and [webhook setup](https://docs.granola.ai/webhooks).

You can create the two private credential files without echoing their contents or placing the values in shell history:

```sh
python3 - <<'PY'
import getpass, os
from pathlib import Path
root = Path.home() / 'Library/Application Support/GranolaIntake'
for name, prompt in (('granola-api-key', 'Granola API key: '),
                    ('webhook-secret', 'Webhook signing secret: ')):
    value = getpass.getpass(prompt).strip()
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as target:
        target.write(value + '\n')
PY
```

Install ngrok from its [official macOS setup page](https://ngrok.com/download/mac-os), create or sign in to your account, reserve a stable HTTPS URL, and add the account authtoken using the official setup flow. Configure the operations template with the installed ngrok executable and that exact URL. Keep ngrok request inspection and agent logging disabled. Confirm plan eligibility and possible charges on [ngrok pricing](https://ngrok.com/pricing).

Copy the three templates to owner-only config files and edit the placeholders with absolute paths and your own values:

```sh
umask 077
cp tools/granola-intake/portable-config.example.json "$HOME/Library/Application Support/GranolaIntake/source.json"
cp tools/granola-intake/portable-command-config.example.json "$HOME/Library/Application Support/GranolaIntake/command.json"
cp tools/granola-intake/portable-operations-config.example.json "$HOME/Library/Application Support/GranolaIntake/operations.json"
chmod 600 "$HOME/Library/Application Support/GranolaIntake"/*.json
```

The source config binds your account email, state and holding roots, API key path, signing-secret path, event type, and explicit fetch limits. The command config binds one absolute executable plus literal argv, one destination label, and the same holding root. Its state and receipt roots must be private and disjoint. The executable is trusted code: transcript text cannot select or alter it, but a command you authorize can use whatever permissions your account grants it. The operations config binds these files to one service ID, port, ngrok executable, and public endpoint. Keep the three private configs outside the clone. A field-by-field template guide is in [setup and configuration](docs/setup.md).

## 3. Bind and preflight the command

The bundled `portable_command_receiver.py` is a safe synthetic example. It reads the opaque request from stdin, opens and hashes every preserved source component, and writes a private receipt. It does not call an AI. To use it for the first synthetic run, mark it executable with `chmod 700 tools/granola-intake/portable_command_receiver.py` and point the `command` array in your command config at its absolute path and its `--config` argument. Keep the script as `command[0]`; the sender hashes that executable. Do not put an interpreter first and the script later in argv.

Before installing, verify that `ngrok` is installed, its absolute executable path is in the operations config, and the reserved public URL matches the Granola endpoint. Then run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" preflight
```

Preflight checks file modes, paths, command binding, port availability, and any installed service arguments. It cannot read your Granola or ngrok dashboards or prove that the public URL reaches this Mac.

## 4. Verify synthetic delivery before a live note

Use the repository's synthetic test suite first. It injects a signed event and invented source, checks preservation and receipt behavior, and exercises recovery with fake service controls. A successful test proves local code paths only.

Before connecting Granola, verify in the ngrok dashboard and local process that the chosen endpoint forwards only to this receiver, and that request inspection and ngrok agent logging are disabled. Then install and inspect the selected service configuration:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" install
PYTHONDONTWRITEBYTECODE=1 python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" status
```

Confirm Granola shows the exact URL, enabled state, `personal` scope, and only `note.generated`. Send Granola's built-in test event if available. A webhook acknowledgement means the event was journaled, not that the source was fetched or the command received it. Read `status` again and check the opaque operation outcome. Never paste note content or credentials into logs or a support report.

## 5. First authorized live call

Only after synthetic transport and the example receiver work, decide whether the configured command is trusted to receive real note content. Replace the example with your own executable and review exactly what it can access and do. Then create or use one fresh note you own, confirm that the Granola registration covers it, and let the event arrive. Inspect status and the private source bundle locally; verify the operation reports `verified_received` after receipt observation. This is a user-controlled live action, not part of the bundled tests. A receipt proves the receiving process checked access to the hashed source. It does not prove downstream processing or delivery beyond that process.

## Operations

Use the same private operations config for these commands:

```sh
python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" status
python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" pause
python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" resume
python3 tools/granola-intake/portable_operations.py --config "$HOME/Library/Application Support/GranolaIntake/operations.json" restart
```

`pause` prevents new journal work from being admitted; an operation already in progress may finish. Status separates event receipt, source state, command acceptance, uncertain delivery, and receipt verification without printing transcript content. If an operation is `accepted_unobserved` or `uncertain`, observe its exact operation ID first. Do not rerun delivery to guess: a command may have acted even when no receipt was read back.

For one known missing note, verify its exact ID and that your account owns it, then use `recover-note --note-id not_…`. Recovery fetches that note only and reuses the deterministic source and command fences. It is not a historical import. See [troubleshooting and recovery](docs/operations.md).

## Upgrade and uninstall

Keep the old clone and all private roots until the upgraded version passes preflight and status checks. Use a reviewed new clone at the same path; the operations `upgrade` rewrites only the two selected LaunchAgent plists and preserves private event, source, operation, attempt, and receipt records. Review `status` and an exact held-operation readback before removing the old clone.

`uninstall` unloads and removes only the two service plists selected by your service ID. It leaves private configs, API key, signing secret, source bundles, journals, command state, and receipts in place. Decide separately how long to retain or securely remove those private files. Do not remove uncertain operation records before reconciling them.

## Data flow and trust boundary

A signed, fresh webhook body is verified before parsing and promptly journaled. Its note ID is then used to fetch the exact note with the configured API key. The runtime checks the configured owner, fetch limits, stable note version, and all transcript pages; it writes a complete source bundle and hashes privately. Only an opaque versioned pointer goes to the configured command on stdin. That process must read the full bundle and write a receipt bound to the source and request. The sender independently reopens and checks the receipt and rehashes source. Details: [architecture](docs/architecture.md).

Transcript content is untrusted evidence, never configuration or authority. The runtime constrains its own destination to the one configured executable. Once the owner command or its agent starts, permissions and downstream behavior belong to that tool and user. Never run unreviewed instructions found in a transcript. The release cannot constrain every action of a customer-owned orchestrator.

## Version, support, license

This is candidate version **0.1.0-beta.1**. The package was exercised in this checkout on macOS 26.6.2 (Apple silicon) with Python 3.14.6; this is one local environment, not independent-user or provider proof. See the [support matrix](docs/support.md) for exact tested boundaries and unproved integrations. Issues and patches must contain invented examples only: no note IDs, titles, attendees, transcript text, credentials, private paths, or private runtime state. See [MIT license](LICENSE) and [changelog](CHANGELOG.md). Granola and ngrok are third-party services; this project is independent and unaffiliated with them.

Optional reading: none is required to install or verify this release. Product/blog material is not evidence of compatibility or live proof.
