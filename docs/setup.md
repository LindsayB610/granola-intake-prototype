# Setup and configuration

## Install location and runtime

Use a local clone whose path will remain fixed while LaunchAgents point to it. Python 3.9+ from python.org, Homebrew, or the operating system is sufficient; no package installation is used. Keep the clone readable only to users who should inspect the code. Runtime state and secrets belong outside it.

## Source config

Start from `tools/granola-intake/portable-config.example.json`. Replace every placeholder. `owner_email` must match the account that owns notes. `state_dir`, `holding_root`, credential file, and signing-secret file must be absolute paths outside the checkout. Keep state and holding separate. `source_policy` bounds page count, per-page bytes, total bytes, and elapsed retrieval time. The only supported event list is `note.generated`.

The API credential is a personal `grn_…` key with personal-note scope. The webhook secret is the one-time `whsec_…` value. Store each in a separate mode-0600 regular file under a mode-0700 parent. Rotate by updating the file safely and re-running preflight. Never commit either value.

## Command config

Start from `tools/granola-intake/portable-command-config.example.json`. Its `holding_root` must exactly equal the source config. `state_dir` and `receipt_root` must be disjoint private directories. `destination_id` is a label, not a route supplied by transcript content. `command` is an argv array: absolute executable path first, followed by literal arguments. No shell expansion occurs. The executable is hashed and checked before delivery and observation. If using the sample receiver, make the shipped script executable and bind it directly as `command[0]`; configure its private config path in later argv.

The receiver gets a small JSON request on stdin: schema version, operation ID, source hashes, destination label, and attempt ID. It does not receive title, attendees, or transcript inline. The recipient must use the operation pointer and configured holding root to read the complete private source, then call the receipt helper. A zero exit status means accepted for execution, not verified receipt. Receipt verification is a separate readback.

## Operations config and service

Start from `tools/granola-intake/portable-operations-config.example.json`. Choose a unique `service_id`, a free loopback port, the absolute paths to the other two configs, ngrok executable, and the exact reserved public URL ending in `/granola`. The first install creates two selected LaunchAgents, receiver and tunnel. It does not register a webhook in Granola. Create the webhook yourself and compare the exact URL, personal scope, event, and enabled state in Granola's UI.

The ngrok tunnel is started with inspection and agent logging disabled, and service stdout/stderr are discarded. Verify your ngrok account's own traffic/log retention settings. `preflight` validates local bindings only; it cannot confirm external account settings or public reachability.
