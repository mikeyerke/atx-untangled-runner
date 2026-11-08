# ATX Untangled Confidential Runner

A disposable, hardware-attested browser execution room for resident-authorized Austin service workflows.

## What it does

- Starts one isolated browser room for one authorized resident case.
- Receives the case directly from the resident's browser using ephemeral ECDH + AES-256-GCM.
- Provides a private resident takeover for CAPTCHA, MFA, signatures, payments, or facts the agent cannot know.
- Resumes automation after the protected step.
- Records success only when the official agency returns a confirmation.
- Exits after the receipt or a hard 30-minute limit. The control plane then deletes the CVM.

The ATX Untangled operator does not receive plaintext resident case facts in the strict path.

## Safety boundaries

The runner rejects unsupported job types, refuses emergencies, restricts navigation to case-specific official domains, caps payload and receipt sizes, caps browser actions, emits no public application logs, and exposes takeover access only through a resident-held token.

This repository contains no API keys, resident data, deployment secrets, or production configuration.

## Build

The publishing workflow supports manual dispatch and main-branch pushes that
change its configured image inputs. It has:

- one concurrent build;
- a 20-minute timeout;
- Linux/amd64 only;
- immutable commit-SHA tags and digest output;
- SBOM and provenance attestations;
- a blocking critical-vulnerability scan.

Published image: `ghcr.io/mikeyerke/atx-untangled-runner`

## Resident origin and readiness monitor

The runner defaults to `https://atxuntangled.com`. `ATX_RESIDENT_ORIGIN` still
replaces that default for the runner's CORS responses and notification links.
Existing running images are unchanged; publishing this source does not repin
the resident app's immutable runner image.

Before merging the origin fix, set the **repository Actions variable**
`ATX_RESIDENT_ORIGIN` to `https://atxuntangled.com` in this repository
(Settings → Secrets and variables → Actions → Variables). It is not a secret.
The workflow deliberately has no hard-coded origin fallback and fails with a
configuration message if the variable is missing or is not an HTTPS origin.
A single trailing slash is accepted; paths, queries, credentials and fragments
are rejected. The repository variable is separate from the environment override
passed to an actual runner container.

`.github/workflows/reconcile.yml` retains its existing workflow name for history,
but now labels its step as a readiness check. It runs every 30 minutes and on
manual dispatch, using only `GET /api/readiness`, without redirects. Three
retries, a 10-second connect timeout and a 20-second per-attempt limit keep
four attempts plus backoff within the two-minute job budget. A passing run proves
HTTP availability; it does not prove that a session was deleted.

### Teardown ownership and a catch-up run

Reviewed against the live resident app revision
`f6d07181ebcea7a621511141db948f0d8eadbc0a` on November 8, 2026:

- `GET /api/readiness` is a read-only status route. It does not invoke expiry
  reconciliation, delete a provider resource, or settle a session budget.
- The resident app's own Cloudflare schedule includes `*/5 * * * *`. When its
  execution pipeline is enabled, scheduled execution maintenance calls
  `expireConfidentialSessions` independently of this GitHub workflow.
- That expiry pass selects at most 10 outstanding eligible rows, including
  expired/invalid timing, prior deletion failures, and certain uncertain create
  intents. For known provider resources it requests deletion, verifies provider
  absence/deletion, and only then marks the matching session generation
  destroyed and settles its reserved/consumed compute ledger. Unknown creates
  have separate identity checks; absence from an inventory alone is not proof.
- The broader scheduled maintenance also handles receipts, leases, notifications
  and other work. It is not a deletion-only catch-up operation.

A one-time manual run of **this updated workflow** would only check readiness;
it would not clear a teardown backlog. Its old-host 404 failures do not establish
whether any provider resources were left behind. Establish a backlog first with
read-only session-ledger and provider-inventory/deletion evidence. Any real
cleanup must be reviewed and authorized separately; no cleanup endpoint or
maintenance trigger is added here.

The initial November 8 D1 query returned authorization error `7403`. After
refreshing the existing CLI session, a read-only ledger/deletion-receipt audit
succeeded: all 14 retained session rows are destroyed, all 11 allocated provider
resources have deletion confirmations, and the other three rows have no provider
allocation. Seven retained rows were destroyed after October 17. The ledger
reports zero active sessions, reserved minutes, or outstanding expired rows.
There was no tracked backlog requiring catch-up and no cleanup was triggered.
This is retained-ledger evidence, not a fresh full provider inventory or a
reconstruction of every historical session generation.

Merging a change to `src/server.mjs` also matches the existing main-branch
`publish.yml` image-build trigger. Opening this PR does not run either workflow.

## Status

The runner is under active beta validation. Do not claim an official submission unless an agency-issued confirmation is present.

ATX Untangled is independent and is not affiliated with the City of Austin, Austin Energy, or any government agency.

## License

Source-available under the Business Source License 1.1 with a limited non-competing production grant. Competitive hosted or managed use requires a commercial license. Each release converts to AGPL-3.0-or-later no later than four years after publication. See [LICENSE](LICENSE).

The ATX Untangled name and brand are not licensed. See [TRADEMARKS.md](TRADEMARKS.md).
