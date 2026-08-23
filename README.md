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

The only publishing workflow is manually dispatched. It has:

- one concurrent build;
- a 20-minute timeout;
- Linux/amd64 only;
- immutable commit-SHA tags and digest output;
- SBOM and provenance attestations;
- a blocking critical-vulnerability scan.

Published image: `ghcr.io/mikeyerke/atx-untangled-runner`

## Status

The runner is under active beta validation. Do not claim an official submission unless an agency-issued confirmation is present.

ATX Untangled is independent and is not affiliated with the City of Austin, Austin Energy, or any government agency.

## License

Source-available under the Business Source License 1.1 with a limited non-competing production grant. Competitive hosted or managed use requires a commercial license. Each release converts to AGPL-3.0-or-later no later than four years after publication. See [LICENSE](LICENSE).

The ATX Untangled name and brand are not licensed. See [TRADEMARKS.md](TRADEMARKS.md).
