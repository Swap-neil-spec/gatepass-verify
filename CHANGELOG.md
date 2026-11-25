# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-25

### Added

- Format adapters for AP2 mandates and Verifiable Intent credentials, checked from the public documents cited in the README. Checks the documents do not define are skipped or rejected, and are not reported as passed.
- `--evidence` and `--evidence --json`, a dispute bundle of what was approved, by whom, when, what ran, the verdict, and why.
- Decision records (`--format gatepass`): approved versus executed hashes, a passkey or key mandate, chain links, and an in-file witness head. See [docs/receipts.md](docs/receipts.md).

## [0.1.1] - 2026-11-25

### Changed

- Release pipeline: publish through npm trusted publishing with staged approval.

## [0.1.0] - 2026-11-14

First release of the offline verifier.

### Added

- `gatepass-verify --sample` checks a Keel permit shipped in the package, so the first command works after an install, without a repository checkout. If `--now` is omitted, the sample uses 2026-06-01T00:00:00Z.
- CITATION.cff and CHANGELOG.md are included in the published package.
- `gatepass-verify` command and `verify()` library entry that read one file or a buffer and return one verdict per record, with no network access and no runtime dependencies.
- Experimental interop for Keel Permit (`authority-envelope.v0`), including request binding, child attenuation on the v0 set fields, signed `permit.revoked` events, and expiry against `--now` or the local clock.
- Experimental interop for HAPS v0.4, ACTION-v1, and agent-flight-recorder hash chains, as described in the README format table.
- Verdicts `valid`, `tampered`, `revoked`, `widened`, `expired`, and `malformed`, with exit codes 0 and 2 through 6, and exit code 1 when the file is rejected before verification.
- JSON result document `gatepass-verify.result.v1`.
- Fixtures and tests for the verdicts above. Keel attenuation fixtures were written here from the public rules. They are not Keel-published test vectors.
