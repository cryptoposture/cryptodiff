# cryptodiff

`cryptodiff` is a Go CLI for **Crypto Posture Governance** in CI/PR workflows.

It scans code/config/IaC for cryptographic posture signals, produces review-ready posture diffs, and gates policy with baseline + exception support.

Primary audience: security and platform teams that want to enforce crypto policy in pull requests without overwhelming developers.

## Project scope and commercialization

`cryptodiff` follows an open-code scanner + closed control-plane model:

- This repository contains the scanner CLI, artifact formats, default policy pack, and CI integration examples.
- The planned `cryptoposture` control plane (hosted management, org policy workflows, and multi-tenant governance features) is proprietary and maintained in separate private repositories.

This project is public for transparency and adoption, but it is not currently offered under an OSI open-source license.
Usage rights are defined in `LICENSE`.

## Why cryptodiff

- **PR-focused workflow**: generate posture artifacts, diff them, and gate only net-new risk.
- **Low-noise defaults**: high-confidence initial rule pack and stable fingerprints.
- **Adoption controls**: suppressions, baselines, and time-bound exceptions.
- **Interoperability**: JSON artifacts, SARIF, and CycloneDX-style CBOM output.

## Quick start

### Build

```bash
go build -o cryptodiff ./cmd/cryptodiff
```

### Scan

```bash
./cryptodiff scan --repo . --out-dir cryptodiff-out
```

Optional scope controls:

```bash
./cryptodiff scan --repo . --include "**/*.go,**/*.yaml" --exclude "**/vendor/**,**/testdata/**"
```

Scan error handling (default: report and continue):

```bash
./cryptodiff scan --repo . --out-dir cryptodiff-out --strict-scan-errors=true
```

When strict mode is enabled, scan exits with code `2` if any file/path scan errors are encountered.

Outputs:

- `cryptodiff-out/posture.json`
- `cryptodiff-out/posture.sarif`
- `cryptodiff-out/cbom.json`

### Diff

```bash
./cryptodiff diff \
  --base cryptodiff-out/base/posture.json \
  --head cryptodiff-out/head/posture.json \
  --out-dir cryptodiff-out
```

Outputs:

- `cryptodiff-out/diff.json`
- `cryptodiff-out/diff.md`

### Audit

```bash
./cryptodiff audit \
  --policy policy/cryptodiff-policy.yaml \
  --diff cryptodiff-out/diff.json \
  --mode gate \
  --fail-level high \
  --out-dir cryptodiff-out
```

Output:

- `cryptodiff-out/audit.json`

Hybrid enforcement semantics:

- Findings at or above `--fail-level` are policy violations by default.
- Policy rules can additionally map findings to policy-specific rule IDs and thresholds.
- In `--mode gate`, any remaining violation after baseline/exception filtering fails the run.

Exit codes:

- `0`: pass
- `1`: policy failure (gate mode)
- `2`: tool/config/runtime error

## Scan error visibility and strict mode

`posture.json` now includes scan error telemetry:

- `summary.scanErrors`: number of file/path scan errors encountered
- `scanErrors[]`: per-error details (`path`, `stage`, `message`)

Default behavior is non-strict: scan still emits artifacts and exits `0` even when `scanErrors > 0`.

Use strict mode to fail CI on scan errors:

- CLI: `--strict-scan-errors=true`
- Config: `scan.failOnError: true`
- Env: `CRYPTODIFF_SCAN_FAIL_ON_ERROR=true`

## Examples

### Report-only pilot (no build break)

```bash
./cryptodiff scan --repo . --out-dir cryptodiff-out
./cryptodiff audit \
  --snapshot cryptodiff-out/posture.json \
  --policy policy/cryptodiff-policy.yaml \
  --mode report \
  --fail-level high \
  --out-dir cryptodiff-out
```

### Gate on PR diff (fail on new high+)

```bash
./cryptodiff scan --repo /tmp/repo-base --out-dir cryptodiff-out/base
./cryptodiff scan --repo /tmp/repo-head --out-dir cryptodiff-out/head
./cryptodiff diff \
  --base cryptodiff-out/base/posture.json \
  --head cryptodiff-out/head/posture.json \
  --out-dir cryptodiff-out
./cryptodiff audit \
  --diff cryptodiff-out/diff.json \
  --policy policy/cryptodiff-policy.yaml \
  --mode gate \
  --fail-level high \
  --out-dir cryptodiff-out
```

### Baseline + exceptions onboarding

```bash
# Create baseline from known current posture
./cryptodiff baseline \
  --snapshot cryptodiff-out/posture.json \
  --write baseline/cryptodiff-baseline.json

# Gate only on net-new violations, allow active exceptions
./cryptodiff audit \
  --diff cryptodiff-out/diff.json \
  --policy policy/cryptodiff-policy.yaml \
  --baseline baseline/cryptodiff-baseline.json \
  --exceptions policy/cryptodiff-exceptions.yaml \
  --mode gate \
  --fail-level high \
  --out-dir cryptodiff-out
```

## Commands

- `scan`: create posture snapshot and optional integration artifacts.
- `diff`: compare base/head posture snapshots.
- `audit`: evaluate policy on snapshot or diff, with optional baseline/exceptions.
- `baseline`: create baseline from `posture.json` or `audit.json`.
- `explain`: render human-readable details for a selected finding.

## Current rule pack (v0.2)

- `CRYPTO.TLS.MIN_VERSION`
- `CRYPTO.TLS.WEAK_CIPHER`
- `CRYPTO.CERT.VERIFY_DISABLED`
- `CRYPTO.ALG.DISALLOWED`
- `CRYPTO.KEY.WEAK_SIZE`

## Artifact contracts

Schemas are embedded and validated at runtime before writing artifacts:

- `schemas/posture.schema.json`
- `schemas/diff.schema.json`
- `schemas/audit.schema.json`

## Config precedence

`cryptodiff` resolves settings in this order:

1. CLI flags
2. Environment variables
3. `cryptodiff.yaml`
4. Defaults

Config file behavior:

- If `--config` or `CRYPTODIFF_CONFIG` is set to a non-empty path, that file must exist or the command fails.
- If neither is set, missing default `cryptodiff.yaml` is allowed and defaults are used.

Examples of environment variables:

- `CRYPTODIFF_CONFIG`
- `CRYPTODIFF_OUT_DIR`
- `CRYPTODIFF_POLICY_MODE`
- `CRYPTODIFF_FAIL_LEVEL`
- `CRYPTODIFF_SCAN_MAX_FILE_BYTES`
- `CRYPTODIFF_SCAN_FAIL_ON_ERROR`
- `CRYPTODIFF_SCAN_INCLUDE`
- `CRYPTODIFF_SCAN_EXCLUDE`
- `CRYPTODIFF_SUPPRESS_RULES`
- `CRYPTODIFF_SUPPRESS_CATEGORIES`
- `CRYPTODIFF_SUPPRESS_PATHS`

## Suppressions, baseline, exceptions

- **Suppressions**:
  - inline directives (`cryptodiff:ignore`, `cryptodiff:ignore-next-line`)
  - ignore file (`.cryptodiffignore`)
  - config suppressions by rule/category/path
- **Intentional insecure test fixtures**: prefer local inline directives on the exact fixture line (with a brief rationale comment) instead of broad path exclusions, so CI signal remains high for the rest of the repository.
- **Baselines**: fail on net-new violations.
- **Exceptions**: time-bound rule/fingerprint exceptions, with invalid/expired entries surfaced in `audit.json`.

## CI/CD usage

Local composite actions are included:

- `./.github/actions/scan`
- `./.github/actions/audit`

Example workflow:

- `./.github/workflows/cryptodiff-ci.yml`

More details: `docs/ci.md`.

Project model details: `docs/project-model.md`.

Contribution policy: `CONTRIBUTING.md`.

Security reporting: `SECURITY.md`.

## Development

Run local quality checks (mirrors CI quality job):

```bash
gofmt -l cmd internal schemas
go vet ./...
go test ./...
go test -race ./...
```

Run tests only:

```bash
go test ./...
```

This repo intentionally uses a stdlib-first approach (including lightweight YAML/schema handling) to remain portable in restricted environments.
