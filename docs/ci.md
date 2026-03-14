# CI integration

This repository includes two composite actions that implement a `scan -> audit` flow.

## Included actions

- `./.github/actions/scan`
- `./.github/actions/audit`

## scan action

Purpose:

- build `cryptodiff`
- run `scan`
- optionally run base/head scans + `diff`
- emit reusable artifact paths

Inputs:

- `config` (default `cryptodiff.yaml`)
- `out-dir` (default `cryptodiff-out`)
- `strict-scan-errors` (default `false`)
- `base-ref` (optional)
- `head-ref` (optional)
- `upload-artifacts` (default `true`)

Config behavior:

- If `config` is left at default `cryptodiff.yaml` and the file is missing, the action falls back to built-in defaults.
- If `config` is set to a non-default path and missing, the action fails fast.

Base/head ref validation:

- Set both `base-ref` and `head-ref` to run range mode (`base` + `head` scans and `diff.json`).
- Set neither to run snapshot mode.
- Setting only one of `base-ref` or `head-ref` is a usage error and fails the action (matches CLI behavior).

Range policy semantics:

- Range diff runs both scans under one constant scanning policy.
- In the composite action, that policy config is read from the trusted `base-ref` (`<base-ref>:<config>`), then applied to both sides.
- This keeps policy constant while comparing code changes across refs.
- If `config` is left at default `cryptodiff.yaml` and the file is missing, the action falls back to built-in defaults.
- If `config` is set to a non-default path and missing, the action fails fast.

Outputs:

- `snapshot-path`
- `diff-path` (set only in base/head mode)
- `sarif-path`
- `cbom-path`

Scan error behavior:

- By default, scan continues and writes artifacts even when some files/paths fail to scan.
- Those errors are captured in `posture.json` under `summary.scanErrors` and `scanErrors[]`.
- Set `strict-scan-errors: true` to fail the scan step if any scan errors are present.

## audit action

Purpose:

- build `cryptodiff`
- run `audit` against either `diff-path` or `snapshot-path`
- expose workflow-friendly outputs

Inputs:

- `config` (default `cryptodiff.yaml`)
- `policy` (default `policy/cryptodiff-policy.yaml`)
- `baseline` (optional)
- `exceptions` (optional)
- `diff-path` (optional, mutually exclusive with `snapshot-path`)
- `snapshot-path` (optional, mutually exclusive with `diff-path`)
- `mode` (`report` or `gate`, default `report`)
- `fail-level` (default `high`)
- `out-dir` (default `cryptodiff-out`)
- `upload-artifacts` (default `true`)

Outputs:

- `violations-found` (`true`/`false`)
- `violation-count`
- `summary`
- `audit-path`

Exit behavior:

- exits with `1` when policy fails in gate mode
- exits with `2` on action/tool misuse errors

## Example workflow

Use the included workflow:

- `./.github/workflows/cryptodiff-ci.yml`

It:

1. checks out full history
2. runs `scan` (PR mode uses base/head refs and generates `diff.json`)
3. uploads SARIF to GitHub code scanning
4. selects exactly one audit target (`diff` when available, else `snapshot`)
5. runs `audit` in `gate` mode

## Minimal custom workflow snippet

```yaml
name: cryptodiff
on:
  pull_request:
  workflow_dispatch:

jobs:
  cryptodiff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan
        id: scan
        uses: ./.github/actions/scan
        with:
          out-dir: cryptodiff-out
          strict-scan-errors: true

      - name: Audit (snapshot mode)
        id: audit
        uses: ./.github/actions/audit
        with:
          snapshot-path: ${{ steps.scan.outputs.snapshot-path }}
          mode: gate
          fail-level: high
```

## Recommended rollout

1. Start with `audit mode=report`.
2. Move to `mode=gate` with `fail-level=critical`.
3. Expand to `fail-level=high` after suppression/baseline cleanup.
4. Enable `strict-scan-errors=true` once repositories are clean of scan-read/parse issues.