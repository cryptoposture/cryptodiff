# cryptodiff manual test plan (one-off / repeatable)

## Purpose

Provide a structured manual test plan that exercises all major `cryptodiff` functionality and configuration behavior:

- Commands: `scan`, `diff`, `audit`, `baseline`, `explain`
- Artifacts: `posture.json`, `posture.sarif`, `cbom.json`, `diff.json`, `diff.md`, `audit.json`
- Modes/options: range scan, strict scan errors, include/exclude scopes, baseline/exceptions, suppressions
- Config behavior: CLI/env/file precedence and explicit config-path handling
- Validation/error paths: malformed and schema-invalid input handling

## Test assets

Use these existing test assets:

- Real samples:
  - `/home/dhaslam/dev/cryptodiff/.ai-helper-files/kmb-server`
  - `/home/dhaslam/dev/cryptodiff/.ai-helper-files/quarklink.io`
- Synthetic fixture:
  - `/home/dhaslam/dev/cryptodiff/.ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo`

Recommended output root:

- `/home/dhaslam/dev/cryptodiff/.ai-helper-files/cryptodiff-kmb-oneoff/manual-results`

## Preconditions

1. Build current binary from the active branch:

```bash
cd /home/dhaslam/dev/cryptodiff
go build -o cryptodiff ./cmd/cryptodiff
mkdir -p .ai-helper-files/cryptodiff-kmb-oneoff/manual-results
```

2. Confirm fixture repo has git history (required for range mode):

```bash
git -C .ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo rev-list --max-parents=0 HEAD
```

## Test execution model

Each test case includes:

- **Objective**: what is being validated
- **Command(s)**: exact command(s) to run
- **Expected**: expected exit code and high-level output
- **Artifacts to inspect**: files/fields to verify
- **Record**: pass/fail + notes in your run log

Use this status template per case:

- `[ ]` Not run
- `[~]` Run / needs investigation
- `[x]` Pass
- `[!]` Fail (bug or regression)

---

## A. Scan command coverage

### A1. Snapshot scan baseline

- **Objective**: confirm default snapshot outputs and artifact generation.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/kmb-server" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A1"
```

- **Expected**:
  - Exit `0`
  - Writes `posture.json`, `posture.sarif`, `cbom.json`
- **Inspect**:
  - `posture.json.summary.findings`
  - `posture.json.findings[].fingerprint`
  - SARIF rule/result count matches posture finding count

### A2. Include/exclude scope behavior

- **Objective**: confirm scope controls materially alter findings.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/kmb-server" \
  --exclude "**/vendor/**,**/*_test.go,**/integration_tests/**,**/tests/**" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A2"
```

- **Expected**:
  - Exit `0`
  - Findings reduced vs A1 (often to zero on this sample)
- **Inspect**:
  - Compare A1 vs A2 finding counts and paths

### A3. Optional artifact toggles

- **Objective**: validate `--sarif` / `--cbom` toggles.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/quarklink.io" \
  --sarif=false \
  --cbom=false \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A3"
```

- **Expected**:
  - Exit `0`
  - Only `posture.json` present

### A4. Strict scan errors

- **Objective**: verify non-strict vs strict exit behavior for scan errors.
- **Command** (fixture contains a symlink case):

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A4/non-strict"

./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --strict-scan-errors=true \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A4/strict"
```

- **Expected**:
  - Non-strict exits `0` and records `scanErrors[]`
  - Strict exits `2` when scan errors are present
- **Inspect**:
  - `posture.json.summary.scanErrors`
  - `posture.json.scanErrors[].stage`

### A5. Range scan mode

- **Objective**: validate base/head worktree flow and generated diff artifacts.
- **Command**:

```bash
BASE=$(git -C .ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo rev-list --max-parents=0 HEAD)
HEAD=$(git -C .ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo rev-parse HEAD)

./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --base-ref "$BASE" \
  --head-ref "$HEAD" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A5"
```

- **Expected**:
  - Exit `0`
  - Writes `A5/base/posture.json`, `A5/head/posture.json`, `A5/diff.json`, `A5/diff.md`

### A6. Range mode validation error

- **Objective**: confirm one-sided ref usage is rejected.
- **Command**:

```bash
BASE=$(git -C .ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo rev-list --max-parents=0 HEAD)
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --base-ref "$BASE" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A6"
```

- **Expected**:
  - Exit `2`
  - Error mentions both refs are required

---

## B. Diff command coverage

### B1. Standard diff

- **Objective**: verify `diff` output generation and summary buckets.
- **Command**:

```bash
./cryptodiff diff \
  --base ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A2/posture.json" \
  --head ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A1/posture.json" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/B1"
```

- **Expected**:
  - Exit `0`
  - Writes `diff.json` and `diff.md`
  - Summary contains `addedCount/removedCount/changedCount/unchangedCount`

### B2. Format controls

- **Objective**: validate `--format=json|md|both`.
- **Command**:

```bash
./cryptodiff diff \
  --base ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A2/posture.json" \
  --head ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A1/posture.json" \
  --format json \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/B2-json"
```

- **Expected**:
  - Exit `0`
  - Only `diff.json` written for `json` mode

### B3. Invalid posture input resilience

- **Objective**: ensure invalid posture content is rejected.
- **Command**:
  - Use previously generated malformed posture file if available (or create one).
- **Expected**:
  - Exit `2`
  - Error indicates invalid diff/posture input

---

## C. Audit command coverage

### C1. Snapshot audit with default policy

- **Objective**: validate audit flow over snapshot and baseline policy behavior.
- **Command**:

```bash
./cryptodiff audit \
  --snapshot ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/A1/posture.json" \
  --policy "policy/cryptodiff-policy.yaml" \
  --mode gate \
  --fail-level high \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C1"
```

- **Expected**:
  - Exit `0` or `1` depending on policy coverage and findings
  - Writes `audit.json`

### C2. Diff audit

- **Objective**: validate change-focused policy evaluation.
- **Command**:

```bash
./cryptodiff audit \
  --diff ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/B1/diff.json" \
  --policy "policy/cryptodiff-policy.yaml" \
  --mode gate \
  --fail-level high \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C2"
```

- **Expected**:
  - Exit reflects gate result (`0` pass / `1` fail)
  - `audit.json.summary.evaluatedFindings` matches diff candidate set

### C3. Operator semantics (`in/not_in/lt/eq/neq`)

- **Objective**: verify policy operators on controlled snapshot.
- **Command**:
  - Reuse policies in:
    - `.ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/operators/`
- **Expected**:
  - `in`, `not_in`, `lt`, `eq` trigger expected failures where matching applies
  - `neq` does not trigger when equal value is present

### C4. Baseline suppression

- **Objective**: ensure baseline suppresses known violations.
- **Command**:

```bash
./cryptodiff baseline \
  --snapshot ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/operators/snapshot/posture.json" \
  --write ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C4/baseline.json"

./cryptodiff audit \
  --snapshot ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/operators/snapshot/posture.json" \
  --policy ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/baseline_exceptions/policy_all.yaml" \
  --baseline ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C4/baseline.json" \
  --mode gate \
  --fail-level high \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C4"
```

- **Expected**:
  - Baseline command exits `0`
  - Audit result moves toward pass with `summary.suppressed` populated

### C5. Exceptions (valid + expired + invalid)

- **Objective**: verify exception application and invalid exception reporting.
- **Command**:

```bash
./cryptodiff audit \
  --snapshot ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/operators/snapshot/posture.json" \
  --policy ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/baseline_exceptions/policy_all.yaml" \
  --exceptions ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/baseline_exceptions/exceptions_mix.yaml" \
  --mode gate \
  --fail-level high \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/C5"
```

- **Expected**:
  - Valid exception reduces violations
  - `invalidExceptions[]` includes expired/invalid entries

### C6. Input validation hardening checks

- **Objective**: confirm malformed inputs fail and shape-invalid parseable inputs are handled safely.
- **Command**:
  - Reuse files in `.ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/schema/`
- **Expected**:
  - Malformed JSON must fail with exit `2`
  - Schema-invalid but parseable artifacts should ideally fail (track current behavior if not)

---

## D. Explain command coverage

### D1. Selector success paths

- **Objective**: validate each selector mode.
- **Command**:

```bash
SNAP=".ai-helper-files/cryptodiff-kmb-oneoff/matrix/results/operators/snapshot/posture.json"
./cryptodiff explain --snapshot "$SNAP" --finding-id finding-9900150d7842
./cryptodiff explain --snapshot "$SNAP" --fingerprint 4b46df064fe84001586a34abf8577e37db018754c85f9b16a96a57acd48015d0
./cryptodiff explain --snapshot "$SNAP" --rule-id CRYPTO.TLS.MIN_VERSION
```

- **Expected**:
  - Exit `0` for each
  - Output includes rule, severity, category, evidence

### D2. Selector error paths

- **Objective**: validate proper errors for misuse and no-match.
- **Command**:

```bash
./cryptodiff explain --snapshot "$SNAP" --finding-id x --rule-id y
./cryptodiff explain --snapshot "$SNAP" --rule-id DOES.NOT.EXIST
```

- **Expected**:
  - Exit `2` with clear error messages

---

## E. Suppression behavior coverage

### E1. Inline + ignore file + config rule suppressions

- **Objective**: verify suppression counts and reason buckets.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --config ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo/cryptodiff.yaml" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/E1"
```

- **Expected**:
  - `posture.json.suppressions.inline` > 0
  - `posture.json.suppressions.ignoreFile` > 0
  - `posture.json.suppressions.configRule` > 0

### E2. Config category suppression

- **Objective**: verify category-based suppression.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --config ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo/config_category.yaml" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/E2"
```

- **Expected**:
  - `suppressions.configCategory` populated
  - Findings in suppressed categories reduced

---

## F. Config and precedence coverage

### F1. Env-only override

- **Objective**: confirm env vars influence behavior when CLI not set.
- **Command**:

```bash
CRYPTODIFF_OUT_DIR=".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/F1-env" \
./cryptodiff scan --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo"
```

- **Expected**:
  - Artifacts written to env out dir

### F2. CLI overrides env

- **Objective**: validate precedence ordering.
- **Command**:

```bash
CRYPTODIFF_OUT_DIR=".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/F2-env" \
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/F2-cli"
```

- **Expected**:
  - Output appears in CLI path (`F2-cli`)

### F3. Explicit missing config path

- **Objective**: ensure explicit config path failures are strict.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo" \
  --config ".ai-helper-files/cryptodiff-kmb-oneoff/matrix/fixture-repo/does-not-exist.yaml" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/F3"
```

- **Expected**:
  - Exit `2` with explicit config missing message

---

## G. Real-sample sanity checks

### G1. kmb-server sample

- **Objective**: validate behavior on larger Go codebase with tests.
- **Command**:
  - Re-run A1/A2 patterns against `.ai-helper-files/kmb-server`
- **Expected**:
  - Findings mainly in test locations unless broader scope enabled

### G2. quarklink.io sample

- **Objective**: validate config-heavy Kubernetes/Istio detection behavior.
- **Command**:

```bash
./cryptodiff scan \
  --repo ".ai-helper-files/quarklink.io" \
  --out-dir ".ai-helper-files/cryptodiff-kmb-oneoff/manual-results/G2"
```

- **Expected**:
  - Detects known verification-disable patterns in configs
  - Useful for detector precision review

---

## Defect logging format

For each issue found, log:

1. ID: `CD-MANUAL-XXX`
2. Title
3. Severity
4. Repro steps (copy exact command)
5. Expected vs actual
6. Artifact evidence path(s)
7. Suspected root cause
8. Suggested remediation

## Exit criteria for a manual run

Minimum for completion:

- All sections A-G executed or explicitly marked out-of-scope.
- Every failed case has a defect entry with artifact evidence.
- One summary table produced:
  - total cases
  - passed
  - failed
  - blocked
  - defects created

Optional quality gate:

- No new High severity defects for release candidate sign-off.
