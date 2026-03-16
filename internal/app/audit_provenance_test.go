package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunAuditEmitsSuppressedExceptedAndInvalidExceptions(t *testing.T) {
	tmp := t.TempDir()
	snapshotPath := filepath.Join(tmp, "posture.json")
	policyPath := filepath.Join(tmp, "policy.yaml")
	baselinePath := filepath.Join(tmp, "baseline.json")
	exceptionsPath := filepath.Join(tmp, "exceptions.yaml")
	outDir := filepath.Join(tmp, "out")

	posture := map[string]any{
		"schemaVersion": "0.2.0",
		"generatedAt":   "2026-01-01T00:00:00Z",
		"tool": map[string]any{
			"name":    "cryptodiff",
			"version": "0.2.0-dev",
		},
		"source": map[string]any{"repoPath": tmp},
		"findings": []map[string]any{
			{
				"id":          "f1",
				"ruleId":      "CRYPTO.ALG.DISALLOWED",
				"severity":    "critical",
				"category":    "algorithm",
				"confidence":  "high",
				"subject":     "Disallowed algorithm reference: md5",
				"fingerprint": "fp1",
				"attributes": map[string]any{
					"attribute":     "name",
					"detectedValue": "md5",
				},
				"evidence": []map[string]any{{"path": "app.yaml", "line": 1}},
			},
			{
				"id":          "f2",
				"ruleId":      "CRYPTO.ALG.DISALLOWED",
				"severity":    "critical",
				"category":    "algorithm",
				"confidence":  "high",
				"subject":     "Disallowed algorithm reference: sha1",
				"fingerprint": "fp2",
				"attributes": map[string]any{
					"attribute":     "name",
					"detectedValue": "sha1",
				},
				"evidence": []map[string]any{{"path": "app.yaml", "line": 2}},
			},
		},
	}
	writeJSONFixture(t, snapshotPath, posture)

	policy := `version: 0.2
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      value: [md5, sha1]
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	baseline := map[string]any{
		"schemaVersion": "0.2.0",
		"generatedAt":   "2026-01-01T00:00:00Z",
		"entries": []map[string]any{
			{"fingerprint": "fp1", "ruleId": "CRYPTO.ALG.DISALLOWED", "subject": "md5"},
		},
	}
	writeJSONFixture(t, baselinePath, baseline)

	exceptions := `entries:
  - fingerprint: fp2
    owner: team
    reason: temporary
    expiresAt: 2099-01-01T00:00:00Z
  - ruleId: CRYPTO.ALG.DISALLOWED
    expiresAt: bad-date
  - owner: no-selector
`
	if err := os.WriteFile(exceptionsPath, []byte(exceptions), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := Run([]string{
		"audit",
		"--snapshot", snapshotPath,
		"--policy", policyPath,
		"--baseline", baselinePath,
		"--exceptions", exceptionsPath,
		"--mode", "gate",
		"--out-dir", outDir,
	})
	if exit != 0 {
		t.Fatalf("expected audit to pass after baseline+exception filtering, got exit=%d", exit)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	summary, ok := report["summary"].(map[string]any)
	if !ok {
		t.Fatal("expected summary object")
	}
	if summary["suppressed"] != float64(1) {
		t.Fatalf("expected summary.suppressed=1, got %v", summary["suppressed"])
	}
	if summary["excepted"] != float64(1) {
		t.Fatalf("expected summary.excepted=1, got %v", summary["excepted"])
	}
	invalid, ok := report["invalidExceptions"].([]any)
	if !ok {
		t.Fatal("expected invalidExceptions array")
	}
	if len(invalid) != 2 {
		t.Fatalf("expected 2 invalidExceptions entries, got %d", len(invalid))
	}
}

func TestRunAuditFailsWhenPolicyPathMissing(t *testing.T) {
	tmp := t.TempDir()
	snapshotPath := filepath.Join(tmp, "posture.json")
	missingPolicy := filepath.Join(tmp, "missing-policy.yaml")
	outDir := filepath.Join(tmp, "out")

	posture := map[string]any{
		"schemaVersion": "0.2.0",
		"generatedAt":   "2026-01-01T00:00:00Z",
		"tool": map[string]any{
			"name":    "cryptodiff",
			"version": "0.2.0-dev",
		},
		"source":   map[string]any{"repoPath": tmp},
		"findings": []map[string]any{},
	}
	writeJSONFixture(t, snapshotPath, posture)

	exit := Run([]string{
		"audit",
		"--snapshot", snapshotPath,
		"--policy", missingPolicy,
		"--out-dir", outDir,
	})
	if exit != 2 {
		t.Fatalf("expected audit to fail with exit=2 for missing policy, got exit=%d", exit)
	}
}

func TestRunAuditFailsWhenExplicitConfigPathMissing(t *testing.T) {
	tmp := t.TempDir()
	snapshotPath := filepath.Join(tmp, "posture.json")
	policyPath := filepath.Join(tmp, "policy.yaml")
	missingConfig := filepath.Join(tmp, "missing-config.yaml")
	outDir := filepath.Join(tmp, "out")

	posture := map[string]any{
		"schemaVersion": "0.2.0",
		"generatedAt":   "2026-01-01T00:00:00Z",
		"tool": map[string]any{
			"name":    "cryptodiff",
			"version": "0.2.0-dev",
		},
		"source":   map[string]any{"repoPath": tmp},
		"findings": []map[string]any{},
	}
	writeJSONFixture(t, snapshotPath, posture)
	if err := os.WriteFile(policyPath, []byte("version: 0.2\nrules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := Run([]string{
		"audit",
		"--snapshot", snapshotPath,
		"--policy", policyPath,
		"--config", missingConfig,
		"--out-dir", outDir,
	})
	if exit != 2 {
		t.Fatalf("expected audit to fail with explicit missing config, got exit=%d", exit)
	}
}

func TestRunAuditGateFailsOnThresholdWhenPolicyDoesNotMatch(t *testing.T) {
	tmp := t.TempDir()
	snapshotPath := filepath.Join(tmp, "posture.json")
	policyPath := filepath.Join(tmp, "policy.yaml")
	outDir := filepath.Join(tmp, "out")

	posture := map[string]any{
		"schemaVersion": "0.2.0",
		"generatedAt":   "2026-01-01T00:00:00Z",
		"tool": map[string]any{
			"name":    "cryptodiff",
			"version": "0.2.0-dev",
		},
		"source": map[string]any{"repoPath": tmp},
		"findings": []map[string]any{
			{
				"id":          "f-cert",
				"ruleId":      "CRYPTO.CERT.VERIFY_DISABLED",
				"severity":    "critical",
				"category":    "pki",
				"confidence":  "high",
				"subject":     "Certificate verification appears disabled",
				"fingerprint": "fp-cert",
				"attributes": map[string]any{
					"attribute":     "verify",
					"detectedValue": "insecureskipverify: true",
				},
				"evidence": []map[string]any{{"path": "app.yaml", "line": 1}},
			},
		},
	}
	writeJSONFixture(t, snapshotPath, posture)

	// Intentionally provide a non-matching policy rule to ensure threshold-based
	// blocking still triggers in hybrid mode.
	policy := `version: 0.2
rules:
  - id: CRYPTO.TLS.MIN_VERSION
    level: high
    match:
      category: tls
      attribute: minVersion
      op: <
      value: "1.2"
`
	if err := os.WriteFile(policyPath, []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	exit := Run([]string{
		"audit",
		"--snapshot", snapshotPath,
		"--policy", policyPath,
		"--mode", "gate",
		"--fail-level", "high",
		"--out-dir", outDir,
	})
	if exit != 1 {
		t.Fatalf("expected gate failure from threshold match, got exit=%d", exit)
	}

	raw, err := os.ReadFile(filepath.Join(outDir, "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if got := report["result"]; got != "fail" {
		t.Fatalf("expected result=fail, got %v", got)
	}
	violations, ok := report["violations"].([]any)
	if !ok || len(violations) != 1 {
		t.Fatalf("expected exactly 1 violation, got %#v", report["violations"])
	}
	v0, _ := violations[0].(map[string]any)
	if got := v0["ruleId"]; got != "CRYPTO.CERT.VERIFY_DISABLED" {
		t.Fatalf("expected threshold violation ruleId to be finding rule id, got %v", got)
	}
}

func writeJSONFixture(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
