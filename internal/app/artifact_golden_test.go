package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestPostureJSONGolden(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Source: model.Source{
			RepoPath: "/repo",
			Commit:   "abc123",
			Ref:      "main",
		},
		Summary: model.PostureSummary{
			Findings:   1,
			Suppressed: 2,
		},
		Suppressions: model.SuppressionSummary{
			Inline:     1,
			IgnoreFile: 1,
		},
		Findings: []model.Finding{
			{
				ID:         "finding-123",
				RuleID:     "CRYPTO.ALG.DISALLOWED",
				Severity:   "critical",
				Category:   "algorithm",
				Confidence: "high",
				Subject:    "Disallowed algorithm reference: md5",
				Attributes: map[string]any{
					"attribute":     "name",
					"detectedValue": "md5",
				},
				Fingerprint: "fp-123",
				Evidence: []model.Evidence{
					{
						Path:        "app.yaml",
						Line:        10,
						SnippetHash: "deadbeef",
					},
				},
			},
		},
	}
	assertJSONGolden(t, "posture.json.golden", p)
}

func TestDiffJSONGolden(t *testing.T) {
	d := model.DiffReport{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		BaseSource: model.Source{
			RepoPath: "/repo",
			Commit:   "base123",
			Ref:      "main",
		},
		HeadSource: model.Source{
			RepoPath: "/repo",
			Commit:   "head456",
			Ref:      "feature",
		},
		Summary: model.DiffSummary{
			AddedCount:     1,
			RemovedCount:   0,
			ChangedCount:   1,
			UnchangedCount: 0,
			AddedBySeverity: map[string]int{
				"critical": 1,
			},
			ChangedByCategory: map[string]int{
				"tls": 1,
			},
		},
		Added: []model.Finding{
			{
				ID:          "finding-add",
				RuleID:      "CRYPTO.CERT.VERIFY_DISABLED",
				Severity:    "critical",
				Category:    "pki",
				Confidence:  "high",
				Subject:     "Certificate verification appears disabled",
				Fingerprint: "fp-add",
				Evidence:    []model.Evidence{{Path: "app.yaml", Line: 22}},
			},
		},
		Changed: []model.ChangedFinding{
			{
				Before: model.Finding{
					ID:          "finding-change",
					RuleID:      "CRYPTO.TLS.MIN_VERSION",
					Severity:    "high",
					Category:    "tls",
					Confidence:  "high",
					Subject:     "Minimum TLS version set to 1.0",
					Fingerprint: "fp-change",
					Evidence:    []model.Evidence{{Path: "tls.yaml", Line: 8}},
				},
				After: model.Finding{
					ID:          "finding-change",
					RuleID:      "CRYPTO.TLS.MIN_VERSION",
					Severity:    "high",
					Category:    "tls",
					Confidence:  "high",
					Subject:     "Minimum TLS version set to 1.1",
					Fingerprint: "fp-change",
					Evidence:    []model.Evidence{{Path: "tls.yaml", Line: 8}},
				},
				ChangedFields: []string{"subject"},
			},
		},
		Removed:   []model.Finding{},
		Unchanged: []model.Finding{},
	}
	assertJSONGolden(t, "diff.json.golden", d)
}

func TestAuditJSONGolden(t *testing.T) {
	a := model.AuditReport{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Mode:          "gate",
		FailLevel:     "high",
		PolicyVersion: "0.1",
		Result:        "fail",
		Summary: model.AuditSummary{
			EvaluatedFindings: 2,
			Violations:        1,
			Suppressed:        1,
			Excepted:          0,
		},
		Violations: []model.AuditViolation{
			{
				RuleID:        "CRYPTO.ALG.DISALLOWED",
				Level:         "critical",
				Fingerprint:   "fp-1",
				Subject:       "Disallowed algorithm reference: md5",
				Category:      "algorithm",
				DetectedValue: "md5",
			},
		},
		InvalidExceptions: []model.InvalidException{
			{
				ID:      "ex-1",
				RuleID:  "CRYPTO.ALG.DISALLOWED",
				Status:  "invalid",
				Message: "missing expiresAt",
			},
		},
	}
	assertJSONGolden(t, "audit.json.golden", a)
}

func assertJSONGolden(t *testing.T, goldenName string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", goldenName)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", goldenName, string(got), string(want))
	}
}
