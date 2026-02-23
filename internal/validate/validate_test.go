package validate

import (
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestPostureValidation(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		Summary: model.PostureSummary{
			Findings:   1,
			Suppressed: 0,
		},
		Suppressions: model.SuppressionSummary{},
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Findings: []model.Finding{
			{
				ID:          "finding-1",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Confidence:  "high",
				Subject:     "Disallowed algorithm reference: md5",
				Fingerprint: "fp1",
				Evidence:    []model.Evidence{{Path: "a.yaml"}},
			},
		},
	}
	if err := Posture(p); err != nil {
		t.Fatalf("expected posture to validate, got error: %v", err)
	}
}

func TestDiffSummaryMismatchFails(t *testing.T) {
	d := model.DiffReport{
		SchemaVersion: "0.2.0",
		Summary: model.DiffSummary{
			AddedCount: 99,
		},
	}
	if err := Diff(d); err == nil {
		t.Fatal("expected diff validation to fail on summary mismatch")
	}
}

func TestAuditSummaryMismatchFails(t *testing.T) {
	a := model.AuditReport{
		SchemaVersion: "0.2.0",
		Mode:          "gate",
		FailLevel:     "high",
		Result:        "fail",
		Summary: model.AuditSummary{
			Violations: 2,
		},
		Violations: []model.AuditViolation{
			{RuleID: "A", Fingerprint: "fp1"},
		},
	}
	if err := Audit(a); err == nil {
		t.Fatal("expected audit validation to fail on summary mismatch")
	}
}

func TestPostureScanErrorSummaryMismatchFails(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		Summary: model.PostureSummary{
			Findings:   0,
			Suppressed: 0,
			ScanErrors: 2,
		},
		Suppressions: model.SuppressionSummary{},
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Findings: []model.Finding{},
		ScanErrors: []model.ScanError{
			{Path: "a.yaml", Stage: "scan_file", Message: "bad file"},
		},
	}
	if err := Posture(p); err == nil {
		t.Fatal("expected posture validation to fail on scanErrors summary mismatch")
	}
}
