package baseline

import (
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestBuildFromFindingsDeduplicates(t *testing.T) {
	in := []model.Finding{
		{Fingerprint: "fp1", RuleID: "R1", Subject: "s1"},
		{Fingerprint: "fp1", RuleID: "R1", Subject: "s1"},
		{Fingerprint: "fp2", RuleID: "R2", Subject: "s2"},
	}
	b := BuildFromFindings(in)
	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}
}

func TestApplyToAuditReportFiltersKnownFingerprints(t *testing.T) {
	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 3,
			Violations:        2,
		},
		Violations: []model.AuditViolation{
			{Fingerprint: "known", RuleID: "A"},
			{Fingerprint: "new", RuleID: "B"},
		},
	}
	b := model.Baseline{
		Entries: []model.BaselineEntry{
			{Fingerprint: "known"},
		},
	}

	updated := ApplyToAuditReport(report, b)
	if len(updated.Violations) != 1 {
		t.Fatalf("expected 1 remaining violation, got %d", len(updated.Violations))
	}
	if updated.Violations[0].Fingerprint != "new" {
		t.Fatalf("expected remaining violation to be 'new', got %q", updated.Violations[0].Fingerprint)
	}
	if updated.Result != "fail" {
		t.Fatalf("expected gate mode to still fail with remaining violation, got %s", updated.Result)
	}
}
