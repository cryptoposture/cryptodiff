package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestCompareClassifiesFindings(t *testing.T) {
	base := model.Posture{
		Findings: []model.Finding{
			{
				Fingerprint: "fp-unchanged",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Subject:     "Disallowed algorithm reference: md5",
			},
			{
				Fingerprint: "fp-removed",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Subject:     "Disallowed algorithm reference: rc4",
			},
			{
				Fingerprint: "fp-changed",
				RuleID:      "CRYPTO.TLS.MIN_VERSION",
				Severity:    "high",
				Category:    "tls",
				Subject:     "Minimum TLS version set to 1.0",
			},
		},
	}

	head := model.Posture{
		Findings: []model.Finding{
			{
				Fingerprint: "fp-unchanged",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Subject:     "Disallowed algorithm reference: md5",
			},
			{
				Fingerprint: "fp-added",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Subject:     "Disallowed algorithm reference: sha1",
			},
			{
				Fingerprint: "fp-changed",
				RuleID:      "CRYPTO.TLS.MIN_VERSION",
				Severity:    "high",
				Category:    "tls",
				Subject:     "Minimum TLS version set to 1.1",
			},
		},
	}

	report := Compare(base, head)
	if report.Summary.AddedCount != 1 {
		t.Fatalf("expected 1 added finding, got %d", report.Summary.AddedCount)
	}
	if report.Summary.RemovedCount != 1 {
		t.Fatalf("expected 1 removed finding, got %d", report.Summary.RemovedCount)
	}
	if report.Summary.ChangedCount != 1 {
		t.Fatalf("expected 1 changed finding, got %d", report.Summary.ChangedCount)
	}
	if report.Summary.UnchangedCount != 1 {
		t.Fatalf("expected 1 unchanged finding, got %d", report.Summary.UnchangedCount)
	}
	if report.Summary.AddedBySeverity["critical"] != 1 {
		t.Fatalf("expected addedBySeverity.critical=1, got %d", report.Summary.AddedBySeverity["critical"])
	}
	if report.Summary.RemovedByCategory["algorithm"] != 1 {
		t.Fatalf("expected removedByCategory.algorithm=1, got %d", report.Summary.RemovedByCategory["algorithm"])
	}
	if report.Summary.ChangedByCategory["tls"] != 1 {
		t.Fatalf("expected changedByCategory.tls=1, got %d", report.Summary.ChangedByCategory["tls"])
	}
	if len(report.Changed) != 1 || len(report.Changed[0].ChangedFields) == 0 {
		t.Fatalf("expected changed finding to include changedFields metadata")
	}
}

func TestMarkdownGolden(t *testing.T) {
	report := model.DiffReport{
		Summary: model.DiffSummary{
			AddedCount: 1,
		},
		Added: []model.Finding{
			{
				RuleID:     "CRYPTO.ALG.DISALLOWED",
				Severity:   "critical",
				Confidence: "high",
				Subject:    "Disallowed algorithm reference: md5",
				Evidence:   []model.Evidence{{Path: "app.yaml"}},
			},
		},
	}
	got := Markdown(report)
	wantBytes, err := os.ReadFile(filepath.Join("testdata", "diff.md.golden"))
	if err != nil {
		t.Fatalf("failed to load golden file: %v", err)
	}
	want := string(wantBytes)
	if got != want {
		t.Fatalf("markdown output mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
