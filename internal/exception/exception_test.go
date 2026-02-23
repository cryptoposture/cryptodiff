package exception

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestApplyFiltersMatchingRuleIDAndFingerprint(t *testing.T) {
	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 3,
			Violations:        2,
		},
		Violations: []model.AuditViolation{
			{RuleID: "CRYPTO.ALG.DISALLOWED", Fingerprint: "fp1"},
			{RuleID: "CRYPTO.TLS.MIN_VERSION", Fingerprint: "fp2"},
		},
	}
	ex := model.ExceptionsFile{
		Entries: []model.ExceptionEntry{
			{RuleID: "CRYPTO.ALG.DISALLOWED", ExpiresAt: "2099-01-01T00:00:00Z"},
		},
	}
	got := Apply(report, ex, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 1 {
		t.Fatalf("expected 1 remaining violation, got %d", len(got.Violations))
	}
	if got.Violations[0].Fingerprint != "fp2" {
		t.Fatalf("expected fp2 to remain, got %s", got.Violations[0].Fingerprint)
	}
	if got.Result != "fail" {
		t.Fatalf("expected gate result fail with remaining violations, got %s", got.Result)
	}
}

func TestApplyDoesNotFilterExpiredExceptions(t *testing.T) {
	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 1,
			Violations:        1,
		},
		Violations: []model.AuditViolation{
			{RuleID: "CRYPTO.ALG.DISALLOWED", Fingerprint: "fp1"},
		},
	}
	ex := model.ExceptionsFile{
		Entries: []model.ExceptionEntry{
			{Fingerprint: "fp1", ExpiresAt: "2020-01-01T00:00:00Z"},
		},
	}
	got := Apply(report, ex, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 1 {
		t.Fatalf("expected expired exception to be ignored, got %d violations", len(got.Violations))
	}
}

func TestApplyWithStatsSurfacesInvalidAndExpiredExceptions(t *testing.T) {
	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 2,
			Violations:        2,
		},
		Violations: []model.AuditViolation{
			{RuleID: "R1", Fingerprint: "fp1"},
			{RuleID: "R2", Fingerprint: "fp2"},
		},
	}
	ex := model.ExceptionsFile{
		Entries: []model.ExceptionEntry{
			{Fingerprint: "fp1", ExpiresAt: "2099-01-01T00:00:00Z"}, // valid and applied
			{RuleID: "R2", ExpiresAt: "bad-date"},                   // invalid
			{RuleID: "R3", ExpiresAt: "2020-01-01T00:00:00Z"},       // expired
			{Owner: "nobody"}, // invalid selector
		},
	}
	got, stats := ApplyWithStats(report, ex, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 1 {
		t.Fatalf("expected one violation left after applying valid exception, got %d", len(got.Violations))
	}
	if stats.ExceptedCount != 1 {
		t.Fatalf("expected exceptedCount=1, got %d", stats.ExceptedCount)
	}
	if len(stats.InvalidExceptions) != 3 {
		t.Fatalf("expected 3 invalid/expired exception entries, got %d", len(stats.InvalidExceptions))
	}
}

func TestLoadRejectsUnknownExceptionKey(t *testing.T) {
	tmp := t.TempDir()
	exPath := filepath.Join(tmp, "exceptions.yaml")
	content := `entries:
  - ruleId: CRYPTO.ALG.DISALLOWED
    expires_at: 2099-01-01T00:00:00Z
`
	if err := os.WriteFile(exPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(exPath)
	if err == nil {
		t.Fatal("expected parse error for unknown exception key")
	}
	if !strings.Contains(err.Error(), `unknown exception key "expires_at"`) {
		t.Fatalf("expected unknown key parse error, got %v", err)
	}
}

func TestLoadRejectsMalformedExceptionsYAMLLine(t *testing.T) {
	tmp := t.TempDir()
	exPath := filepath.Join(tmp, "exceptions.yaml")
	content := `entries:
  - ruleId CRYPTO.ALG.DISALLOWED
`
	if err := os.WriteFile(exPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(exPath)
	if err == nil {
		t.Fatal("expected parse error for malformed YAML line")
	}
	if !strings.Contains(err.Error(), "invalid YAML line") {
		t.Fatalf("expected invalid YAML line parse error, got %v", err)
	}
}

func TestLoadNormalizesMixedCaseFingerprintFromYAML(t *testing.T) {
	tmp := t.TempDir()
	exPath := filepath.Join(tmp, "exceptions.yaml")
	content := `entries:
  - fingerprint: ABCDEF1234
    expiresAt: 2099-01-01T00:00:00Z
`
	if err := os.WriteFile(exPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := Load(exPath)
	if err != nil {
		t.Fatalf("load exceptions: %v", err)
	}
	if len(ef.Entries) != 1 {
		t.Fatalf("expected 1 exception entry, got %d", len(ef.Entries))
	}
	if ef.Entries[0].Fingerprint != "abcdef1234" {
		t.Fatalf("expected normalized lowercase fingerprint, got %q", ef.Entries[0].Fingerprint)
	}

	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 1,
			Violations:        1,
		},
		Violations: []model.AuditViolation{
			{RuleID: "CRYPTO.ALG.DISALLOWED", Fingerprint: "abcdef1234"},
		},
	}
	got := Apply(report, ef, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 0 {
		t.Fatalf("expected mixed-case fingerprint exception to apply, got %d violations", len(got.Violations))
	}
}

func TestLoadNormalizesMixedCaseRuleIDFromJSON(t *testing.T) {
	tmp := t.TempDir()
	exPath := filepath.Join(tmp, "exceptions.json")
	content := `{
  "entries": [
    {
      "ruleId": "crypto.alg.disallowed",
      "expiresAt": "2099-01-01T00:00:00Z"
    }
  ]
}`
	if err := os.WriteFile(exPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ef, err := Load(exPath)
	if err != nil {
		t.Fatalf("load exceptions: %v", err)
	}
	if len(ef.Entries) != 1 {
		t.Fatalf("expected 1 exception entry, got %d", len(ef.Entries))
	}
	if ef.Entries[0].RuleID != "CRYPTO.ALG.DISALLOWED" {
		t.Fatalf("expected normalized uppercase ruleId, got %q", ef.Entries[0].RuleID)
	}

	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 1,
			Violations:        1,
		},
		Violations: []model.AuditViolation{
			{RuleID: "CRYPTO.ALG.DISALLOWED", Fingerprint: "fp1"},
		},
	}
	got := Apply(report, ef, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 0 {
		t.Fatalf("expected mixed-case ruleId exception to apply, got %d violations", len(got.Violations))
	}
}

func TestApplyRequiresBothSelectorsWhenExceptionProvidesBoth(t *testing.T) {
	report := model.AuditReport{
		Mode: "gate",
		Summary: model.AuditSummary{
			EvaluatedFindings: 2,
			Violations:        2,
		},
		Violations: []model.AuditViolation{
			{RuleID: "R1", Fingerprint: "fp1"},
			{RuleID: "R1", Fingerprint: "fp2"},
		},
	}
	ex := model.ExceptionsFile{
		Entries: []model.ExceptionEntry{
			{RuleID: "R1", Fingerprint: "fp1", ExpiresAt: "2099-01-01T00:00:00Z"},
		},
	}

	got := Apply(report, ex, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(got.Violations) != 1 {
		t.Fatalf("expected one remaining violation with AND semantics, got %d", len(got.Violations))
	}
	if got.Violations[0].Fingerprint != "fp2" {
		t.Fatalf("expected fp2 to remain, got %s", got.Violations[0].Fingerprint)
	}
}
