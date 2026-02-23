package audit

import (
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestEvaluateSnapshotGateModeFailsWhenViolationsExist(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "CRYPTO.ALG.DISALLOWED", Severity: "critical"},
		{RuleID: "CRYPTO.TLS.MIN_VERSION", Severity: "high"},
		{RuleID: "CRYPTO.TLS.MIN_VERSION", Severity: "low"},
	}
	report := EvaluateSnapshot(findings, model.Policy{}, Options{
		Mode:      "gate",
		FailLevel: "high",
	})
	if report.Result != "fail" {
		t.Fatalf("expected fail in gate mode with violations, got %s", report.Result)
	}
	if report.Summary.Violations != 2 {
		t.Fatalf("expected 2 violations, got %d", report.Summary.Violations)
	}
}

func TestEvaluateDiffUsesAddedAndChangedAfterOnly(t *testing.T) {
	diff := model.DiffReport{
		Added: []model.Finding{
			{RuleID: "A", Severity: "high"},
		},
		Removed: []model.Finding{
			{RuleID: "A", Severity: "critical"},
		},
		Changed: []model.ChangedFinding{
			{
				Before: model.Finding{RuleID: "A", Severity: "low"},
				After:  model.Finding{RuleID: "A", Severity: "critical"},
			},
		},
	}
	report := EvaluateDiff(diff, model.Policy{}, Options{
		Mode:      "report",
		FailLevel: "high",
	})
	if report.Summary.EvaluatedFindings != 2 {
		t.Fatalf("expected 2 evaluated findings, got %d", report.Summary.EvaluatedFindings)
	}
	if report.Summary.Violations != 2 {
		t.Fatalf("expected 2 violations, got %d", report.Summary.Violations)
	}
	if report.Result != "pass" {
		t.Fatalf("expected report mode to return pass, got %s", report.Result)
	}
}

func TestPolicyRuleFiltering(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "CRYPTO.ALG.DISALLOWED", Severity: "critical"},
		{RuleID: "CRYPTO.TLS.MIN_VERSION", Severity: "high"},
	}
	policy := model.Policy{
		Rules: []model.PolicyRule{
			{
				ID:    "CRYPTO.TLS.MIN_VERSION",
				Level: "critical",
				Match: model.PolicyRuleMatch{
					Category:  "tls",
					Attribute: "minVersion",
					Op:        "<",
					Value:     "1.2",
				},
			},
		},
	}
	report := EvaluateSnapshot(findings, policy, Options{
		Mode:      "gate",
		FailLevel: "high",
	})
	if report.Summary.Violations != 0 {
		t.Fatalf("expected no violations after policy filtering, got %d", report.Summary.Violations)
	}
}

func TestPolicyMatchCategoryAttributeAndOpValue(t *testing.T) {
	findings := []model.Finding{
		{
			RuleID:      "CRYPTO.TLS.MIN_VERSION",
			Severity:    "high",
			Category:    "tls",
			Fingerprint: "fp-tls-1",
			Subject:     "Minimum TLS version set to 1.0",
			Attributes: map[string]any{
				"attribute":     "minVersion",
				"detectedValue": "1.0",
			},
		},
	}
	policy := model.Policy{
		Rules: []model.PolicyRule{
			{
				ID:    "TLS_RULE",
				Level: "high",
				Match: model.PolicyRuleMatch{
					Category:  "tls",
					Attribute: "minVersion",
					Op:        "<",
					Value:     "1.2",
				},
			},
		},
	}
	report := EvaluateSnapshot(findings, policy, Options{Mode: "gate", FailLevel: "high"})
	if report.Summary.Violations != 1 {
		t.Fatalf("expected one matched violation, got %d", report.Summary.Violations)
	}
	if report.Violations[0].RuleID != "TLS_RULE" {
		t.Fatalf("expected violation to carry policy rule ID, got %s", report.Violations[0].RuleID)
	}
}

func TestPolicyMatchInOperator(t *testing.T) {
	findings := []model.Finding{
		{
			RuleID:      "CRYPTO.ALG.DISALLOWED",
			Severity:    "critical",
			Category:    "algorithm",
			Fingerprint: "fp-alg-1",
			Subject:     "Disallowed algorithm reference: md5",
			Attributes: map[string]any{
				"attribute":     "name",
				"detectedValue": "md5",
			},
		},
	}
	policy := model.Policy{
		Rules: []model.PolicyRule{
			{
				ID:    "ALG_RULE",
				Level: "critical",
				Match: model.PolicyRuleMatch{
					Category:  "algorithm",
					Attribute: "name",
					Op:        "in",
					Values:    []string{"sha1", "md5"},
				},
			},
		},
	}
	report := EvaluateSnapshot(findings, policy, Options{Mode: "gate", FailLevel: "high"})
	if report.Summary.Violations != 1 {
		t.Fatalf("expected in-operator match to produce violation, got %d", report.Summary.Violations)
	}
}
