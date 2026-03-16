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
	if report.Summary.ThresholdMatched != 2 {
		t.Fatalf("expected 2 thresholdMatched, got %d", report.Summary.ThresholdMatched)
	}
	if report.Summary.PolicyMatched != 0 {
		t.Fatalf("expected 0 policyMatched, got %d", report.Summary.PolicyMatched)
	}
	if report.Summary.UnmappedFindings != 3 {
		t.Fatalf("expected 3 unmappedFindings, got %d", report.Summary.UnmappedFindings)
	}
}

func TestEvaluateDiffUsesAddedAndChangedAfterOnly(t *testing.T) {
	diff := model.DiffReport{
		Added: []model.Finding{
			{RuleID: "A", Severity: "high", Fingerprint: "fp-added", Category: "tls", Subject: "added"},
		},
		Removed: []model.Finding{
			{RuleID: "A", Severity: "critical", Fingerprint: "fp-removed", Category: "tls", Subject: "removed"},
		},
		Changed: []model.ChangedFinding{
			{
				Before: model.Finding{RuleID: "A", Severity: "low", Fingerprint: "fp-changed", Category: "tls", Subject: "before"},
				After:  model.Finding{RuleID: "A", Severity: "critical", Fingerprint: "fp-changed", Category: "tls", Subject: "after"},
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
	if report.Summary.ThresholdMatched != 2 {
		t.Fatalf("expected 2 thresholdMatched, got %d", report.Summary.ThresholdMatched)
	}
	if report.Summary.PolicyMatched != 0 {
		t.Fatalf("expected 0 policyMatched, got %d", report.Summary.PolicyMatched)
	}
	if report.Summary.UnmappedFindings != 2 {
		t.Fatalf("expected 2 unmappedFindings, got %d", report.Summary.UnmappedFindings)
	}
	if report.Result != "pass" {
		t.Fatalf("expected report mode to return pass, got %s", report.Result)
	}
}

func TestPolicyRulesDoNotDisableSeverityThreshold(t *testing.T) {
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
	if report.Summary.Violations != 2 {
		t.Fatalf("expected threshold to still produce 2 violations, got %d", report.Summary.Violations)
	}
	if report.Summary.PolicyMatched != 0 {
		t.Fatalf("expected no policy matches, got %d", report.Summary.PolicyMatched)
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
		t.Fatalf("expected one merged violation, got %d", report.Summary.Violations)
	}
	if report.Summary.PolicyMatched != 1 {
		t.Fatalf("expected policyMatched=1, got %d", report.Summary.PolicyMatched)
	}
	if report.Summary.UnmappedFindings != 0 {
		t.Fatalf("expected unmappedFindings=0, got %d", report.Summary.UnmappedFindings)
	}
	if len(report.Violations) != 1 || report.Violations[0].RuleID != "TLS_RULE" {
		t.Fatalf("expected policy rule to override threshold rule id, got %#v", report.Violations)
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
	if report.Violations[0].RuleID != "ALG_RULE" {
		t.Fatalf("expected policy rule id ALG_RULE, got %s", report.Violations[0].RuleID)
	}
}

func TestThresholdOnlyFindingUsesFindingRuleID(t *testing.T) {
	findings := []model.Finding{
		{
			RuleID:      "CRYPTO.CERT.VERIFY_DISABLED",
			Severity:    "critical",
			Category:    "pki",
			Fingerprint: "fp-cert-1",
			Subject:     "Certificate verification appears disabled",
			Attributes: map[string]any{
				"attribute":     "verify",
				"detectedValue": "insecureskipverify: true",
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
		t.Fatalf("expected threshold-only violation, got %d", report.Summary.Violations)
	}
	if report.Violations[0].RuleID != "CRYPTO.CERT.VERIFY_DISABLED" {
		t.Fatalf("expected finding rule id for threshold-only violation, got %s", report.Violations[0].RuleID)
	}
	if report.Summary.PolicyMatched != 0 {
		t.Fatalf("expected policyMatched=0, got %d", report.Summary.PolicyMatched)
	}
	if report.Summary.UnmappedFindings != 1 {
		t.Fatalf("expected unmappedFindings=1, got %d", report.Summary.UnmappedFindings)
	}
}
