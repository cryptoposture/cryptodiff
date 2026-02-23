package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

type Options struct {
	Mode      string
	FailLevel string
}

func LoadDiff(path string) (model.DiffReport, error) {
	var d model.DiffReport
	b, err := os.ReadFile(path)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	return d, nil
}

func EvaluateSnapshot(findings []model.Finding, policy model.Policy, opts Options) model.AuditReport {
	violations := evaluateFindings(findings, policy, opts.FailLevel)
	return newReport(opts, policy.Version, len(findings), violations)
}

func EvaluateDiff(d model.DiffReport, policy model.Policy, opts Options) model.AuditReport {
	candidates := make([]model.Finding, 0, len(d.Added)+len(d.Changed))
	candidates = append(candidates, d.Added...)
	for _, ch := range d.Changed {
		candidates = append(candidates, ch.After)
	}
	violations := evaluateFindings(candidates, policy, opts.FailLevel)
	return newReport(opts, policy.Version, len(candidates), violations)
}

func evaluateFindings(findings []model.Finding, policy model.Policy, failLevel string) []model.AuditViolation {
	out := make([]model.AuditViolation, 0)
	defaultThreshold := normalizeLevel(failLevel)
	if len(policy.Rules) == 0 {
		return evaluateFindingsWithoutRules(findings, defaultThreshold)
	}
	for _, f := range findings {
		out = append(out, evaluateFindingAgainstRules(f, policy.Rules, defaultThreshold)...)
	}
	return out
}

func evaluateFindingsWithoutRules(findings []model.Finding, threshold string) []model.AuditViolation {
	out := make([]model.AuditViolation, 0)
	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(threshold) {
			out = append(out, newViolation(f.RuleID, f))
		}
	}
	return out
}

func evaluateFindingAgainstRules(f model.Finding, rules []model.PolicyRule, defaultThreshold string) []model.AuditViolation {
	out := make([]model.AuditViolation, 0)
	for _, r := range rules {
		if !ruleMatchesFinding(r, f) {
			continue
		}
		threshold := thresholdForRule(r, defaultThreshold)
		if severityRank(f.Severity) < severityRank(threshold) {
			continue
		}
		out = append(out, newViolation(ruleIDForViolation(r, f), f))
	}
	return out
}

func thresholdForRule(rule model.PolicyRule, defaultThreshold string) string {
	if strings.TrimSpace(rule.Level) == "" {
		return defaultThreshold
	}
	return normalizeLevel(rule.Level)
}

func ruleIDForViolation(rule model.PolicyRule, f model.Finding) string {
	ruleID := strings.TrimSpace(rule.ID)
	if ruleID == "" {
		return f.RuleID
	}
	return ruleID
}

func newViolation(ruleID string, f model.Finding) model.AuditViolation {
	return model.AuditViolation{
		RuleID:        ruleID,
		Level:         normalizeLevel(f.Severity),
		Fingerprint:   f.Fingerprint,
		Subject:       f.Subject,
		Category:      f.Category,
		DetectedValue: findingDetectedValue(f),
	}
}

func findingDetectedValue(f model.Finding) string {
	if f.Attributes == nil {
		return ""
	}
	v, ok := f.Attributes["detectedValue"]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func findingAttributeName(f model.Finding) string {
	if f.Attributes == nil {
		return ""
	}
	v, ok := f.Attributes["attribute"]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func ruleMatchesFinding(rule model.PolicyRule, f model.Finding) bool {
	m := rule.Match
	if strings.TrimSpace(m.Category) != "" &&
		!strings.EqualFold(strings.TrimSpace(f.Category), strings.TrimSpace(m.Category)) {
		return false
	}

	if strings.TrimSpace(m.Attribute) != "" &&
		!strings.EqualFold(findingAttributeName(f), strings.TrimSpace(m.Attribute)) {
		return false
	}

	op := strings.ToLower(strings.TrimSpace(m.Op))
	if op == "" {
		return true
	}

	detected := findingDetectedValue(f)
	if detected == "" {
		return false
	}
	values := ruleValues(m)
	if len(values) == 0 {
		return false
	}
	return compareOp(op, detected, values)
}

func ruleValues(m model.PolicyRuleMatch) []string {
	out := []string{}
	for _, v := range m.Values {
		clean := strings.TrimSpace(v)
		if clean != "" {
			out = append(out, clean)
		}
	}
	if len(out) > 0 {
		return out
	}
	if m.Value != nil {
		clean := strings.TrimSpace(fmt.Sprintf("%v", m.Value))
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func compareOp(op, detected string, values []string) bool {
	switch op {
	case "in":
		for _, v := range values {
			if strings.EqualFold(strings.TrimSpace(detected), strings.TrimSpace(v)) {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range values {
			if strings.EqualFold(strings.TrimSpace(detected), strings.TrimSpace(v)) {
				return false
			}
		}
		return true
	case "=", "==", "eq":
		return strings.EqualFold(strings.TrimSpace(detected), strings.TrimSpace(values[0]))
	case "!=", "neq":
		return !strings.EqualFold(strings.TrimSpace(detected), strings.TrimSpace(values[0]))
	case "<", "<=", ">", ">=":
		return compareOrdered(op, detected, values[0])
	}
	return false
}

func compareOrdered(op, detected, expected string) bool {
	d, dok := parseComparableValue(detected)
	e, eok := parseComparableValue(expected)
	if !dok || !eok {
		return false
	}
	switch op {
	case "<":
		return d < e
	case "<=":
		return d <= e
	case ">":
		return d > e
	case ">=":
		return d >= e
	default:
		return false
	}
}

func parseComparableValue(v string) (float64, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(s, "tlsv")
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func newReport(opts Options, policyVersion string, evaluated int, violations []model.AuditViolation) model.AuditReport {
	mode := normalizeMode(opts.Mode)
	failLevel := normalizeLevel(opts.FailLevel)

	result := "pass"
	if mode == "gate" && len(violations) > 0 {
		result = "fail"
	}

	return model.AuditReport{
		SchemaVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Mode:          mode,
		FailLevel:     failLevel,
		PolicyVersion: policyVersion,
		Result:        result,
		Summary: model.AuditSummary{
			EvaluatedFindings: evaluated,
			Violations:        len(violations),
		},
		Violations: violations,
	}
}

func normalizeMode(mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m != "gate" {
		return "report"
	}
	return "gate"
}

func normalizeLevel(level string) string {
	l := strings.ToLower(strings.TrimSpace(level))
	switch l {
	case "info", "low", "medium", "high", "critical":
		return l
	default:
		return "high"
	}
}

func severityRank(severity string) int {
	switch normalizeLevel(severity) {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 3
	}
}
