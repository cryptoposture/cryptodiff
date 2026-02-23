package policy

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/model"
	"github.com/cryptoposture/cryptodiff/internal/validate"
)

func Default() model.Policy {
	return model.Policy{
		Version: "0.2",
		Rules: []model.PolicyRule{
			{
				ID:    "CRYPTO.TLS.MIN_VERSION",
				Level: "high",
				Match: model.PolicyRuleMatch{
					Category:  "tls",
					Attribute: "minVersion",
					Op:        "<",
					Value:     "1.2",
				},
			},
			{
				ID:    "CRYPTO.ALG.DISALLOWED",
				Level: "critical",
				Match: model.PolicyRuleMatch{
					Category:  "algorithm",
					Attribute: "name",
					Op:        "in",
					Values:    []string{"md5", "sha1", "des", "3des", "rc4"},
				},
			},
		},
	}
}

func Load(path string) (model.Policy, error) {
	p := Default()
	if strings.TrimSpace(path) == "" {
		return p, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return model.Policy{}, err
	}

	parsed, err := parseLightweightPolicyYAML(string(b))
	if err != nil {
		return model.Policy{}, err
	}
	if err := validate.ArtifactAgainstEmbeddedSchema("policy.schema.json", parsed); err != nil {
		return model.Policy{}, fmt.Errorf("policy schema validation failed: %w", err)
	}
	if err := validatePolicySemantics(parsed); err != nil {
		return model.Policy{}, err
	}
	if parsed.Version != "" {
		p.Version = parsed.Version
	}
	if len(parsed.Rules) > 0 {
		p.Rules = parsed.Rules
	}
	return p, nil
}

// parseLightweightPolicyYAML parses a minimal subset of YAML sufficient for:
// version + rules list with id/level and a match object containing category/attribute/op/value.
func parseLightweightPolicyYAML(input string) (model.Policy, error) {
	p := lightweightPolicyParser{}
	sc := bufio.NewScanner(strings.NewReader(input))
	for sc.Scan() {
		p.lineNo++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if isIgnoredYAMLLine(trim) {
			continue
		}
		if err := p.parseLine(line); err != nil {
			return model.Policy{}, err
		}
	}
	if err := sc.Err(); err != nil {
		return model.Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if err := p.flushRule(); err != nil {
		return model.Policy{}, err
	}
	return p.out, nil
}

type lightweightPolicyParser struct {
	out     model.Policy
	current *model.PolicyRule
	inRules bool
	inMatch bool
	inValues bool
	valuesIndent int
	lineNo   int
}

func (p *lightweightPolicyParser) parseLine(line string) error {
	trim := strings.TrimSpace(line)
	indent := leadingWhitespaceCount(line)

	if indent == 0 && p.current != nil {
		if err := p.flushRule(); err != nil {
			return err
		}
		p.inMatch = false
		p.inValues = false
		p.valuesIndent = 0
	}

	if p.inValues {
		if indent > p.valuesIndent && strings.HasPrefix(trim, "- ") {
			item := strings.ToLower(cleanValue(strings.TrimSpace(strings.TrimPrefix(trim, "- "))))
			if item == "" {
				return p.lineErr("match.values list item cannot be empty")
			}
			p.current.Match.Values = append(p.current.Match.Values, item)
			p.current.Match.Value = nil
			return nil
		}
		p.inValues = false
		p.valuesIndent = 0
	}

	if strings.HasPrefix(trim, "- ") {
		if !p.inRules {
			return p.lineErr("rule entry found before rules section")
		}
		return p.startRule(strings.TrimSpace(strings.TrimPrefix(trim, "- ")))
	}

	key, val, ok := parseKV(trim)
	if !ok {
		return p.lineErr("invalid YAML line")
	}

	if p.current == nil {
		switch key {
		case "version":
			p.out.Version = val
		case "rules":
			p.inRules = true
			p.inMatch = false
		default:
			return p.lineErr(fmt.Sprintf("unknown top-level key %q", key))
		}
		return nil
	}
	if p.inMatch && key == "values" && val == "" {
		p.valuesIndent = indent
	}
	return p.parseRuleField(key, val)
}

func (p *lightweightPolicyParser) startRule(line string) error {
	if err := p.flushRule(); err != nil {
		return err
	}
	p.current = &model.PolicyRule{}
	p.inMatch = false
	p.inValues = false
	p.valuesIndent = 0
	if key, val, ok := parseKV(line); ok {
		return p.assignRuleField(key, val)
	}
	return nil
}

func (p *lightweightPolicyParser) parseRuleField(key, val string) error {
	if key == "match" {
		if val != "" {
			return p.lineErr(`"match" must be an object`)
		}
		p.inMatch = true
		p.inValues = false
		p.valuesIndent = 0
		return nil
	}
	if p.inMatch {
		return p.assignMatchField(key, val)
	}
	return p.assignRuleField(key, val)
}

func (p *lightweightPolicyParser) assignRuleField(key, val string) error {
	switch key {
	case "id":
		p.current.ID = normalizeRuleID(val)
	case "level":
		p.current.Level = strings.ToLower(val)
	case "match":
		if val != "" {
			return p.lineErr(`"match" must be an object`)
		}
		p.inMatch = true
	default:
		return p.lineErr(fmt.Sprintf("unknown rule key %q", key))
	}
	return nil
}

func normalizeRuleID(v string) string {
	return strings.ToUpper(strings.TrimSpace(v))
}

func (p *lightweightPolicyParser) assignMatchField(key, val string) error {
	switch key {
	case "category":
		p.current.Match.Category = val
	case "attribute":
		p.current.Match.Attribute = val
	case "op":
		p.current.Match.Op = val
	case "value":
		if list := parseInlineArray(val); len(list) > 0 {
			p.current.Match.Values = list
			p.current.Match.Value = nil
			return nil
		}
		p.current.Match.Value = val
		p.inValues = false
		p.valuesIndent = 0
	case "values":
		if list := parseInlineArray(val); len(list) > 0 {
			p.current.Match.Values = list
			p.current.Match.Value = nil
			p.inValues = false
			p.valuesIndent = 0
			return nil
		}
		if val != "" {
			return p.lineErr(`"match.values" must be an array`)
		}
		p.current.Match.Values = nil
		p.current.Match.Value = nil
		p.inValues = true
	default:
		return p.lineErr(fmt.Sprintf("unknown match key %q", key))
	}
	return nil
}

func (p *lightweightPolicyParser) flushRule() error {
	if p.current == nil {
		return nil
	}
	if strings.TrimSpace(p.current.ID) == "" {
		p.current = nil
		return p.lineErr(`rule is missing required field "id"`)
	}
	p.out.Rules = append(p.out.Rules, *p.current)
	p.current = nil
	return nil
}

func parseKV(s string) (string, string, bool) {
	if !strings.Contains(s, ":") {
		return "", "", false
	}
	key := strings.TrimSpace(beforeColon(s))
	if key == "" {
		return "", "", false
	}
	return key, cleanValue(afterColon(s)), true
}

func isIgnoredYAMLLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

func parseInlineArray(v string) []string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(v, "["), "]"))
	if body == "" {
		return nil
	}
	parts := strings.Split(body, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.ToLower(strings.TrimSpace(strings.Trim(p, `"'`)))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	return v
}

func (p *lightweightPolicyParser) lineErr(msg string) error {
	return fmt.Errorf("policy parse error at line %d: %s", p.lineNo, msg)
}

func beforeColon(s string) string {
	parts := strings.SplitN(s, ":", 2)
	return parts[0]
}

func afterColon(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func ParseTLSVersion(v string) float64 {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "tlsv")
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0
	}
	return n
}

func validatePolicySemantics(p model.Policy) error {
	for i, r := range p.Rules {
		if err := validatePolicyRuleSemantics(i, r); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyRuleSemantics(index int, r model.PolicyRule) error {
	ruleRef := policyRuleRef(index, r)
	if err := validatePolicyRuleLevel(ruleRef, r); err != nil {
		return err
	}
	op := strings.ToLower(strings.TrimSpace(r.Match.Op))
	if op == "" {
		return nil
	}
	if !isAllowedOp(op) {
		return fmt.Errorf("%s has invalid match.op %q", ruleRef, r.Match.Op)
	}
	value, values := policyMatchValues(r.Match)
	if op == "in" || op == "not_in" {
		return validateSetOperatorMatch(ruleRef, op, value, values)
	}
	return validateScalarOperatorMatch(ruleRef, op, value, values)
}

func policyRuleRef(index int, r model.PolicyRule) string {
	ruleRef := fmt.Sprintf("rule[%d]", index)
	if id := strings.TrimSpace(r.ID); id != "" {
		ruleRef = fmt.Sprintf("rule[%d] (%s)", index, id)
	}
	return ruleRef
}

func validatePolicyRuleLevel(ruleRef string, r model.PolicyRule) error {
	level := strings.ToLower(strings.TrimSpace(r.Level))
	if isAllowedLevel(level) {
		return nil
	}
	return fmt.Errorf("%s has invalid level %q", ruleRef, r.Level)
}

func policyMatchValues(m model.PolicyRuleMatch) (string, []string) {
	values := normalizedValues(m.Values)
	if m.Value == nil {
		return "", values
	}
	value := strings.TrimSpace(fmt.Sprintf("%v", m.Value))
	return value, values
}

func validateSetOperatorMatch(ruleRef, op, value string, values []string) error {
	if value != "" {
		return fmt.Errorf("%s uses op=%q and must not set match.value", ruleRef, op)
	}
	if len(values) == 0 {
		return fmt.Errorf("%s uses op=%q but has no match.values", ruleRef, op)
	}
	return nil
}

func validateScalarOperatorMatch(ruleRef, op, value string, values []string) error {
	if len(values) > 0 {
		return fmt.Errorf("%s uses op=%q and must not set match.values", ruleRef, op)
	}
	if value == "" {
		return fmt.Errorf("%s uses op=%q but has empty match.value", ruleRef, op)
	}
	return nil
}

func normalizedValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		item := strings.TrimSpace(v)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func isAllowedLevel(level string) bool {
	switch level {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func isAllowedOp(op string) bool {
	switch op {
	case "=", "==", "eq", "!=", "neq", "<", "<=", ">", ">=", "in", "not_in":
		return true
	default:
		return false
	}
}

func leadingWhitespaceCount(s string) int {
	count := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			count++
			continue
		}
		break
	}
	return count
}
