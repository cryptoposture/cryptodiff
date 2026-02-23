package exception

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

type ApplyStats struct {
	ExceptedCount     int
	InvalidExceptions []model.InvalidException
}

func Load(path string) (model.ExceptionsFile, error) {
	var ef model.ExceptionsFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return ef, err
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		if err := json.Unmarshal(raw, &ef); err != nil {
			return ef, err
		}
		normalizeExceptionsFile(&ef)
		return ef, nil
	}

	// Default to lightweight YAML parsing for .yaml/.yml and unknown extensions.
	ef, err = parseLightweightYAML(string(raw))
	if err != nil {
		return ef, err
	}
	normalizeExceptionsFile(&ef)
	return ef, nil
}

func Apply(report model.AuditReport, ef model.ExceptionsFile, now time.Time) model.AuditReport {
	applied, _ := ApplyWithStats(report, ef, now)
	return applied
}

func ApplyWithStats(report model.AuditReport, ef model.ExceptionsFile, now time.Time) (model.AuditReport, ApplyStats) {
	stats := ApplyStats{}
	if len(ef.Entries) == 0 || len(report.Violations) == 0 {
		stats.InvalidExceptions = invalidExceptionEntries(ef.Entries, now)
		return report, stats
	}
	stats.InvalidExceptions = invalidExceptionEntries(ef.Entries, now)

	out := make([]model.AuditViolation, 0, len(report.Violations))
	for _, v := range report.Violations {
		if isExcepted(v, ef.Entries, now) {
			stats.ExceptedCount++
			continue
		}
		out = append(out, v)
	}

	report.Violations = out
	report.Summary.Violations = len(out)
	if report.Mode == "gate" && len(out) > 0 {
		report.Result = "fail"
	} else {
		report.Result = "pass"
	}
	return report, stats
}

func isExcepted(v model.AuditViolation, entries []model.ExceptionEntry, now time.Time) bool {
	for _, e := range entries {
		status, _ := exceptionStatus(e, now)
		if status != "valid" {
			continue
		}
		if matchesExceptionSelector(e, v) {
			return true
		}
	}
	return false
}

func matchesExceptionSelector(e model.ExceptionEntry, v model.AuditViolation) bool {
	hasFP := strings.TrimSpace(e.Fingerprint) != ""
	hasRule := strings.TrimSpace(e.RuleID) != ""

	switch {
	case hasFP && hasRule:
		return e.Fingerprint == v.Fingerprint && e.RuleID == v.RuleID
	case hasFP:
		return e.Fingerprint == v.Fingerprint
	case hasRule:
		return e.RuleID == v.RuleID
	default:
		return false
	}
}

func isExpired(expiresAt string, now time.Time) bool {
	if strings.TrimSpace(expiresAt) == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAt))
	if err != nil {
		// Invalid date should not silently exempt findings.
		return true
	}
	return now.After(t)
}

func invalidExceptionEntries(entries []model.ExceptionEntry, now time.Time) []model.InvalidException {
	out := make([]model.InvalidException, 0)
	for _, e := range entries {
		status, msg := exceptionStatus(e, now)
		if status == "valid" {
			continue
		}
		out = append(out, model.InvalidException{
			ID:          e.ID,
			RuleID:      e.RuleID,
			Fingerprint: e.Fingerprint,
			Owner:       e.Owner,
			Reason:      e.Reason,
			ExpiresAt:   e.ExpiresAt,
			Status:      status,
			Message:     msg,
		})
	}
	return out
}

func exceptionStatus(e model.ExceptionEntry, now time.Time) (string, string) {
	if strings.TrimSpace(e.RuleID) == "" && strings.TrimSpace(e.Fingerprint) == "" {
		return "invalid", "exception must include ruleId or fingerprint selector"
	}
	if strings.TrimSpace(e.ExpiresAt) == "" {
		return "valid", ""
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.ExpiresAt))
	if err != nil {
		return "invalid", fmt.Sprintf("invalid expiresAt format: %v", err)
	}
	if now.After(t) {
		return "expired", "exception has expired"
	}
	return "valid", ""
}

// parseLightweightYAML supports:
// schemaVersion: "0.2.0" (optional)
// generatedAt: "2026-01-01T00:00:00Z" (optional)
// entries:
//   - id: ...
//     ruleId: ...
//     fingerprint: ...
//     owner: ...
//     reason: ...
//     expiresAt: 2027-01-01T00:00:00Z
func parseLightweightYAML(input string) (model.ExceptionsFile, error) {
	p := lightweightExceptionsParser{}
	sc := bufio.NewScanner(strings.NewReader(input))
	for sc.Scan() {
		p.lineNo++
		line := strings.TrimSpace(sc.Text())
		if isIgnoredYAMLLine(line) {
			continue
		}
		if err := p.parseLine(line); err != nil {
			return model.ExceptionsFile{}, err
		}
	}
	if err := sc.Err(); err != nil {
		return model.ExceptionsFile{}, fmt.Errorf("read exceptions: %w", err)
	}
	p.flush()
	return p.out, nil
}

func isIgnoredYAMLLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

type lightweightExceptionsParser struct {
	out       model.ExceptionsFile
	inEntries bool
	current   *model.ExceptionEntry
	lineNo    int
}

func (p *lightweightExceptionsParser) parseLine(line string) error {
	if line == "entries:" {
		p.inEntries = true
		return nil
	}
	if strings.HasSuffix(line, ":") && !strings.Contains(line, " ") {
		return p.lineErr("unknown top-level section %q", strings.TrimSuffix(line, ":"))
	}
	if strings.HasPrefix(line, "- ") {
		if !p.inEntries {
			return p.lineErr("entry found before entries section")
		}
		p.flush()
		p.current = &model.ExceptionEntry{}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if rest == "" {
			return nil
		}
		return p.assignIfKeyValue(p.current, rest)
	}
	if p.inEntries {
		if p.current == nil {
			return p.lineErr("entry field found before entry start")
		}
		return p.assignIfKeyValue(p.current, line)
	}
	return p.assignTopLevelField(line)
}

func (p *lightweightExceptionsParser) assignTopLevelField(line string) error {
	key, value, ok := keyValue(line)
	if !ok {
		return p.lineErr("invalid YAML line")
	}
	switch key {
	case "schemaVersion":
		p.out.SchemaVersion = value
	case "generatedAt":
		p.out.GeneratedAt = value
	default:
		return p.lineErr("unknown top-level key %q", key)
	}
	return nil
}

func (p *lightweightExceptionsParser) assignIfKeyValue(entry *model.ExceptionEntry, line string) error {
	key, val, ok := keyValue(line)
	if !ok {
		return p.lineErr("invalid YAML line")
	}
	if err := assignExceptionField(entry, key, val); err != nil {
		return p.lineErr("%v", err)
	}
	return nil
}

func (p *lightweightExceptionsParser) flush() {
	if p.current == nil {
		return
	}
	p.out.Entries = append(p.out.Entries, *p.current)
	p.current = nil
}

func (p *lightweightExceptionsParser) lineErr(format string, args ...any) error {
	return fmt.Errorf("exceptions parse error at line %d: %s", p.lineNo, fmt.Sprintf(format, args...))
}

func keyValue(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	if key == "" {
		return "", "", false
	}
	val := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	return key, val, true
}

func assignExceptionField(e *model.ExceptionEntry, key, value string) error {
	switch key {
	case "id":
		e.ID = value
	case "ruleId":
		e.RuleID = normalizeRuleIDSelector(value)
	case "fingerprint":
		e.Fingerprint = normalizeFingerprintSelector(value)
	case "owner":
		e.Owner = value
	case "reason":
		e.Reason = value
	case "expiresAt":
		e.ExpiresAt = value
	default:
		return fmt.Errorf("unknown exception key %q", key)
	}
	return nil
}

func normalizeExceptionsFile(ef *model.ExceptionsFile) {
	if ef == nil {
		return
	}
	for i := range ef.Entries {
		ef.Entries[i].RuleID = normalizeRuleIDSelector(ef.Entries[i].RuleID)
		ef.Entries[i].Fingerprint = normalizeFingerprintSelector(ef.Entries[i].Fingerprint)
	}
}

func normalizeRuleIDSelector(v string) string {
	return strings.ToUpper(strings.TrimSpace(v))
}

func normalizeFingerprintSelector(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
