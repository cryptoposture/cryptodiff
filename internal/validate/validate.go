package validate

import (
	"fmt"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func Posture(p model.Posture) error {
	if strings.TrimSpace(p.SchemaVersion) == "" {
		return fmt.Errorf("posture.schemaVersion is required")
	}
	if strings.TrimSpace(p.Tool.Name) == "" {
		return fmt.Errorf("posture.tool.name is required")
	}
	if strings.TrimSpace(p.Tool.Version) == "" {
		return fmt.Errorf("posture.tool.version is required")
	}
	if p.Summary.Findings != len(p.Findings) {
		return fmt.Errorf("posture.summary.findings must match findings length")
	}
	if p.Summary.Suppressed < 0 {
		return fmt.Errorf("posture.summary.suppressed must be >= 0")
	}
	if p.Summary.ScanErrors < 0 {
		return fmt.Errorf("posture.summary.scanErrors must be >= 0")
	}
	if p.Suppressions.Inline < 0 || p.Suppressions.IgnoreFile < 0 || p.Suppressions.ConfigPath < 0 ||
		p.Suppressions.ConfigRule < 0 || p.Suppressions.ConfigCategory < 0 {
		return fmt.Errorf("posture suppressions must be >= 0")
	}
	suppressionTotal := p.Suppressions.Inline + p.Suppressions.IgnoreFile + p.Suppressions.ConfigPath +
		p.Suppressions.ConfigRule + p.Suppressions.ConfigCategory
	if p.Summary.Suppressed != suppressionTotal {
		return fmt.Errorf("posture.summary.suppressed must equal suppressions breakdown")
	}
	if p.Summary.ScanErrors != len(p.ScanErrors) {
		return fmt.Errorf("posture.summary.scanErrors must match scanErrors length")
	}
	for i, scanErr := range p.ScanErrors {
		if strings.TrimSpace(scanErr.Stage) == "" {
			return fmt.Errorf("posture.scanErrors[%d].stage is required", i)
		}
		if strings.TrimSpace(scanErr.Message) == "" {
			return fmt.Errorf("posture.scanErrors[%d].message is required", i)
		}
	}
	for i, f := range p.Findings {
		if err := validateFinding(f); err != nil {
			return fmt.Errorf("posture.findings[%d]: %w", i, err)
		}
	}
	return nil
}

func Diff(d model.DiffReport) error {
	if strings.TrimSpace(d.SchemaVersion) == "" {
		return fmt.Errorf("diff.schemaVersion is required")
	}
	total := len(d.Added) + len(d.Removed) + len(d.Changed) + len(d.Unchanged)
	sum := d.Summary.AddedCount + d.Summary.RemovedCount + d.Summary.ChangedCount + d.Summary.UnchangedCount
	if total != sum {
		return fmt.Errorf("diff summary mismatch: summary=%d actual=%d", sum, total)
	}
	if err := validateFindingSlice("diff.added", d.Added); err != nil {
		return err
	}
	if err := validateFindingSlice("diff.removed", d.Removed); err != nil {
		return err
	}
	if err := validateChangedFindings(d.Changed); err != nil {
		return err
	}
	if err := validateFindingSlice("diff.unchanged", d.Unchanged); err != nil {
		return err
	}
	return nil
}

func validateFindingSlice(prefix string, findings []model.Finding) error {
	for i, f := range findings {
		if err := validateFinding(f); err != nil {
			return fmt.Errorf("%s[%d]: %w", prefix, i, err)
		}
	}
	return nil
}

func validateChangedFindings(changed []model.ChangedFinding) error {
	for i, c := range changed {
		if err := validateFinding(c.Before); err != nil {
			return fmt.Errorf("diff.changed[%d].before: %w", i, err)
		}
		if err := validateFinding(c.After); err != nil {
			return fmt.Errorf("diff.changed[%d].after: %w", i, err)
		}
	}
	return nil
}

func Audit(a model.AuditReport) error {
	if strings.TrimSpace(a.SchemaVersion) == "" {
		return fmt.Errorf("audit.schemaVersion is required")
	}
	if strings.TrimSpace(a.Mode) == "" {
		return fmt.Errorf("audit.mode is required")
	}
	if strings.TrimSpace(a.FailLevel) == "" {
		return fmt.Errorf("audit.failLevel is required")
	}
	if strings.TrimSpace(a.Result) == "" {
		return fmt.Errorf("audit.result is required")
	}
	if a.Summary.Violations != len(a.Violations) {
		return fmt.Errorf("audit summary mismatch: summary=%d actual=%d", a.Summary.Violations, len(a.Violations))
	}
	if a.Summary.Suppressed < 0 {
		return fmt.Errorf("audit.summary.suppressed must be >= 0")
	}
	if a.Summary.Excepted < 0 {
		return fmt.Errorf("audit.summary.excepted must be >= 0")
	}
	if a.Summary.ThresholdMatched < 0 {
		return fmt.Errorf("audit.summary.thresholdMatched must be >= 0")
	}
	if a.Summary.PolicyMatched < 0 {
		return fmt.Errorf("audit.summary.policyMatched must be >= 0")
	}
	if a.Summary.UnmappedFindings < 0 {
		return fmt.Errorf("audit.summary.unmappedFindings must be >= 0")
	}
	for i, v := range a.Violations {
		if strings.TrimSpace(v.RuleID) == "" {
			return fmt.Errorf("audit.violations[%d].ruleId is required", i)
		}
		if strings.TrimSpace(v.Fingerprint) == "" {
			return fmt.Errorf("audit.violations[%d].fingerprint is required", i)
		}
	}
	for i, ex := range a.InvalidExceptions {
		if strings.TrimSpace(ex.Status) == "" {
			return fmt.Errorf("audit.invalidExceptions[%d].status is required", i)
		}
	}
	return nil
}

func validateFinding(f model.Finding) error {
	if strings.TrimSpace(f.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(f.RuleID) == "" {
		return fmt.Errorf("ruleId is required")
	}
	if strings.TrimSpace(f.Severity) == "" {
		return fmt.Errorf("severity is required")
	}
	if strings.TrimSpace(f.Category) == "" {
		return fmt.Errorf("category is required")
	}
	if strings.TrimSpace(f.Confidence) == "" {
		return fmt.Errorf("confidence is required")
	}
	if strings.TrimSpace(f.Subject) == "" {
		return fmt.Errorf("subject is required")
	}
	if strings.TrimSpace(f.Fingerprint) == "" {
		return fmt.Errorf("fingerprint is required")
	}
	if len(f.Evidence) == 0 {
		return fmt.Errorf("evidence is required")
	}
	return nil
}
