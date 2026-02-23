package baseline

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func Load(path string) (model.Baseline, error) {
	var b model.Baseline
	raw, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, err
	}
	return b, nil
}

func BuildFromFindings(findings []model.Finding) model.Baseline {
	byFP := map[string]model.BaselineEntry{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		if f.Fingerprint == "" {
			continue
		}
		byFP[f.Fingerprint] = model.BaselineEntry{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			Subject:     f.Subject,
			AddedAt:     now,
		}
	}
	return buildSortedBaseline(byFP)
}

func BuildFromViolations(violations []model.AuditViolation) model.Baseline {
	byFP := map[string]model.BaselineEntry{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, v := range violations {
		if v.Fingerprint == "" {
			continue
		}
		byFP[v.Fingerprint] = model.BaselineEntry{
			Fingerprint: v.Fingerprint,
			RuleID:      v.RuleID,
			Subject:     v.Subject,
			AddedAt:     now,
		}
	}
	return buildSortedBaseline(byFP)
}

func FilterViolations(violations []model.AuditViolation, b model.Baseline) []model.AuditViolation {
	known := map[string]struct{}{}
	for _, e := range b.Entries {
		if e.Fingerprint == "" {
			continue
		}
		known[e.Fingerprint] = struct{}{}
	}
	out := make([]model.AuditViolation, 0, len(violations))
	for _, v := range violations {
		if _, ok := known[v.Fingerprint]; ok {
			continue
		}
		out = append(out, v)
	}
	return out
}

func ApplyToAuditReport(report model.AuditReport, b model.Baseline) model.AuditReport {
	report.Violations = FilterViolations(report.Violations, b)
	report.Summary.Violations = len(report.Violations)
	if report.Mode == "gate" && len(report.Violations) > 0 {
		report.Result = "fail"
	} else {
		report.Result = "pass"
	}
	return report
}

func buildSortedBaseline(byFP map[string]model.BaselineEntry) model.Baseline {
	entries := make([]model.BaselineEntry, 0, len(byFP))
	for _, e := range byFP {
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
	return model.Baseline{
		SchemaVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Entries:       entries,
	}
}
