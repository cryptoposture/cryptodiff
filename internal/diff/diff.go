package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func LoadPosture(path string) (model.Posture, error) {
	var p model.Posture
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	return p, nil
}

func Compare(base, head model.Posture) model.DiffReport {
	baseByFP := map[string]model.Finding{}
	headByFP := map[string]model.Finding{}

	for _, f := range base.Findings {
		baseByFP[f.Fingerprint] = f
	}
	for _, f := range head.Findings {
		headByFP[f.Fingerprint] = f
	}

	allFP := make([]string, 0, len(baseByFP)+len(headByFP))
	seen := map[string]struct{}{}
	for fp := range baseByFP {
		seen[fp] = struct{}{}
		allFP = append(allFP, fp)
	}
	for fp := range headByFP {
		if _, ok := seen[fp]; ok {
			continue
		}
		allFP = append(allFP, fp)
	}
	sort.Strings(allFP)

	report := model.DiffReport{
		SchemaVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		BaseSource:    base.Source,
		HeadSource:    head.Source,
		Added:         []model.Finding{},
		Removed:       []model.Finding{},
		Changed:       []model.ChangedFinding{},
		Unchanged:     []model.Finding{},
	}

	for _, fp := range allFP {
		bf, hasBase := baseByFP[fp]
		hf, hasHead := headByFP[fp]

		switch {
		case hasBase && !hasHead:
			report.Removed = append(report.Removed, bf)
		case !hasBase && hasHead:
			report.Added = append(report.Added, hf)
		default:
			if sameFindingContent(bf, hf) {
				report.Unchanged = append(report.Unchanged, hf)
			} else {
				report.Changed = append(report.Changed, model.ChangedFinding{
					Before:        bf,
					After:         hf,
					ChangedFields: changedFields(bf, hf),
				})
			}
		}
	}

	report.Summary = model.DiffSummary{
		AddedCount:        len(report.Added),
		RemovedCount:      len(report.Removed),
		ChangedCount:      len(report.Changed),
		UnchangedCount:    len(report.Unchanged),
		AddedBySeverity:   countFindingsBy(report.Added, func(f model.Finding) string { return normalizeKey(f.Severity) }),
		RemovedBySeverity: countFindingsBy(report.Removed, func(f model.Finding) string { return normalizeKey(f.Severity) }),
		ChangedBySeverity: countFindingsByChanged(report.Changed, func(f model.Finding) string { return normalizeKey(f.Severity) }),
		AddedByCategory:   countFindingsBy(report.Added, func(f model.Finding) string { return normalizeKey(f.Category) }),
		RemovedByCategory: countFindingsBy(report.Removed, func(f model.Finding) string { return normalizeKey(f.Category) }),
		ChangedByCategory: countFindingsByChanged(report.Changed, func(f model.Finding) string { return normalizeKey(f.Category) }),
	}
	return report
}

func Markdown(report model.DiffReport) string {
	var b strings.Builder
	b.WriteString("# cryptodiff posture diff\n\n")
	b.WriteString(fmt.Sprintf(
		"- Added: **%d**  \n- Removed: **%d**  \n- Changed: **%d**  \n- Unchanged: **%d**\n\n",
		report.Summary.AddedCount,
		report.Summary.RemovedCount,
		report.Summary.ChangedCount,
		report.Summary.UnchangedCount,
	))

	writeFindingSection(&b, "Added", report.Added)
	writeFindingSection(&b, "Removed", report.Removed)
	writeFindingSection(&b, "Unchanged", report.Unchanged)
	writeChangedSection(&b, report.Changed)

	return b.String()
}

func writeFindingSection(b *strings.Builder, title string, findings []model.Finding) {
	if len(findings) == 0 {
		return
	}
	b.WriteString("## " + title + "\n\n")
	for _, f := range findings {
		path := findingPath(f)
		b.WriteString(fmt.Sprintf("- `%s` (%s/%s): %s", f.RuleID, f.Severity, f.Confidence, f.Subject))
		if path != "" {
			b.WriteString(fmt.Sprintf(" [`%s`]", path))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeChangedSection(b *strings.Builder, changed []model.ChangedFinding) {
	if len(changed) == 0 {
		return
	}
	b.WriteString("## Changed\n\n")
	for _, c := range changed {
		path := findingPath(c.After)
		b.WriteString(fmt.Sprintf("- `%s`: %s -> %s", c.After.RuleID, c.Before.Subject, c.After.Subject))
		if path != "" {
			b.WriteString(fmt.Sprintf(" [`%s`]", path))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func findingPath(f model.Finding) string {
	if len(f.Evidence) == 0 {
		return ""
	}
	return f.Evidence[0].Path
}

func sameFindingContent(a, b model.Finding) bool {
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

func countFindingsBy(findings []model.Finding, keyFn func(model.Finding) string) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		k := keyFn(f)
		if k == "" {
			continue
		}
		out[k]++
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func countFindingsByChanged(changes []model.ChangedFinding, keyFn func(model.Finding) string) map[string]int {
	out := map[string]int{}
	for _, ch := range changes {
		k := keyFn(ch.After)
		if k == "" {
			continue
		}
		out[k]++
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeKey(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func changedFields(a, b model.Finding) []string {
	out := []string{}
	if a.ID != b.ID {
		out = append(out, "id")
	}
	if a.RuleID != b.RuleID {
		out = append(out, "ruleId")
	}
	if a.Severity != b.Severity {
		out = append(out, "severity")
	}
	if a.Category != b.Category {
		out = append(out, "category")
	}
	if a.Confidence != b.Confidence {
		out = append(out, "confidence")
	}
	if a.Subject != b.Subject {
		out = append(out, "subject")
	}
	if !reflect.DeepEqual(a.Attributes, b.Attributes) {
		out = append(out, "attributes")
	}
	if !reflect.DeepEqual(a.Evidence, b.Evidence) {
		out = append(out, "evidence")
	}
	if a.Fingerprint != b.Fingerprint {
		out = append(out, "fingerprint")
	}
	return out
}
