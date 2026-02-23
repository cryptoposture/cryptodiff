package sarif

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

type report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []rule `json:"rules,omitempty"`
}

type rule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription shortDescription  `json:"shortDescription,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type shortDescription struct {
	Text string `json:"text"`
}

type result struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    shortDescription `json:"message"`
	Locations  []location       `json:"locations,omitempty"`
	Properties map[string]any   `json:"properties,omitempty"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine,omitempty"`
}

func FromPosture(p model.Posture) ([]byte, error) {
	rules := uniqueRules(p.Findings)
	results := make([]result, 0, len(p.Findings))
	for _, f := range p.Findings {
		results = append(results, findingResult(f))
	}
	rep := report{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{
			{
				Tool: tool{
					Driver: driver{
						Name:           p.Tool.Name,
						Version:        p.Tool.Version,
						InformationURI: "https://github.com/cryptoposture/cryptodiff",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
	return json.MarshalIndent(rep, "", "  ")
}

func uniqueRules(findings []model.Finding) []rule {
	byID := map[string]rule{}
	for _, f := range findings {
		if _, ok := byID[f.RuleID]; ok {
			continue
		}
		byID[f.RuleID] = rule{
			ID:   f.RuleID,
			Name: f.RuleID,
			ShortDescription: shortDescription{
				Text: f.Subject,
			},
		}
	}
	out := make([]rule, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func findingResult(f model.Finding) result {
	res := result{
		RuleID:  f.RuleID,
		Level:   severityToSARIFLevel(f.Severity),
		Message: shortDescription{Text: f.Subject},
		Properties: map[string]any{
			"category":    f.Category,
			"confidence":  f.Confidence,
			"fingerprint": f.Fingerprint,
		},
	}
	if len(f.Evidence) > 0 {
		e := f.Evidence[0]
		loc := location{
			PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: e.Path},
			},
		}
		if e.Line > 0 {
			loc.PhysicalLocation.Region = &region{StartLine: e.Line}
		}
		res.Locations = []location{loc}
	}
	return res
}

func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
