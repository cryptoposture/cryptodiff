package cbom

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    metadata    `json:"metadata"`
	Components  []component `json:"components,omitempty"`
	Properties  []property  `json:"properties,omitempty"`
}

type metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     []tool     `json:"tools,omitempty"`
	Component *component `json:"component,omitempty"`
}

type tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	BOMRef     string     `json:"bom-ref,omitempty"`
	Version    string     `json:"version,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func FromPosture(p model.Posture) ([]byte, error) {
	components := make([]component, 0, len(p.Findings))
	for _, f := range p.Findings {
		components = append(components, findingComponent(f))
	}
	sort.Slice(components, func(i, j int) bool {
		if components[i].BOMRef == components[j].BOMRef {
			return components[i].Name < components[j].Name
		}
		return components[i].BOMRef < components[j].BOMRef
	})

	rootName := "scan-target"
	if strings.TrimSpace(p.Source.RepoPath) != "" {
		rootName = filepath.Base(p.Source.RepoPath)
	}

	doc := document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: metadata{
			Timestamp: p.GeneratedAt,
			Tools: []tool{
				{
					Vendor:  "cryptoposture",
					Name:    p.Tool.Name,
					Version: p.Tool.Version,
				},
			},
			Component: &component{
				Type: "application",
				Name: rootName,
			},
		},
		Components: components,
		Properties: []property{
			{Name: "cryptodiff:schemaVersion", Value: p.SchemaVersion},
			{Name: "cryptodiff:findingsCount", Value: strconv.Itoa(len(p.Findings))},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}

func findingComponent(f model.Finding) component {
	name := strings.TrimSpace(f.Subject)
	if name == "" {
		name = f.RuleID
	}
	props := []property{
		{Name: "cryptodiff:ruleId", Value: f.RuleID},
		{Name: "cryptodiff:severity", Value: f.Severity},
		{Name: "cryptodiff:category", Value: f.Category},
		{Name: "cryptodiff:confidence", Value: f.Confidence},
		{Name: "cryptodiff:fingerprint", Value: f.Fingerprint},
	}
	if len(f.Evidence) > 0 {
		e := f.Evidence[0]
		props = append(props, property{Name: "cryptodiff:path", Value: e.Path})
		if e.Line > 0 {
			props = append(props, property{Name: "cryptodiff:line", Value: strconv.Itoa(e.Line)})
		}
	}
	if detected, ok := findingDetectedValue(f); ok {
		props = append(props, property{Name: "cryptodiff:detectedValue", Value: detected})
	}
	return component{
		Type:       "data",
		Name:       name,
		BOMRef:     fmt.Sprintf("urn:cryptodiff:finding:%s", f.Fingerprint),
		Version:    "1",
		Properties: props,
	}
}

func findingDetectedValue(f model.Finding) (string, bool) {
	if f.Attributes == nil {
		return "", false
	}
	v, ok := f.Attributes["detectedValue"]
	if !ok || v == nil {
		return "", false
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v)), true
}
