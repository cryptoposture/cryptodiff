package cbom

import (
	"encoding/json"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestFromPostureGeneratesCycloneDXDocument(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-02-22T00:00:00Z",
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Source: model.Source{
			RepoPath: "/tmp/repo",
		},
		Findings: []model.Finding{
			{
				RuleID:      "CRYPTO.KEY.WEAK_SIZE",
				Severity:    "high",
				Category:    "algorithm",
				Confidence:  "high",
				Subject:     "Weak RSA key size detected: 1024",
				Fingerprint: "abc123",
				Attributes:  map[string]any{"detectedValue": "1024"},
				Evidence: []model.Evidence{
					{Path: "app.yaml", Line: 7},
				},
			},
		},
	}

	b, err := FromPosture(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatalf("cbom output should be valid json: %v", err)
	}
	if root["bomFormat"] != "CycloneDX" {
		t.Fatalf("expected bomFormat CycloneDX, got %v", root["bomFormat"])
	}
	if root["specVersion"] != "1.5" {
		t.Fatalf("expected specVersion 1.5, got %v", root["specVersion"])
	}
}

func TestFromPostureIsDeterministic(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		Tool:          model.Tool{Name: "cryptodiff", Version: "dev"},
		Findings: []model.Finding{
			{
				RuleID:      "R2",
				Severity:    "medium",
				Category:    "tls",
				Confidence:  "high",
				Subject:     "b",
				Fingerprint: "2",
				Evidence:    []model.Evidence{{Path: "b.yaml"}},
			},
			{
				RuleID:      "R1",
				Severity:    "high",
				Category:    "tls",
				Confidence:  "high",
				Subject:     "a",
				Fingerprint: "1",
				Evidence:    []model.Evidence{{Path: "a.yaml"}},
			},
		},
	}
	first, err := FromPosture(p)
	if err != nil {
		t.Fatalf("first generation failed: %v", err)
	}
	second, err := FromPosture(p)
	if err != nil {
		t.Fatalf("second generation failed: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("expected deterministic cbom output")
	}
}
