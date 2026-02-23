package sarif

import (
	"encoding/json"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestFromPostureGeneratesValidSkeleton(t *testing.T) {
	p := model.Posture{
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Findings: []model.Finding{
			{
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Confidence:  "high",
				Subject:     "Disallowed algorithm reference: md5",
				Fingerprint: "fp1",
				Evidence: []model.Evidence{
					{Path: "app.yaml", Line: 3},
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
		t.Fatalf("sarif output should be valid json: %v", err)
	}
	if root["version"] != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %v", root["version"])
	}
}

func TestSeverityMapping(t *testing.T) {
	if got := severityToSARIFLevel("critical"); got != "error" {
		t.Fatalf("critical should map to error, got %s", got)
	}
	if got := severityToSARIFLevel("medium"); got != "warning" {
		t.Fatalf("medium should map to warning, got %s", got)
	}
	if got := severityToSARIFLevel("low"); got != "note" {
		t.Fatalf("low should map to note, got %s", got)
	}
}
