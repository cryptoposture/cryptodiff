package explain

import (
	"strings"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestSelectFindingByID(t *testing.T) {
	p := model.Posture{
		Findings: []model.Finding{
			{ID: "finding-1", RuleID: "A", Fingerprint: "fp1"},
			{ID: "finding-2", RuleID: "B", Fingerprint: "fp2"},
		},
	}
	f, ok := SelectFinding(p, Selector{FindingID: "finding-2"})
	if !ok {
		t.Fatal("expected finding to be selected")
	}
	if f.ID != "finding-2" {
		t.Fatalf("expected finding-2, got %s", f.ID)
	}
}

func TestRenderContainsRecommendation(t *testing.T) {
	f := model.Finding{
		ID:       "finding-1",
		RuleID:   "CRYPTO.TLS.MIN_VERSION",
		Severity: "high",
		Category: "tls",
		Subject:  "Minimum TLS version set to 1.0",
		Evidence: []model.Evidence{{Path: "app.yaml", Line: 3}},
	}
	out := Render(f)
	if !strings.Contains(out, "Raise the minimum TLS version") {
		t.Fatalf("expected TLS recommendation in output, got: %s", out)
	}
}
