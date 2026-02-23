package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadParsesMatchValuesBlockList(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      values:
        - md5
        - sha1
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	if got := p.Rules[0].Match.Values; len(got) != 2 || got[0] != "md5" || got[1] != "sha1" {
		t.Fatalf("unexpected match.values: %#v", got)
	}
}

func TestLoadParsesMultipleRulesAfterMatchValuesBlockList(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      values:
        - md5
        - sha1
  - id: CRYPTO.TLS.MIN_VERSION
    level: high
    match:
      category: tls
      attribute: minVersion
      op: <
      value: "1.2"
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Rules))
	}
	if got := p.Rules[0].Match.Values; len(got) != 2 || got[0] != "md5" || got[1] != "sha1" {
		t.Fatalf("unexpected first rule match.values: %#v", got)
	}
	if p.Rules[1].ID != "CRYPTO.TLS.MIN_VERSION" {
		t.Fatalf("expected second rule id CRYPTO.TLS.MIN_VERSION, got %q", p.Rules[1].ID)
	}
	if p.Rules[1].Match.Value != "1.2" {
		t.Fatalf("expected second rule scalar value 1.2, got %#v", p.Rules[1].Match.Value)
	}
}

func TestLoadErrorsWhenPolicyFileMissing(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.yaml")

	_, err := Load(missing)
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got: %v", err)
	}
}

func TestLoadRejectsUnknownTopLevelKey(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      values: [md5]
unexpected: true
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := Load(policyPath)
	if err == nil || !strings.Contains(err.Error(), "unknown top-level key") {
		t.Fatalf("expected unknown top-level key error, got: %v", err)
	}
}

func TestLoadRejectsUnknownMatchKey(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      valuess: [md5, sha1]
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := Load(policyPath)
	if err == nil || !strings.Contains(err.Error(), "unknown match key") {
		t.Fatalf("expected unknown match key error, got: %v", err)
	}
}

func TestLoadRejectsRuleMissingID(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - level: high
    match:
      category: tls
      attribute: minVersion
      op: <
      value: "1.2"
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      values: [md5]
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	_, err := Load(policyPath)
	if err == nil || !strings.Contains(err.Error(), `missing required field "id"`) {
		t.Fatalf("expected missing id error, got: %v", err)
	}
}

func TestLoadNormalizesRuleIDToUppercase(t *testing.T) {
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	content := `
version: "0.2"
rules:
  - id: crypto.alg.disallowed
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      values: [md5]
`
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	p, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(p.Rules))
	}
	if got := p.Rules[0].ID; got != "CRYPTO.ALG.DISALLOWED" {
		t.Fatalf("expected normalized uppercase rule id, got %q", got)
	}
}

func TestLoadRejectsInvalidSemanticCombos(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErrPart string
	}{
		{
			name: "in without values",
			content: `
version: "0.2"
rules:
  - id: CRYPTO.ALG.DISALLOWED
    level: critical
    match:
      category: algorithm
      attribute: name
      op: in
      value: md5
`,
			wantErrPart: `must not set match.value`,
		},
		{
			name: "lt with values",
			content: `
version: "0.2"
rules:
  - id: CRYPTO.TLS.MIN_VERSION
    level: high
    match:
      category: tls
      attribute: minVersion
      op: <
      values: [1.2]
`,
			wantErrPart: `must not set match.values`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			policyPath := filepath.Join(tmp, "policy.yaml")
			if err := os.WriteFile(policyPath, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("write policy: %v", err)
			}

			_, err := Load(policyPath)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantErrPart, err)
			}
		})
	}
}
