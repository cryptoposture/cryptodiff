package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEnvOverridesFileAndDefaults(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cryptodiff.yaml")
	content := `outputs:
  outDir: file-out
policy:
  mode: report
  failLevel: medium
scan:
  include: ["**/*.yaml"]
  exclude: ["**/vendor/**"]
  maxFileBytes: 1234
  failOnError: false
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CRYPTODIFF_OUT_DIR", "env-out")
	t.Setenv("CRYPTODIFF_POLICY_MODE", "gate")
	t.Setenv("CRYPTODIFF_FAIL_LEVEL", "critical")
	t.Setenv("CRYPTODIFF_SCAN_MAX_FILE_BYTES", "9999")
	t.Setenv("CRYPTODIFF_SCAN_FAIL_ON_ERROR", "true")
	t.Setenv("CRYPTODIFF_SCAN_INCLUDE", "**/*.go,**/*.yaml")
	t.Setenv("CRYPTODIFF_SCAN_EXCLUDE", "**/.git/**,**/node_modules/**")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if cfg.Outputs.OutDir != "env-out" {
		t.Fatalf("expected env outDir override, got %q", cfg.Outputs.OutDir)
	}
	if cfg.Policy.Mode != "gate" {
		t.Fatalf("expected env policy mode override, got %q", cfg.Policy.Mode)
	}
	if cfg.Policy.FailLevel != "critical" {
		t.Fatalf("expected env failLevel override, got %q", cfg.Policy.FailLevel)
	}
	if cfg.Scan.MaxFileBytes != 9999 {
		t.Fatalf("expected env maxFileBytes override, got %d", cfg.Scan.MaxFileBytes)
	}
	if !cfg.Scan.FailOnError {
		t.Fatal("expected env failOnError override")
	}
	if got, want := len(cfg.Scan.Include), 2; got != want {
		t.Fatalf("expected env include override length=%d, got %d", want, got)
	}
	if got, want := len(cfg.Scan.Exclude), 2; got != want {
		t.Fatalf("expected env exclude override length=%d, got %d", want, got)
	}
}

func TestLoadMissingConfigStillAppliesEnv(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.yaml")

	t.Setenv("CRYPTODIFF_OUT_DIR", "env-only-out")
	t.Setenv("CRYPTODIFF_SCAN_MAX_FILE_BYTES", "7777")

	cfg, err := Load(missing)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if cfg.Outputs.OutDir != "env-only-out" {
		t.Fatalf("expected env outDir when config file is missing, got %q", cfg.Outputs.OutDir)
	}
	if cfg.Scan.MaxFileBytes != 7777 {
		t.Fatalf("expected env maxFileBytes when config file is missing, got %d", cfg.Scan.MaxFileBytes)
	}
}

func TestLoadParsesScanIncludeExcludeFromYAMLLists(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "cryptodiff.yaml")
	content := `scan:
  include:
    - "**/*.yaml"
    - "**/*.json"
  exclude:
    - "**/.git/**"
    - "**/vendor/**"
  maxFileBytes: 1234
  failOnError: true
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
	if got, want := len(cfg.Scan.Include), 2; got != want {
		t.Fatalf("expected include length=%d, got %d", want, got)
	}
	if got, want := len(cfg.Scan.Exclude), 2; got != want {
		t.Fatalf("expected exclude length=%d, got %d", want, got)
	}
	if cfg.Scan.MaxFileBytes != 1234 {
		t.Fatalf("expected maxFileBytes=1234, got %d", cfg.Scan.MaxFileBytes)
	}
	if !cfg.Scan.FailOnError {
		t.Fatal("expected failOnError=true from yaml")
	}
}

func TestLoadRejectsMalformedOrUnknownConfigYAML(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErrPart string
	}{
		{
			name: "invalid yaml line",
			content: `scan:
  include
`,
			wantErrPart: "invalid YAML line",
		},
		{
			name: "unknown top-level section",
			content: `scann:
  include: ["**/*.yaml"]
`,
			wantErrPart: "unknown top-level section",
		},
		{
			name: "unknown key in section",
			content: `scan:
  includes: ["**/*.yaml"]
`,
			wantErrPart: `unknown key "includes" in section "scan"`,
		},
		{
			name: "invalid boolean value",
			content: `scan:
  failOnError: maybe
`,
			wantErrPart: "scan.failOnError must be true or false",
		},
		{
			name: "list item outside list context",
			content: `scan:
  - "**/*.yaml"
`,
			wantErrPart: "list item found outside of list context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			cfgPath := filepath.Join(tmp, "cryptodiff.yaml")
			if err := os.WriteFile(cfgPath, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(cfgPath)
			if err == nil {
				t.Fatal("expected config parse error")
			}
			if !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErrPart, err)
			}
		})
	}
}
