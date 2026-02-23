package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPrecedenceCLIOverEnvOverConfig(t *testing.T) {
	repo := t.TempDir()
	cfgPath := filepath.Join(repo, "cryptodiff.yaml")
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("outputs:\n  outDir: config-out\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CRYPTODIFF_CONFIG", cfgPath)
	t.Setenv("CRYPTODIFF_OUT_DIR", filepath.Join(repo, "env-out"))

	// No --out-dir, so env should win over config.
	exit := Run([]string{"scan", "--repo", repo})
	if exit != 0 {
		t.Fatalf("expected scan to succeed, got %d", exit)
	}
	if _, err := os.Stat(filepath.Join(repo, "env-out", "posture.json")); err != nil {
		t.Fatalf("expected posture.json in env-out, got error: %v", err)
	}

	// CLI should win over env.
	cliOut := filepath.Join(repo, "cli-out")
	exit = Run([]string{"scan", "--repo", repo, "--out-dir", cliOut})
	if exit != 0 {
		t.Fatalf("expected scan to succeed with cli out-dir, got %d", exit)
	}
	if _, err := os.Stat(filepath.Join(cliOut, "posture.json")); err != nil {
		t.Fatalf("expected posture.json in cli out-dir, got error: %v", err)
	}
}

func TestScanScopePrecedenceCLIOverEnvOverConfig(t *testing.T) {
	repo := t.TempDir()
	cfgPath := filepath.Join(repo, "cryptodiff.yaml")
	cfgBody := `scan:
  include: ["**/*.json"]
  exclude: ["**/blocked/**"]
outputs:
  outDir: config-out
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "allowed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "allowed", "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "allowed", "app.json"), []byte(`{"algorithm":"md5"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CRYPTODIFF_CONFIG", cfgPath)
	t.Setenv("CRYPTODIFF_OUT_DIR", filepath.Join(repo, "env-out"))
	t.Setenv("CRYPTODIFF_SCAN_INCLUDE", "**/*.yaml")

	// No CLI include/exclude: env include should win over config include.
	exit := Run([]string{"scan", "--repo", repo, "--sarif=false", "--cbom=false"})
	if exit != 0 {
		t.Fatalf("expected scan to succeed, got %d", exit)
	}
	postureBytes, err := os.ReadFile(filepath.Join(repo, "env-out", "posture.json"))
	if err != nil {
		t.Fatalf("read posture: %v", err)
	}
	if !strings.Contains(string(postureBytes), "allowed/app.yaml") {
		t.Fatalf("expected env include to select yaml findings")
	}
	if strings.Contains(string(postureBytes), "allowed/app.json") {
		t.Fatalf("expected env include to exclude json findings")
	}

	// CLI include should win over env include.
	cliOut := filepath.Join(repo, "cli-out")
	exit = Run([]string{
		"scan",
		"--repo", repo,
		"--out-dir", cliOut,
		"--include", "**/*.json",
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 0 {
		t.Fatalf("expected scan to succeed with cli include, got %d", exit)
	}
	postureBytes, err = os.ReadFile(filepath.Join(cliOut, "posture.json"))
	if err != nil {
		t.Fatalf("read posture: %v", err)
	}
	if !strings.Contains(string(postureBytes), "allowed/app.json") {
		t.Fatalf("expected cli include to select json findings")
	}
	if strings.Contains(string(postureBytes), "allowed/app.yaml") {
		t.Fatalf("expected cli include to exclude yaml findings")
	}
}

func TestScanStrictErrorPrecedenceCLIOverConfig(t *testing.T) {
	repo := t.TempDir()
	cfgPath := filepath.Join(repo, "cryptodiff.yaml")
	cfgBody := `scan:
  failOnError: true
outputs:
  outDir: config-out
`
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "bad.yaml"), []byte{0xff, 0xfe}, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CRYPTODIFF_CONFIG", cfgPath)

	// Config strict mode should fail when scan errors are present.
	exit := Run([]string{"scan", "--repo", repo, "--sarif=false", "--cbom=false"})
	if exit != 2 {
		t.Fatalf("expected scan to fail from config failOnError, got %d", exit)
	}

	// CLI should override config strictness.
	cliOut := filepath.Join(repo, "cli-out")
	exit = Run([]string{
		"scan",
		"--repo", repo,
		"--out-dir", cliOut,
		"--strict-scan-errors=false",
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 0 {
		t.Fatalf("expected scan to succeed with cli strict override, got %d", exit)
	}
	if _, err := os.Stat(filepath.Join(cliOut, "posture.json")); err != nil {
		t.Fatalf("expected posture.json in cli out-dir, got error: %v", err)
	}
}
