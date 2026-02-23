package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunScanEmitsPostureSarifAndCBOM(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	configPath := filepath.Join(repo, "cryptodiff.yaml")

	// Deliberately include high-confidence patterns so scan emits findings.
	source := `tls_min_version: 1.0
ciphers: RC4-SHA
insecureSkipVerify: true
rsa_key_size: 1024
`
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte(source), 0o644); err != nil {
		t.Fatalf("failed to write test source file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("version: 0.2\n"), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--config", configPath,
		"--out-dir", outDir,
		"--sarif=true",
		"--cbom=true",
	})
	if exit != 0 {
		t.Fatalf("expected scan command to succeed, got exit code %d", exit)
	}

	mustExist(t, filepath.Join(outDir, "posture.json"))
	mustExist(t, filepath.Join(outDir, "posture.sarif"))
	mustExist(t, filepath.Join(outDir, "cbom.json"))

	assertJSONFile(t, filepath.Join(outDir, "posture.json"))
	assertTopLevelFieldEquals(t, filepath.Join(outDir, "posture.sarif"), "version", "2.1.0")
	assertTopLevelFieldEquals(t, filepath.Join(outDir, "cbom.json"), "bomFormat", "CycloneDX")
	assertTopLevelFieldEquals(t, filepath.Join(outDir, "cbom.json"), "specVersion", "1.5")
}

func TestRunScanReportsScanErrorsInPosture(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	configPath := filepath.Join(repo, "cryptodiff.yaml")

	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write valid test source file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "bad.yaml"), []byte{0xff, 0xfe, 0xfd}, 0o644); err != nil {
		t.Fatalf("failed to write invalid utf8 file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("version: 0.2\n"), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--config", configPath,
		"--out-dir", outDir,
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 0 {
		t.Fatalf("expected scan command to succeed in non-strict mode, got exit code %d", exit)
	}

	posturePath := filepath.Join(outDir, "posture.json")
	mustExist(t, posturePath)
	b, err := os.ReadFile(posturePath)
	if err != nil {
		t.Fatalf("failed reading posture: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid posture json: %v", err)
	}
	summary, ok := m["summary"].(map[string]any)
	if !ok {
		t.Fatal("expected summary object")
	}
	if summary["scanErrors"] != float64(1) {
		t.Fatalf("expected summary.scanErrors=1, got %v", summary["scanErrors"])
	}
	scanErrors, ok := m["scanErrors"].([]any)
	if !ok || len(scanErrors) != 1 {
		t.Fatalf("expected exactly 1 scanErrors entry, got %#v", m["scanErrors"])
	}
}

func TestRunScanStrictScanErrorsFails(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	configPath := filepath.Join(repo, "cryptodiff.yaml")

	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write valid test source file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "bad.yaml"), []byte{0xff, 0xfe, 0xfd}, 0o644); err != nil {
		t.Fatalf("failed to write invalid utf8 file: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("version: 0.2\n"), 0o644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--config", configPath,
		"--out-dir", outDir,
		"--strict-scan-errors=true",
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 2 {
		t.Fatalf("expected strict scan to fail with exit code 2, got %d", exit)
	}
	// Posture should still be emitted to preserve error details for diagnostics.
	mustExist(t, filepath.Join(outDir, "posture.json"))
}

func TestRunScanFailsWhenExplicitConfigPathMissing(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	missingConfig := filepath.Join(repo, "does-not-exist.yaml")
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write test source file: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--config", missingConfig,
		"--out-dir", outDir,
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 2 {
		t.Fatalf("expected scan to fail with explicit missing config, got exit code %d", exit)
	}
}

func TestRunScanFailsWhenEnvConfigPathMissing(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	missingConfig := filepath.Join(repo, "does-not-exist.yaml")
	t.Setenv("CRYPTODIFF_CONFIG", missingConfig)
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write test source file: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--out-dir", outDir,
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 2 {
		t.Fatalf("expected scan to fail with env missing config, got exit code %d", exit)
	}
}

func TestRunScanAllowsMissingDefaultConfigPath(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatalf("failed to write test source file: %v", err)
	}

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--out-dir", outDir,
		"--sarif=false",
		"--cbom=false",
	})
	if exit != 0 {
		t.Fatalf("expected scan to succeed when default config is missing, got exit code %d", exit)
	}
	mustExist(t, filepath.Join(outDir, "posture.json"))
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected file to exist: %s (%v)", path, err)
	}
	if info.IsDir() {
		t.Fatalf("expected file but found directory: %s", path)
	}
}

func assertJSONFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading %s: %v", path, err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("invalid json in %s: %v", path, err)
	}
}

func assertTopLevelFieldEquals(t *testing.T, path, field, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("invalid json in %s: %v", path, err)
	}
	got, ok := m[field]
	if !ok {
		t.Fatalf("expected top-level field %q in %s", field, path)
	}
	if got != want {
		t.Fatalf("unexpected value for %s in %s: got=%v want=%v", field, path, got, want)
	}
}
