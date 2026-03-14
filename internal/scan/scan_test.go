package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/config"
	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestRunEmitsNewRulePackFindings(t *testing.T) {
	repo := t.TempDir()
	content := `tls_min_version: 1.0
ciphers: RC4-SHA
insecureSkipVerify: true
rsa_key_size: 1024
`
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if !hasRule(posture.Findings, "CRYPTO.TLS.WEAK_CIPHER") {
		t.Fatal("expected CRYPTO.TLS.WEAK_CIPHER finding")
	}
	if !hasRule(posture.Findings, "CRYPTO.CERT.VERIFY_DISABLED") {
		t.Fatal("expected CRYPTO.CERT.VERIFY_DISABLED finding")
	}
	if !hasRule(posture.Findings, "CRYPTO.KEY.WEAK_SIZE") {
		t.Fatal("expected CRYPTO.KEY.WEAK_SIZE finding")
	}
	if posture.Summary.Findings != len(posture.Findings) {
		t.Fatalf("expected posture summary findings to match findings length")
	}
}

func TestRunIsDeterministicForSameInput(t *testing.T) {
	repo := t.TempDir()
	content := `tls_min_version: 1.0
ciphers: RC4-SHA
insecureSkipVerify: true
rsa_key_size: 1024
`
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()

	first, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("first scan failed: %v", err)
	}
	second, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("second scan failed: %v", err)
	}

	// Ignore generation timestamp in determinism assertion.
	first.GeneratedAt = ""
	second.GeneratedAt = ""

	fb, _ := json.Marshal(first)
	sb, _ := json.Marshal(second)
	if !reflect.DeepEqual(fb, sb) {
		t.Fatalf("expected deterministic scan output; first=%s second=%s", string(fb), string(sb))
	}
}

func TestRunTracksSuppressionProvenance(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".cryptodiffignore"), []byte("ignored.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := `# cryptodiff:ignore-next-line CRYPTO.TLS.MIN_VERSION
tls_min_version: 1.0
rsa_key_size: 1024
`
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "ignored.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if posture.Summary.Suppressed != 2 {
		t.Fatalf("expected total suppressed=2, got %d", posture.Summary.Suppressed)
	}
	if posture.Suppressions.Inline != 1 {
		t.Fatalf("expected inline suppressions=1, got %d", posture.Suppressions.Inline)
	}
	if posture.Suppressions.IgnoreFile != 1 {
		t.Fatalf("expected ignore-file suppressions=1, got %d", posture.Suppressions.IgnoreFile)
	}
}

func TestRunRespectsIncludeExcludeScope(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "allowed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "allowed", "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "blocked", "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "blocked", "app.json"), []byte(`{"tls_min_version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Scan.Include = []string{"**/*.yaml"}
	cfg.Scan.Exclude = []string{"**/blocked/**"}

	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	for _, f := range posture.Findings {
		if strings.Contains(f.Evidence[0].Path, "blocked/") {
			t.Fatalf("expected blocked path to be excluded, got finding at %s", f.Evidence[0].Path)
		}
	}
	if !hasRule(posture.Findings, "CRYPTO.TLS.MIN_VERSION") {
		t.Fatal("expected finding from allowed/app.yaml")
	}
}

func TestRunMergesDuplicateClassFindingsIntoEvidence(t *testing.T) {
	repo := t.TempDir()
	content := `tls_min_version: 1.0
other_setting: true
tls_min_version: 1.0
`
	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	var tlsFindings []model.Finding
	for _, f := range posture.Findings {
		if f.RuleID == "CRYPTO.TLS.MIN_VERSION" {
			tlsFindings = append(tlsFindings, f)
		}
	}
	if len(tlsFindings) != 1 {
		t.Fatalf("expected 1 class finding, got %d", len(tlsFindings))
	}
	if len(tlsFindings[0].Evidence) != 2 {
		t.Fatalf("expected 2 evidence entries for repeated finding, got %d", len(tlsFindings[0].Evidence))
	}
	if tlsFindings[0].Evidence[0].Line != 1 || tlsFindings[0].Evidence[1].Line != 3 {
		t.Fatalf("unexpected evidence lines: %+v", tlsFindings[0].Evidence)
	}
}

func TestRunCollectsPerFileScanErrors(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "good.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "bad.yaml"), []byte{0xff, 0xfe, 0xfd}, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if posture.Summary.ScanErrors != 1 {
		t.Fatalf("expected summary scanErrors=1, got %d", posture.Summary.ScanErrors)
	}
	if len(posture.ScanErrors) != 1 {
		t.Fatalf("expected 1 scanErrors entry, got %d", len(posture.ScanErrors))
	}
	if posture.ScanErrors[0].Path != "bad.yaml" {
		t.Fatalf("expected scanErrors path bad.yaml, got %q", posture.ScanErrors[0].Path)
	}
	if posture.ScanErrors[0].Stage != "scan_file" {
		t.Fatalf("expected scanErrors stage scan_file, got %q", posture.ScanErrors[0].Stage)
	}
	if !hasRule(posture.Findings, "CRYPTO.TLS.MIN_VERSION") {
		t.Fatal("expected scan to retain findings from readable files")
	}
}

func TestRunSkipsSymlinkedFiles(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(outside, "external.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "external.yaml"), filepath.Join(repo, "linked.yaml")); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasRule(posture.Findings, "CRYPTO.TLS.MIN_VERSION") {
		t.Fatal("expected no findings from symlinked external file")
	}
	if posture.Summary.ScanErrors != 1 {
		t.Fatalf("expected summary scanErrors=1, got %d", posture.Summary.ScanErrors)
	}
	if len(posture.ScanErrors) != 1 {
		t.Fatalf("expected 1 scan error, got %d", len(posture.ScanErrors))
	}
	if posture.ScanErrors[0].Path != "linked.yaml" {
		t.Fatalf("expected scan error path linked.yaml, got %q", posture.ScanErrors[0].Path)
	}
	if posture.ScanErrors[0].Stage != "scan_symlink_skipped" {
		t.Fatalf("expected scan error stage scan_symlink_skipped, got %q", posture.ScanErrors[0].Stage)
	}
}

func TestRunSkipsSymlinkedDirectories(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(outside, "external.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "linked-dir")); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	posture, err := Run(repo, cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if hasRule(posture.Findings, "CRYPTO.TLS.MIN_VERSION") {
		t.Fatal("expected no findings from symlinked external directory")
	}
	if posture.Summary.ScanErrors != 1 {
		t.Fatalf("expected summary scanErrors=1, got %d", posture.Summary.ScanErrors)
	}
	if len(posture.ScanErrors) != 1 {
		t.Fatalf("expected 1 scan error, got %d", len(posture.ScanErrors))
	}
	if posture.ScanErrors[0].Path != "linked-dir" {
		t.Fatalf("expected scan error path linked-dir, got %q", posture.ScanErrors[0].Path)
	}
	if posture.ScanErrors[0].Stage != "scan_symlink_skipped" {
		t.Fatalf("expected scan error stage scan_symlink_skipped, got %q", posture.ScanErrors[0].Stage)
	}
}

func TestPathScopeMatcherSemantics(t *testing.T) {
	m, err := newPathScopeMatcher(
		[]string{"*.yaml", "/src/**"},
		[]string{"**/vendor/**", "**/testdata/**", "secret.yaml"},
	)
	if err != nil {
		t.Fatalf("unexpected matcher compile error: %v", err)
	}

	tests := []struct {
		name       string
		path       string
		shouldScan bool
	}{
		{
			name:       "basename include matches nested yaml",
			path:       "services/api/config.yaml",
			shouldScan: true,
		},
		{
			name:       "anchored include matches root src",
			path:       "src/main.go",
			shouldScan: true,
		},
		{
			name:       "anchored include does not match nested src segment",
			path:       "pkg/src/main.go",
			shouldScan: false,
		},
		{
			name:       "exclude wins over include",
			path:       "src/vendor/config.yaml",
			shouldScan: false,
		},
		{
			name:       "basename exclude applies globally",
			path:       "configs/secret.yaml",
			shouldScan: false,
		},
		{
			name:       "path not matching include is excluded",
			path:       "docs/readme.md",
			shouldScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.ShouldScanFile(tt.path)
			if got != tt.shouldScan {
				t.Fatalf("ShouldScanFile(%q)=%v want %v", tt.path, got, tt.shouldScan)
			}
		})
	}
}

func TestPathScopeMatcherDirectoryPruning(t *testing.T) {
	m, err := newPathScopeMatcher(nil, []string{"**/vendor/**", "**/build/**"})
	if err != nil {
		t.Fatalf("unexpected matcher compile error: %v", err)
	}

	tests := []struct {
		dir      string
		shouldGo bool
	}{
		{dir: "src", shouldGo: true},
		{dir: "vendor", shouldGo: false},
		{dir: "pkg/vendor", shouldGo: false},
		{dir: "pkg/build/output", shouldGo: false},
		{dir: "pkg/builder", shouldGo: true},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			got := m.ShouldEnterDir(tt.dir)
			if got != tt.shouldGo {
				t.Fatalf("ShouldEnterDir(%q)=%v want %v", tt.dir, got, tt.shouldGo)
			}
		})
	}
}

func TestNormalizeScanErrorPathPrefersRelativeAndFallsBackToBase(t *testing.T) {
	repo := t.TempDir()
	s := repoScanState{absRepo: repo}

	inside := filepath.Join(repo, "nested", "bad.yaml")
	got := s.normalizeScanErrorPath(inside)
	if got != "nested/bad.yaml" {
		t.Fatalf("expected relative normalized path, got %q", got)
	}
	if strings.HasPrefix(got, "/") {
		t.Fatalf("expected non-absolute normalized path, got %q", got)
	}

	outside := "/tmp/elsewhere/config.yaml"
	got = s.normalizeScanErrorPath(outside)
	if got != "config.yaml" {
		t.Fatalf("expected basename fallback, got %q", got)
	}
}

func hasRule(findings []model.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
