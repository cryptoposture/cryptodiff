package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestRunDiffFormatJSONOnly(t *testing.T) {
	tmp := t.TempDir()
	basePath := filepath.Join(tmp, "base.json")
	headPath := filepath.Join(tmp, "head.json")
	outDir := filepath.Join(tmp, "out")

	writePostureFixture(t, basePath, []model.Finding{
		{
			ID:          "f1",
			RuleID:      "CRYPTO.TLS.MIN_VERSION",
			Severity:    "high",
			Category:    "tls",
			Confidence:  "high",
			Subject:     "Minimum TLS version set to 1.0",
			Fingerprint: "fp-1",
			Evidence:    []model.Evidence{{Path: "app.yaml", Line: 1}},
		},
	})
	writePostureFixture(t, headPath, []model.Finding{
		{
			ID:          "f2",
			RuleID:      "CRYPTO.TLS.MIN_VERSION",
			Severity:    "high",
			Category:    "tls",
			Confidence:  "high",
			Subject:     "Minimum TLS version set to 1.1",
			Fingerprint: "fp-2",
			Evidence:    []model.Evidence{{Path: "app.yaml", Line: 1}},
		},
	})

	exit := Run([]string{
		"diff",
		"--base", basePath,
		"--head", headPath,
		"--out-dir", outDir,
		"--format", "json",
	})
	if exit != 0 {
		t.Fatalf("expected diff command to succeed, got exit code %d", exit)
	}
	mustExist(t, filepath.Join(outDir, "diff.json"))
	if _, err := os.Stat(filepath.Join(outDir, "diff.md")); err == nil {
		t.Fatal("expected diff.md to be absent when --format json")
	}
}

func TestRunDiffFormatMDOnly(t *testing.T) {
	tmp := t.TempDir()
	basePath := filepath.Join(tmp, "base.json")
	headPath := filepath.Join(tmp, "head.json")
	outDir := filepath.Join(tmp, "out")

	writePostureFixture(t, basePath, []model.Finding{})
	writePostureFixture(t, headPath, []model.Finding{
		{
			ID:          "f1",
			RuleID:      "CRYPTO.CERT.VERIFY_DISABLED",
			Severity:    "critical",
			Category:    "pki",
			Confidence:  "high",
			Subject:     "Certificate verification appears disabled",
			Fingerprint: "fp-1",
			Evidence:    []model.Evidence{{Path: "tls.yaml", Line: 2}},
		},
	})

	exit := Run([]string{
		"diff",
		"--base", basePath,
		"--head", headPath,
		"--out-dir", outDir,
		"--format", "md",
	})
	if exit != 0 {
		t.Fatalf("expected diff command to succeed, got exit code %d", exit)
	}
	mustExist(t, filepath.Join(outDir, "diff.md"))
	if _, err := os.Stat(filepath.Join(outDir, "diff.json")); err == nil {
		t.Fatal("expected diff.json to be absent when --format md")
	}
}

func TestRunScanBaseRefHeadRef(t *testing.T) {
	repo := t.TempDir()
	outDir := filepath.Join(t.TempDir(), "out")
	cfgPath := filepath.Join(repo, "cryptodiff.yaml")

	if err := os.WriteFile(cfgPath, []byte("version: 0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	runGit(t, repo, "init")
	runGit(t, repo, "config", "user.email", "devnull@example.com")
	runGit(t, repo, "config", "user.name", "Dev Null")

	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "base")
	baseSHA := runGit(t, repo, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(repo, "app.yaml"), []byte("tls_min_version: 1.0\ninsecureSkipVerify: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-m", "head")
	headSHA := runGit(t, repo, "rev-parse", "HEAD")

	exit := Run([]string{
		"scan",
		"--repo", repo,
		"--config", cfgPath,
		"--out-dir", outDir,
		"--base-ref", baseSHA,
		"--head-ref", headSHA,
	})
	if exit != 0 {
		t.Fatalf("expected range scan to succeed, got exit code %d", exit)
	}

	mustExist(t, filepath.Join(outDir, "base", "posture.json"))
	mustExist(t, filepath.Join(outDir, "head", "posture.json"))
	mustExist(t, filepath.Join(outDir, "diff.json"))
	mustExist(t, filepath.Join(outDir, "diff.md"))
}

func writePostureFixture(t *testing.T, path string, findings []model.Finding) {
	t.Helper()
	p := model.Posture{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Tool:          model.Tool{Name: "cryptodiff", Version: "0.2.0-dev"},
		Source:        model.Source{RepoPath: "/repo"},
		Summary: model.PostureSummary{
			Findings: len(findings),
		},
		Suppressions: model.SuppressionSummary{},
		Findings:     findings,
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal posture fixture failed: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write posture fixture failed: %v", err)
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v (%s)", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}
