package suppress

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/config"
	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestSuppressPathFromIgnoreFile(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".cryptodiffignore"), []byte("**/ignored/**\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewMatcher(tmp, config.Suppress{IgnoreFile: ".cryptodiffignore"})
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	if !m.SuppressPath("src/ignored/app.yaml") {
		t.Fatal("expected path to be suppressed by ignore file pattern")
	}
	if m.SuppressPath("src/ok/app.yaml") {
		t.Fatal("did not expect non-matching path to be suppressed")
	}
}

func TestSuppressPathFromIgnoreFileMatchesRootAndNestedDoubleStarDir(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".cryptodiffignore"), []byte("**/ignored/**\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewMatcher(tmp, config.Suppress{IgnoreFile: ".cryptodiffignore"})
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	if !m.SuppressPath("ignored/app.yaml") {
		t.Fatal("expected root-level ignored path to be suppressed")
	}
	if !m.SuppressPath("src/ignored/app.yaml") {
		t.Fatal("expected nested ignored path to be suppressed")
	}
	if m.SuppressPath("src/not-ignored/app.yaml") {
		t.Fatal("did not expect non-matching path to be suppressed")
	}
}

func TestSuppressPathFromIgnoreFileMatchesRootAndNestedDoubleStarExtension(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".cryptodiffignore"), []byte("**/*.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := NewMatcher(tmp, config.Suppress{IgnoreFile: ".cryptodiffignore"})
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	if !m.SuppressPath("app.yaml") {
		t.Fatal("expected root-level yaml path to be suppressed")
	}
	if !m.SuppressPath("src/app.yaml") {
		t.Fatal("expected nested yaml path to be suppressed")
	}
	if m.SuppressPath("src/app.json") {
		t.Fatal("did not expect non-yaml path to be suppressed")
	}
}

func TestInlineDirectiveSuppression(t *testing.T) {
	m, err := NewMatcher(t.TempDir(), config.Suppress{})
	if err != nil {
		t.Fatalf("unexpected matcher error: %v", err)
	}
	f := model.Finding{RuleID: "CRYPTO.ALG.DISALLOWED", Category: "algorithm"}
	if !m.SuppressFinding(f, []string{"CRYPTO.ALG.*"}) {
		t.Fatal("expected inline wildcard directive to suppress finding")
	}
}

func TestIgnoreNextLineDirective(t *testing.T) {
	active, pending := ParseInlineDirectives("# cryptodiff:ignore-next-line CRYPTO.ALG.*", nil)
	if len(active) != 0 {
		t.Fatalf("expected no active directives on marker line, got %d", len(active))
	}
	active2, _ := ParseInlineDirectives("md5", pending)
	if len(active2) != 1 {
		t.Fatalf("expected next-line directive to become active, got %d", len(active2))
	}
}

func TestNewMatcherFailsForInvalidConfigPathGlob(t *testing.T) {
	_, err := NewMatcher(t.TempDir(), config.Suppress{
		Paths: []string{"/"},
	})
	if err == nil {
		t.Fatal("expected matcher construction to fail for invalid config glob")
	}
}

func TestNewMatcherFailsForInvalidIgnoreFileGlob(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, ".cryptodiffignore"), []byte("/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewMatcher(tmp, config.Suppress{IgnoreFile: ".cryptodiffignore"})
	if err == nil {
		t.Fatal("expected matcher construction to fail for invalid ignore file glob")
	}
}
