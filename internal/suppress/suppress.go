package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/config"
	"github.com/cryptoposture/cryptodiff/internal/model"
	"github.com/cryptoposture/cryptodiff/internal/pathglob"
)

type Matcher struct {
	ignorePathPatterns []pathglob.Pattern
	configPathPatterns []pathglob.Pattern
	cfg                config.Suppress
}

func NewMatcher(repoRoot string, cfg config.Suppress) (*Matcher, error) {
	configPatterns, err := compileGlobs(cfg.Paths, "suppress.paths")
	if err != nil {
		return nil, err
	}
	ignoreSource := fmt.Sprintf("suppress ignore file %q", cfg.IgnoreFile)
	ignorePatterns, err := compileGlobs(loadIgnorePatterns(repoRoot, cfg.IgnoreFile), ignoreSource)
	if err != nil {
		return nil, err
	}
	return &Matcher{
		ignorePathPatterns: ignorePatterns,
		configPathPatterns: configPatterns,
		cfg:                cfg,
	}, nil
}

func (m *Matcher) SuppressPath(relPath string) bool {
	ok, _ := m.SuppressPathReason(relPath)
	return ok
}

func (m *Matcher) SuppressPathReason(relPath string) (bool, string) {
	p := filepath.ToSlash(relPath)
	if pathglob.MatchAny(m.ignorePathPatterns, p, false) {
		return true, "ignore_file"
	}
	if pathglob.MatchAny(m.configPathPatterns, p, false) {
		return true, "config_path"
	}
	return false, ""
}

func (m *Matcher) SuppressFinding(f model.Finding, inlineDirectives []string) bool {
	ok, _ := m.SuppressFindingReason(f, inlineDirectives)
	return ok
}

func (m *Matcher) SuppressFindingReason(f model.Finding, inlineDirectives []string) (bool, string) {
	for _, d := range inlineDirectives {
		if patternMatchesRule(d, f.RuleID) {
			return true, "inline"
		}
	}
	for _, rule := range m.cfg.Rules {
		if patternMatchesRule(rule, f.RuleID) {
			return true, "config_rule"
		}
	}
	for _, c := range m.cfg.Categories {
		if strings.EqualFold(strings.TrimSpace(c), f.Category) {
			return true, "config_category"
		}
	}
	return false, ""
}

func ParseInlineDirectives(line string, pendingNext []string) (active []string, nextPending []string) {
	active = append(active, pendingNext...)
	lower := strings.ToLower(line)

	ignoreNext := extractDirectiveArg(lower, "cryptodiff:ignore-next-line")
	if ignoreNext.found {
		nextPending = append(nextPending, normalizePattern(ignoreNext.arg))
		// Prevent overlap where "cryptodiff:ignore-next-line" is parsed again as "cryptodiff:ignore".
		lower = strings.ReplaceAll(lower, "cryptodiff:ignore-next-line", "")
	}

	ignore := extractDirectiveArg(lower, "cryptodiff:ignore")
	if ignore.found {
		active = append(active, normalizePattern(ignore.arg))
	}
	return active, nextPending
}

func extractDirectiveArg(line string, directive string) struct {
	found bool
	arg   string
} {
	idx := strings.Index(line, directive)
	if idx < 0 {
		return struct {
			found bool
			arg   string
		}{}
	}
	rest := strings.TrimSpace(line[idx+len(directive):])
	if rest == "" {
		return struct {
			found bool
			arg   string
		}{found: true, arg: "*"}
	}
	token := strings.Fields(rest)[0]
	return struct {
		found bool
		arg   string
	}{found: true, arg: token}
}

func normalizePattern(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "*"
	}
	return strings.ToUpper(strings.Trim(p, `"'`))
}

func patternMatchesRule(pattern, ruleID string) bool {
	p := normalizePattern(pattern)
	r := strings.ToUpper(strings.TrimSpace(ruleID))
	if p == "*" {
		return true
	}
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(r, strings.TrimSuffix(p, "*"))
	}
	return p == r
}

func loadIgnorePatterns(repoRoot, ignoreFile string) []string {
	if strings.TrimSpace(ignoreFile) == "" {
		return nil
	}
	path := filepath.Join(repoRoot, ignoreFile)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	out := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func compileGlobs(patterns []string, source string) ([]pathglob.Pattern, error) {
	compiled := make([]pathglob.Pattern, 0, len(patterns))
	for _, p := range patterns {
		raw := strings.TrimSpace(p)
		pp, ok, err := pathglob.Compile(raw)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid glob %q: %w", source, raw, err)
		}
		if !ok {
			return nil, fmt.Errorf("%s contains invalid glob %q", source, raw)
		}
		compiled = append(compiled, pp)
	}
	return compiled, nil
}
