package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cryptoposture/cryptodiff/internal/config"
	"github.com/cryptoposture/cryptodiff/internal/model"
	"github.com/cryptoposture/cryptodiff/internal/pathglob"
	"github.com/cryptoposture/cryptodiff/internal/suppress"
)

const toolVersion = "0.2.0-dev"

var (
	tlsMinVersionPattern      = regexp.MustCompile(`(?i)(?:tls(?:[_\.\- ]?(?:min(?:imum)?[_\.\- ]?)?version)|min[_\.\- ]?tls[_\.\- ]?version|ssl_protocols)\s*[:= ]\s*["']?(tlsv1(?:\.0|\.1)?|1\.[01])\b`)
	tlsWeakCipherPattern      = regexp.MustCompile(`(?i)(?:cipher|ciphers|cipher[_\.\- ]?suite|ciphersuites|ssl[_\.\- ]?ciphers)[^\n]*\b(rc4|3des|des|null|export|anon)\b`)
	certVerifyDisabledPattern = regexp.MustCompile(`(?i)(insecureskipverify\s*[:=]\s*true|verify(?:_peer)?\s*[:=]\s*false|rejectunauthorized\s*[:=]\s*false|ssl[_\.\- ]?verify\s*[:=]\s*false|certificateverification\s*[:=]\s*none)`)
	disallowedAlgPattern      = regexp.MustCompile(`(?i)\b(3des|md5|sha1|des|rc4)\b`)
	rsaKeySizePattern         = regexp.MustCompile(`(?i)(?:rsa(?:[_\.\- ]?(?:key)?[_\.\- ]?size)|modulus[_\.\- ]?bits|key[_\.\- ]?size)\s*[:= ]\s*["']?([0-9]{3,5})\b`)
	rsaInlineWeakBitsPattern  = regexp.MustCompile(`(?i)\brsa\b[^\n]{0,40}\b(512|768|1024|1536)\b`)
)

var supportedExtensions = map[string]struct{}{
	".c": {}, ".cc": {}, ".cfg": {}, ".cnf": {}, ".conf": {}, ".cpp": {}, ".cs": {}, ".env": {}, ".go": {}, ".h": {}, ".hpp": {},
	".ini": {}, ".java": {}, ".js": {}, ".json": {}, ".kts": {}, ".kt": {}, ".php": {}, ".properties": {}, ".py": {}, ".rb": {},
	".scala": {}, ".swift": {}, ".tf": {}, ".toml": {}, ".ts": {}, ".tsx": {}, ".xml": {}, ".yaml": {}, ".yml": {},
}

func Run(repo string, cfg config.Config) (model.Posture, error) {
	absRepo, err := filepath.Abs(repo)
	if err != nil {
		return model.Posture{}, err
	}

	source := model.Source{
		RepoPath: absRepo,
		Commit:   gitValue(absRepo, "rev-parse", "HEAD"),
		Ref:      gitValue(absRepo, "rev-parse", "--abbrev-ref", "HEAD"),
	}

	findingByFingerprint, suppressionCounts, scanErrors, err := scanRepository(absRepo, cfg)
	if err != nil {
		return model.Posture{}, err
	}
	findings := sortedFindings(findingByFingerprint)
	return buildPosture(source, findings, suppressionCounts, scanErrors), nil
}

func scanRepository(absRepo string, cfg config.Config) (map[string]model.Finding, map[string]int, []model.ScanError, error) {
	scope, err := newPathScopeMatcher(cfg.Scan.Include, cfg.Scan.Exclude)
	if err != nil {
		return nil, nil, nil, err
	}
	state := repoScanState{
		absRepo:             absRepo,
		maxFileBytes:        cfg.Scan.MaxFileBytes,
		scope:               scope,
		findingByFingerprint: map[string]model.Finding{},
		suppressionCounts:   map[string]int{},
		scanErrors:          []model.ScanError{},
	}
	matcher, err := suppress.NewMatcher(absRepo, cfg.Suppress)
	if err != nil {
		return nil, nil, nil, err
	}
	state.suppressMatcher = matcher

	err = filepath.WalkDir(absRepo, state.handlePath)
	if err != nil {
		return nil, nil, nil, err
	}
	return state.findingByFingerprint, state.suppressionCounts, sortedScanErrors(state.scanErrors), nil
}

type repoScanState struct {
	absRepo              string
	maxFileBytes         int64
	scope                pathScopeMatcher
	suppressMatcher      *suppress.Matcher
	findingByFingerprint map[string]model.Finding
	suppressionCounts    map[string]int
	scanErrors           []model.ScanError
}

func (s *repoScanState) handlePath(path string, d os.DirEntry, walkErr error) error {
	if walkErr != nil {
		s.recordScanError(path, "walk", walkErr)
		return nil
	}
	rel, ok := s.relativePath(path)
	if !ok {
		return nil
	}
	if isSymlinkEntry(d) {
		s.recordScanError(rel, "scan_symlink_skipped", fmt.Errorf("symlink entries are not scanned"))
		return nil
	}
	if d.IsDir() {
		if rel == "." {
			return nil
		}
		if !s.scope.ShouldEnterDir(rel) {
			return filepath.SkipDir
		}
		return nil
	}
	if !s.scope.ShouldScanFile(rel) || !isCandidateFile(path, s.maxFileBytes) {
		return nil
	}
	if suppressed, reason := s.suppressMatcher.SuppressPathReason(rel); suppressed {
		s.bumpSuppression(reason)
		return nil
	}

	fileFindings, fileSuppressionCounts, err := scanFile(path, rel, s.suppressMatcher)
	s.mergeSuppressionCounts(fileSuppressionCounts)
	s.addFindings(fileFindings)
	if err != nil {
		s.recordScanError(rel, "scan_file", err)
	}
	return nil
}

func (s *repoScanState) relativePath(path string) (string, bool) {
	rel, err := filepath.Rel(s.absRepo, path)
	if err != nil {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

func (s *repoScanState) bumpSuppression(reason string) {
	if reason == "" {
		return
	}
	s.suppressionCounts[reason]++
}

func (s *repoScanState) mergeSuppressionCounts(counts map[string]int) {
	for k, v := range counts {
		s.suppressionCounts[k] += v
	}
}

func (s *repoScanState) addFindings(findings []model.Finding) {
	for _, f := range findings {
		existing, ok := s.findingByFingerprint[f.Fingerprint]
		if !ok {
			s.findingByFingerprint[f.Fingerprint] = f
			continue
		}
		existing.Evidence = mergeEvidence(existing.Evidence, f.Evidence)
		s.findingByFingerprint[f.Fingerprint] = existing
	}
}

func (s *repoScanState) recordScanError(path, stage string, err error) {
	if err == nil {
		return
	}
	s.scanErrors = append(s.scanErrors, model.ScanError{
		Path:    s.normalizeScanErrorPath(path),
		Stage:   strings.TrimSpace(stage),
		Message: strings.TrimSpace(err.Error()),
	})
}

func (s *repoScanState) normalizeScanErrorPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if rel, ok := s.relativePath(trimmed); ok {
		if rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
			return rel
		}
	}
	base := strings.TrimSpace(filepath.Base(filepath.ToSlash(trimmed)))
	if base == "." {
		return ""
	}
	return base
}

func mergeEvidence(existing, incoming []model.Evidence) []model.Evidence {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	out := make([]model.Evidence, 0, len(existing)+len(incoming))
	for _, e := range existing {
		key := evidenceKey(e)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	for _, e := range incoming {
		key := evidenceKey(e)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, e)
	}
	return out
}

func evidenceKey(e model.Evidence) string {
	return strings.ToLower(strings.TrimSpace(e.Path)) + "|" +
		strconv.Itoa(e.Line) + "|" +
		strings.TrimSpace(e.SnippetHash)
}

func sortedFindings(findingByFingerprint map[string]model.Finding) []model.Finding {
	findings := make([]model.Finding, 0, len(findingByFingerprint))
	for _, f := range findingByFingerprint {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Fingerprint != findings[j].Fingerprint {
			return findings[i].Fingerprint < findings[j].Fingerprint
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Subject < findings[j].Subject
	})
	return findings
}

func buildPosture(source model.Source, findings []model.Finding, suppressionCounts map[string]int, scanErrors []model.ScanError) model.Posture {
	return model.Posture{
		SchemaVersion: "0.2.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: toolVersion,
		},
		Summary: model.PostureSummary{
			Findings:   len(findings),
			Suppressed: totalSuppressed(suppressionCounts),
			ScanErrors: len(scanErrors),
		},
		Suppressions: model.SuppressionSummary{
			Inline:         suppressionCounts["inline"],
			IgnoreFile:     suppressionCounts["ignore_file"],
			ConfigPath:     suppressionCounts["config_path"],
			ConfigRule:     suppressionCounts["config_rule"],
			ConfigCategory: suppressionCounts["config_category"],
		},
		Source:     source,
		ScanErrors: scanErrors,
		Findings:   findings,
	}
}

func scanFile(path, relPath string, suppressMatcher *suppress.Matcher) ([]model.Finding, map[string]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}
	if !utf8.Valid(b) {
		return nil, nil, fmt.Errorf("file is not valid UTF-8")
	}

	var findings []model.Finding
	suppressionCounts := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64*1024), len(b)+1)
	lineNo := 0
	pendingNext := []string{}
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		inlineDirectives, nextPending := suppress.ParseInlineDirectives(line, pendingNext)
		pendingNext = nextPending
		for _, f := range detectFindingsInLine(relPath, lineNo, line) {
			if ok, reason := suppressMatcher.SuppressFindingReason(f, inlineDirectives); ok {
				suppressionCounts[reason]++
				continue
			}
			findings = append(findings, f)
		}
	}
	return findings, suppressionCounts, sc.Err()
}

func sortedScanErrors(in []model.ScanError) []model.ScanError {
	out := make([]model.ScanError, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].Stage != out[j].Stage {
			return out[i].Stage < out[j].Stage
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func detectFindingsInLine(relPath string, lineNo int, line string) []model.Finding {
	out := []model.Finding{}
	if match := tlsMinVersionPattern.FindStringSubmatch(line); len(match) > 1 {
		value := strings.ToLower(strings.TrimSpace(match[1]))
		out = append(out, newFinding(
			"CRYPTO.TLS.MIN_VERSION",
			"high",
			"tls",
			"high",
			fmt.Sprintf("Minimum TLS version set to %s", value),
			relPath,
			lineNo,
			line,
			map[string]any{
				"attribute":     "minVersion",
				"detectedValue": value,
			},
		))
	}
	if match := tlsWeakCipherPattern.FindStringSubmatch(line); len(match) > 1 {
		cipher := strings.ToLower(strings.TrimSpace(match[len(match)-1]))
		out = append(out, newFinding(
			"CRYPTO.TLS.WEAK_CIPHER",
			"high",
			"tls",
			"high",
			fmt.Sprintf("Weak TLS cipher configured: %s", cipher),
			relPath,
			lineNo,
			line,
			map[string]any{
				"attribute":     "cipher",
				"detectedValue": cipher,
			},
		))
	}
	if certVerifyDisabledPattern.MatchString(line) {
		detected := strings.TrimSpace(certVerifyDisabledPattern.FindString(line))
		out = append(out, newFinding(
			"CRYPTO.CERT.VERIFY_DISABLED",
			"critical",
			"pki",
			"high",
			"Certificate verification appears disabled",
			relPath,
			lineNo,
			line,
			map[string]any{
				"attribute":     "verify",
				"detectedValue": strings.ToLower(detected),
			},
		))
	}
	for _, bits := range weakRSAKeyBits(line) {
		out = append(out, newFinding(
			"CRYPTO.KEY.WEAK_SIZE",
			"high",
			"algorithm",
			"medium",
			fmt.Sprintf("Weak RSA key size detected: %d", bits),
			relPath,
			lineNo,
			line,
			map[string]any{
				"attribute":     "keySize",
				"detectedValue": fmt.Sprintf("%d", bits),
			},
		))
	}
	for _, m := range disallowedAlgPattern.FindAllString(line, -1) {
		value := strings.ToLower(strings.TrimSpace(m))
		out = append(out, newFinding(
			"CRYPTO.ALG.DISALLOWED",
			"critical",
			"algorithm",
			"medium",
			fmt.Sprintf("Disallowed algorithm reference: %s", value),
			relPath,
			lineNo,
			line,
			map[string]any{
				"attribute":     "name",
				"detectedValue": value,
			},
		))
	}
	return out
}

func weakRSAKeyBits(line string) []int {
	out := []int{}
	seen := map[int]struct{}{}

	appendBitsFromMatches(&out, seen, rsaKeySizePattern.FindAllStringSubmatch(line, -1), func(bits int) bool {
		return bits > 0 && bits < 2048
	})
	appendBitsFromMatches(&out, seen, rsaInlineWeakBitsPattern.FindAllStringSubmatch(line, -1), func(bits int) bool {
		return bits > 0
	})
	return out
}

func appendBitsFromMatches(out *[]int, seen map[int]struct{}, matches [][]string, allow func(int) bool) {
	for _, m := range matches {
		bits, ok := bitsFromMatch(m)
		if !ok || !allow(bits) {
			continue
		}
		if _, exists := seen[bits]; exists {
			continue
		}
		seen[bits] = struct{}{}
		*out = append(*out, bits)
	}
}

func bitsFromMatch(m []string) (int, bool) {
	if len(m) < 2 {
		return 0, false
	}
	bits, err := strconv.Atoi(strings.TrimSpace(m[1]))
	if err != nil {
		return 0, false
	}
	return bits, true
}

func newFinding(ruleID, severity, category, confidence, subject, relPath string, lineNo int, sourceLine string, attrs map[string]any) model.Finding {
	fp := fingerprint(ruleID, relPath, subject)
	evidence := model.Evidence{
		Path:        relPath,
		Line:        lineNo,
		SnippetHash: sha256Hex(sourceLine),
	}

	return model.Finding{
		ID:          "finding-" + fp[:12],
		RuleID:      ruleID,
		Severity:    severity,
		Category:    category,
		Confidence:  confidence,
		Subject:     subject,
		Attributes:  attrs,
		Evidence:    []model.Evidence{evidence},
		Fingerprint: fp,
	}
}

func fingerprint(ruleID, path, subject string) string {
	raw := strings.ToLower(strings.TrimSpace(ruleID)) + "|" +
		strings.ToLower(strings.TrimSpace(filepath.ToSlash(path))) + "|" +
		strings.ToLower(strings.TrimSpace(subject))
	return sha256Hex(raw)
}

func sha256Hex(in string) string {
	h := sha256.Sum256([]byte(in))
	return hex.EncodeToString(h[:])
}

func gitValue(dir string, args ...string) string {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

type pathScopeMatcher struct {
	include []pathglob.Pattern
	exclude []pathglob.Pattern
}

func newPathScopeMatcher(include, exclude []string) (pathScopeMatcher, error) {
	inc, err := compileScopePatterns(include)
	if err != nil {
		return pathScopeMatcher{}, err
	}
	exc, err := compileScopePatterns(exclude)
	if err != nil {
		return pathScopeMatcher{}, err
	}
	return pathScopeMatcher{include: inc, exclude: exc}, nil
}

func compileScopePatterns(globs []string) ([]pathglob.Pattern, error) {
	return pathglob.CompileAll(globs)
}

func (m pathScopeMatcher) ShouldEnterDir(relDir string) bool {
	return !m.matches(relDir, true, m.exclude)
}

func (m pathScopeMatcher) ShouldScanFile(relPath string) bool {
	if m.matches(relPath, false, m.exclude) {
		return false
	}
	if len(m.include) == 0 {
		return true
	}
	return m.matches(relPath, false, m.include)
}

func (m pathScopeMatcher) matches(relPath string, isDir bool, patterns []pathglob.Pattern) bool {
	return pathglob.MatchAny(patterns, relPath, isDir)
}

func isCandidateFile(path string, maxBytes int64) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := supportedExtensions[ext]; !ok {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() <= maxBytes
}

func totalSuppressed(counts map[string]int) int {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total
}

func isSymlinkEntry(d os.DirEntry) bool {
	return d != nil && d.Type()&os.ModeSymlink != 0
}
