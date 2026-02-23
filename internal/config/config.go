package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Version  string   `yaml:"version"`
	Scan     Scan     `yaml:"scan"`
	Outputs  Outputs  `yaml:"outputs"`
	Policy   Policy   `yaml:"policy"`
	Suppress Suppress `yaml:"suppress"`
}

type Scan struct {
	Include      []string `yaml:"include"`
	Exclude      []string `yaml:"exclude"`
	MaxFileBytes int64    `yaml:"maxFileBytes"`
	FailOnError  bool     `yaml:"failOnError"`
}

type Outputs struct {
	OutDir string `yaml:"outDir"`
}

type Policy struct {
	Mode      string `yaml:"mode"`
	FailLevel string `yaml:"failLevel"`
}

type Suppress struct {
	IgnoreFile string   `yaml:"ignoreFile"`
	Rules      []string `yaml:"rules"`
	Categories []string `yaml:"categories"`
	Paths      []string `yaml:"paths"`
}

func Default() Config {
	return Config{
		Version: "0.2",
		Scan: Scan{
			Include: []string{"**/*"},
			Exclude: []string{
				"**/.git/**",
				"**/.ai-helper-files/**",
				"**/node_modules/**",
				"**/vendor/**",
				"**/dist/**",
				"**/build/**",
				"**/target/**",
			},
			MaxFileBytes: 2_000_000,
		},
		Outputs: Outputs{OutDir: "cryptodiff-out"},
		Policy: Policy{
			Mode:      "report",
			FailLevel: "high",
		},
		Suppress: Suppress{
			IgnoreFile: ".cryptodiffignore",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		ApplyEnv(&cfg)
		return cfg, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ApplyEnv(&cfg)
			return cfg, nil
		}
		return Config{}, err
	}

	loaded, err := parseLightweightYAML(string(b))
	if err != nil {
		return Config{}, err
	}
	mergeDefaults(&cfg, loaded)
	ApplyEnv(&cfg)
	return cfg, nil
}

// ApplyEnv applies environment variable overrides to config values.
// This enforces env > file/default precedence for supported fields.
func ApplyEnv(cfg *Config) {
	if cfg == nil {
		return
	}
	if v, ok := envString("CRYPTODIFF_OUT_DIR"); ok {
		cfg.Outputs.OutDir = v
	}
	if v, ok := envString("CRYPTODIFF_POLICY_MODE"); ok {
		cfg.Policy.Mode = v
	}
	if v, ok := envString("CRYPTODIFF_FAIL_LEVEL"); ok {
		cfg.Policy.FailLevel = v
	}
	if v, ok := envInt64("CRYPTODIFF_SCAN_MAX_FILE_BYTES"); ok && v > 0 {
		cfg.Scan.MaxFileBytes = v
	}
	if v, ok := envBool("CRYPTODIFF_SCAN_FAIL_ON_ERROR"); ok {
		cfg.Scan.FailOnError = v
	}
	if v, ok := envCSV("CRYPTODIFF_SCAN_INCLUDE"); ok {
		cfg.Scan.Include = v
	}
	if v, ok := envCSV("CRYPTODIFF_SCAN_EXCLUDE"); ok {
		cfg.Scan.Exclude = v
	}
	if v, ok := envString("CRYPTODIFF_SUPPRESS_IGNORE_FILE"); ok {
		cfg.Suppress.IgnoreFile = v
	}
	if v, ok := envCSV("CRYPTODIFF_SUPPRESS_RULES"); ok {
		cfg.Suppress.Rules = v
	}
	if v, ok := envCSV("CRYPTODIFF_SUPPRESS_CATEGORIES"); ok {
		cfg.Suppress.Categories = v
	}
	if v, ok := envCSV("CRYPTODIFF_SUPPRESS_PATHS"); ok {
		cfg.Suppress.Paths = v
	}
}

func mergeDefaults(dst *Config, src Config) {
	if src.Version != "" {
		dst.Version = src.Version
	}
	if len(src.Scan.Include) > 0 {
		dst.Scan.Include = src.Scan.Include
	}
	if len(src.Scan.Exclude) > 0 {
		dst.Scan.Exclude = src.Scan.Exclude
	}
	if src.Scan.MaxFileBytes > 0 {
		dst.Scan.MaxFileBytes = src.Scan.MaxFileBytes
	}
	if src.Scan.FailOnError {
		dst.Scan.FailOnError = src.Scan.FailOnError
	}
	if src.Outputs.OutDir != "" {
		dst.Outputs.OutDir = src.Outputs.OutDir
	}
	if src.Policy.Mode != "" {
		dst.Policy.Mode = src.Policy.Mode
	}
	if src.Policy.FailLevel != "" {
		dst.Policy.FailLevel = src.Policy.FailLevel
	}
	if src.Suppress.IgnoreFile != "" {
		dst.Suppress.IgnoreFile = src.Suppress.IgnoreFile
	}
	if len(src.Suppress.Rules) > 0 {
		dst.Suppress.Rules = src.Suppress.Rules
	}
	if len(src.Suppress.Categories) > 0 {
		dst.Suppress.Categories = src.Suppress.Categories
	}
	if len(src.Suppress.Paths) > 0 {
		dst.Suppress.Paths = src.Suppress.Paths
	}
}

// parseLightweightYAML handles a tiny subset of YAML used by the v0 scaffold.
// It supports:
// - top-level "version"
// - scan.maxFileBytes, scan.failOnError, scan.include, scan.exclude
// - outputs.outDir
// - policy.mode, policy.failLevel
// - suppress.ignoreFile, suppress.rules, suppress.categories, suppress.paths
func parseLightweightYAML(s string) (Config, error) {
	p := lightweightConfigParser{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if err := p.consumeLine(sc.Text()); err != nil {
			return Config{}, err
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return p.out, nil
}

type lightweightConfigParser struct {
	out     Config
	section string
	listKey string
	lineNo  int
}

func (p *lightweightConfigParser) consumeLine(rawLine string) error {
	p.lineNo++
	line := strings.TrimSpace(rawLine)
	if isIgnoredYAMLLine(line) {
		return nil
	}
	if handled, err := p.handleTopLevel(rawLine, line); handled || err != nil {
		return err
	}
	if item, ok := parseYAMLListItem(line); ok {
		return p.handleListItem(item)
	}
	key, value, ok := parseYAMLKeyValue(line)
	if !ok {
		return lineErr(p.lineNo, "invalid YAML line")
	}
	return p.handleKeyValue(key, value)
}

func (p *lightweightConfigParser) handleTopLevel(rawLine, line string) (bool, error) {
	if !isTopLevelLine(rawLine) {
		return false, nil
	}
	p.section = ""
	p.listKey = ""
	if !strings.HasSuffix(line, ":") || strings.Contains(line, " ") {
		return false, nil
	}
	if nextSection, ok := parseSectionHeader(rawLine, line); ok {
		p.section = nextSection
		return true, nil
	}
	return true, lineErr(p.lineNo, "unknown top-level section %q", strings.TrimSuffix(line, ":"))
}

func (p *lightweightConfigParser) handleListItem(item string) error {
	if p.listKey == "" {
		return lineErr(p.lineNo, "list item found outside of list context")
	}
	if err := applyLightweightListItem(&p.out, p.section, p.listKey, item); err != nil {
		return lineErr(p.lineNo, "%v", err)
	}
	return nil
}

func (p *lightweightConfigParser) handleKeyValue(key, value string) error {
	if !isAllowedKey(p.section, key) {
		if p.section == "" {
			return lineErr(p.lineNo, "unknown top-level key %q", key)
		}
		return lineErr(p.lineNo, "unknown key %q in section %q", key, p.section)
	}
	if value == "" && isListKey(p.section, key) {
		p.listKey = key
		return nil
	}
	if value == "" && p.section != "" {
		return lineErr(p.lineNo, "empty value for %s.%s", p.section, key)
	}
	p.listKey = ""
	if err := applyLightweightKV(&p.out, p.section, key, value); err != nil {
		return lineErr(p.lineNo, "%v", err)
	}
	return nil
}

func isIgnoredYAMLLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

func parseSectionHeader(rawLine string, trimmedLine string) (string, bool) {
	if !isTopLevelLine(rawLine) {
		return "", false
	}
	trimmed := strings.TrimSpace(trimmedLine)
	if strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, " ") {
		switch strings.TrimSuffix(trimmed, ":") {
		case "scan", "outputs", "policy", "suppress":
			return strings.TrimSuffix(trimmed, ":"), true
		}
	}
	return "", false
}

func isTopLevelLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return len(line) > 0 && line[0] != ' ' && line[0] != '\t'
}

func parseYAMLKeyValue(line string) (string, string, bool) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	return key, value, true
}

func parseYAMLListItem(line string) (string, bool) {
	if !strings.HasPrefix(line, "-") {
		return "", false
	}
	item := strings.TrimSpace(strings.TrimPrefix(line, "-"))
	item = strings.Trim(item, `"'`)
	if item == "" {
		return "", false
	}
	return item, true
}

func isListKey(section, key string) bool {
	switch section {
	case "scan":
		return key == "include" || key == "exclude"
	case "suppress":
		return key == "rules" || key == "categories" || key == "paths"
	default:
		return false
	}
}

func applyLightweightKV(out *Config, section, key, value string) error {
	switch section {
	case "":
		applyTopLevelKV(out, key, value)
	case "scan":
		return applyScanKV(out, key, value)
	case "outputs":
		applyOutputsKV(out, key, value)
	case "policy":
		applyPolicyKV(out, key, value)
	case "suppress":
		applySuppressKV(out, key, value)
	}
	return nil
}

func applyTopLevelKV(out *Config, key, value string) {
	if key == "version" {
		out.Version = value
	}
}

func applyScanKV(out *Config, key, value string) error {
	switch key {
	case "include":
		out.Scan.Include = parseListValue(value)
	case "exclude":
		out.Scan.Exclude = parseListValue(value)
	case "maxFileBytes":
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("scan.maxFileBytes must be a positive integer")
		}
		out.Scan.MaxFileBytes = n
	case "failOnError":
		v, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(value)))
		if err != nil {
			return fmt.Errorf("scan.failOnError must be true or false")
		}
		out.Scan.FailOnError = v
	}
	return nil
}

func applyOutputsKV(out *Config, key, value string) {
	if key == "outDir" {
		out.Outputs.OutDir = value
	}
}

func applyPolicyKV(out *Config, key, value string) {
	switch key {
	case "mode":
		out.Policy.Mode = value
	case "failLevel":
		out.Policy.FailLevel = value
	}
}

func applySuppressKV(out *Config, key, value string) {
	switch key {
	case "ignoreFile":
		out.Suppress.IgnoreFile = value
	case "rules":
		out.Suppress.Rules = parseListValue(value)
	case "categories":
		out.Suppress.Categories = parseListValue(value)
	case "paths":
		out.Suppress.Paths = parseListValue(value)
	}
}

func applyLightweightListItem(out *Config, section, key, item string) error {
	switch section {
	case "scan":
		switch key {
		case "include":
			out.Scan.Include = append(out.Scan.Include, item)
		case "exclude":
			out.Scan.Exclude = append(out.Scan.Exclude, item)
		default:
			return fmt.Errorf("unknown list key %q in section %q", key, section)
		}
	case "suppress":
		switch key {
		case "rules":
			out.Suppress.Rules = append(out.Suppress.Rules, item)
		case "categories":
			out.Suppress.Categories = append(out.Suppress.Categories, item)
		case "paths":
			out.Suppress.Paths = append(out.Suppress.Paths, item)
		default:
			return fmt.Errorf("unknown list key %q in section %q", key, section)
		}
	default:
		return fmt.Errorf("list item is not allowed in section %q", section)
	}
	return nil
}

func isAllowedKey(section, key string) bool {
	switch section {
	case "":
		return key == "version"
	case "scan":
		return key == "include" || key == "exclude" || key == "maxFileBytes" || key == "failOnError"
	case "outputs":
		return key == "outDir"
	case "policy":
		return key == "mode" || key == "failLevel"
	case "suppress":
		return key == "ignoreFile" || key == "rules" || key == "categories" || key == "paths"
	default:
		return false
	}
}

func lineErr(lineNo int, format string, args ...any) error {
	return fmt.Errorf("config parse error at line %d: %s", lineNo, fmt.Sprintf(format, args...))
}

func parseListValue(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"))
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.Trim(strings.TrimSpace(p), `"'`)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func envString(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

func envInt64(key string) (int64, bool) {
	v, ok := envString(key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func envCSV(key string) ([]string, bool) {
	v, ok := envString(key)
	if !ok {
		return nil, false
	}
	out := parseListValue(v)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func envBool(key string) (bool, bool) {
	v, ok := envString(key)
	if !ok {
		return false, false
	}
	b, err := strconv.ParseBool(strings.ToLower(v))
	if err != nil {
		return false, false
	}
	return b, true
}
