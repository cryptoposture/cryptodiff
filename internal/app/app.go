package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cryptoposture/cryptodiff/internal/audit"
	"github.com/cryptoposture/cryptodiff/internal/baseline"
	"github.com/cryptoposture/cryptodiff/internal/cbom"
	"github.com/cryptoposture/cryptodiff/internal/config"
	"github.com/cryptoposture/cryptodiff/internal/diff"
	"github.com/cryptoposture/cryptodiff/internal/exception"
	"github.com/cryptoposture/cryptodiff/internal/explain"
	"github.com/cryptoposture/cryptodiff/internal/model"
	"github.com/cryptoposture/cryptodiff/internal/policy"
	"github.com/cryptoposture/cryptodiff/internal/sarif"
	"github.com/cryptoposture/cryptodiff/internal/scan"
	"github.com/cryptoposture/cryptodiff/internal/validate"
)

func Run(args []string) int {
	if len(args) == 0 {
		printRootHelp()
		return 0
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "diff":
		return runDiff(args[1:])
	case "audit":
		return runAudit(args[1:])
	case "baseline":
		return runBaseline(args[1:])
	case "explain":
		return runExplain(args[1:])
	case "-h", "--help", "help":
		printRootHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printRootHelp()
		return 2
	}
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	repo := fs.String("repo", ".", "Repository path to scan")
	outDir := fs.String("out-dir", "", "Output directory for artifacts")
	configPath := fs.String("config", "cryptodiff.yaml", "Path to cryptodiff config file")
	include := fs.String("include", "", "Comma-separated include glob patterns for files/paths")
	exclude := fs.String("exclude", "", "Comma-separated exclude glob patterns for files/paths")
	strictScanErrors := fs.Bool("strict-scan-errors", false, "Fail scan if any file/path scan errors are encountered")
	baseRef := fs.String("base-ref", "", "Optional git base ref for range scan mode")
	headRef := fs.String("head-ref", "", "Optional git head ref for range scan mode")
	emitSARIF := fs.Bool("sarif", true, "Emit posture.sarif")
	emitCBOM := fs.Bool("cbom", true, "Emit cbom.json (CycloneDX)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := visitSetFlags(fs)
	cfg, err := loadCommandConfig(setFlags, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		return 2
	}
	resolvedRepo := resolveString(setFlags, "repo", *repo, "CRYPTODIFF_REPO", ".")
	resolvedBaseRef := resolveString(setFlags, "base-ref", *baseRef, "CRYPTODIFF_BASE_REF", "")
	resolvedHeadRef := resolveString(setFlags, "head-ref", *headRef, "CRYPTODIFF_HEAD_REF", "")
	resolvedSARIF := resolveBool(setFlags, "sarif", *emitSARIF, "CRYPTODIFF_SARIF", true)
	resolvedCBOM := resolveBool(setFlags, "cbom", *emitCBOM, "CRYPTODIFF_CBOM", true)
	if setFlags["include"] {
		values := parseCSV(*include)
		if len(values) > 0 {
			cfg.Scan.Include = values
		}
	}
	if setFlags["exclude"] {
		values := parseCSV(*exclude)
		if len(values) > 0 {
			cfg.Scan.Exclude = values
		}
	}
	if setFlags["strict-scan-errors"] {
		cfg.Scan.FailOnError = *strictScanErrors
	}

	resolvedOutDir := resolveString(setFlags, "out-dir", *outDir, "CRYPTODIFF_OUT_DIR", cfg.Outputs.OutDir)

	hasBase := strings.TrimSpace(resolvedBaseRef) != ""
	hasHead := strings.TrimSpace(resolvedHeadRef) != ""
	if hasBase != hasHead {
		fmt.Fprintln(os.Stderr, "both --base-ref and --head-ref are required when using range scan mode")
		return 2
	}

	if hasBase && hasHead {
		if err := runRangeScan(resolvedRepo, resolvedOutDir, resolvedBaseRef, resolvedHeadRef, cfg, resolvedSARIF, resolvedCBOM); err != nil {
			fmt.Fprintf(os.Stderr, "range scan failed: %v\n", err)
			return 2
		}
		return 0
	}

	posture, posturePath, err := runScanForRepo(resolvedRepo, resolvedOutDir, cfg, resolvedSARIF, resolvedCBOM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}
	fmt.Printf("wrote %s (%d findings)\n", posturePath, len(posture.Findings))
	return 0
}

func printRootHelp() {
	fmt.Println("cryptodiff - crypto posture diff tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cryptodiff <command> [flags]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  scan      Scan repository and emit posture.json, posture.sarif, cbom.json")
	fmt.Println("  diff      Compute posture diff and emit diff.json/diff.md")
	fmt.Println("  audit     Evaluate policy with optional baseline/exceptions and emit audit.json")
	fmt.Println("  baseline  Create baseline json from snapshot or audit output")
	fmt.Println("  explain   Render human-readable details for a finding")
}

func runDiff(args []string) int {
	opts, err := parseRunDiffArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	report, err := buildDiffReport(opts.basePath, opts.headPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	written, err := writeDiffArtifacts(report, opts.outDir, opts.format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	fmt.Printf("wrote %s\n", strings.Join(written, " and "))
	return 0
}

type runDiffOptions struct {
	basePath string
	headPath string
	outDir   string
	format   string
}

func parseRunDiffArgs(args []string) (runDiffOptions, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	basePath := fs.String("base", "", "Path to base posture.json")
	headPath := fs.String("head", "", "Path to head posture.json")
	outDir := fs.String("out-dir", "cryptodiff-out", "Output directory for diff artifacts")
	format := fs.String("format", "both", "Output format: json|md|both")

	if err := fs.Parse(args); err != nil {
		return runDiffOptions{}, err
	}
	if strings.TrimSpace(*basePath) == "" || strings.TrimSpace(*headPath) == "" {
		return runDiffOptions{}, fmt.Errorf("both --base and --head are required")
	}
	setFlags := visitSetFlags(fs)
	resolvedFormat := resolveString(setFlags, "format", *format, "CRYPTODIFF_DIFF_FORMAT", "both")
	resolvedFormat = normalizeDiffFormat(resolvedFormat)
	if resolvedFormat == "" {
		return runDiffOptions{}, fmt.Errorf("invalid --format; supported values: json, md, both")
	}
	return runDiffOptions{
		basePath: strings.TrimSpace(*basePath),
		headPath: strings.TrimSpace(*headPath),
		outDir:   resolveString(setFlags, "out-dir", *outDir, "CRYPTODIFF_OUT_DIR", "cryptodiff-out"),
		format:   resolvedFormat,
	}, nil
}

func buildDiffReport(basePath, headPath string) (model.DiffReport, error) {
	base, err := diff.LoadPosture(basePath)
	if err != nil {
		return model.DiffReport{}, fmt.Errorf("failed to read base posture file: %v", err)
	}
	head, err := diff.LoadPosture(headPath)
	if err != nil {
		return model.DiffReport{}, fmt.Errorf("failed to read head posture file: %v", err)
	}
	report := diff.Compare(base, head)
	if err := validate.Diff(report); err != nil {
		return model.DiffReport{}, fmt.Errorf("invalid diff artifact: %v", err)
	}
	if err := validate.ArtifactAgainstEmbeddedSchema("diff.schema.json", report); err != nil {
		return model.DiffReport{}, fmt.Errorf("diff schema validation failed: %v", err)
	}
	return report, nil
}

func writeDiffArtifacts(report model.DiffReport, outDir, format string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	diffJSONPath := filepath.Join(outDir, "diff.json")
	diffMDPath := filepath.Join(outDir, "diff.md")
	written := []string{}
	if format == "json" || format == "both" {
		j, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to encode diff report: %v", err)
		}
		j = append(j, '\n')
		if err := os.WriteFile(diffJSONPath, j, 0o644); err != nil {
			return nil, fmt.Errorf("failed to write diff.json: %v", err)
		}
		written = append(written, diffJSONPath)
	}
	if format == "md" || format == "both" {
		md := diff.Markdown(report)
		if err := os.WriteFile(diffMDPath, []byte(md), 0o644); err != nil {
			return nil, fmt.Errorf("failed to write diff.md: %v", err)
		}
		written = append(written, diffMDPath)
	}
	return written, nil
}

func normalizeDiffFormat(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "json":
		return "json"
	case "md", "markdown":
		return "md"
	case "", "both":
		return "both"
	default:
		return ""
	}
}

func runScanForRepo(repo, outDir string, cfg config.Config, emitSARIF, emitCBOM bool) (model.Posture, string, error) {
	posture, err := scan.Run(repo, cfg)
	if err != nil {
		return model.Posture{}, "", err
	}
	if err := validate.Posture(posture); err != nil {
		return model.Posture{}, "", fmt.Errorf("invalid posture artifact: %w", err)
	}
	if err := validate.ArtifactAgainstEmbeddedSchema("posture.schema.json", posture); err != nil {
		return model.Posture{}, "", fmt.Errorf("posture schema validation failed: %w", err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return model.Posture{}, "", fmt.Errorf("failed to create output directory: %w", err)
	}

	posturePath := filepath.Join(outDir, "posture.json")
	b, err := json.MarshalIndent(posture, "", "  ")
	if err != nil {
		return model.Posture{}, "", fmt.Errorf("failed to encode posture report: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(posturePath, b, 0o644); err != nil {
		return model.Posture{}, "", fmt.Errorf("failed to write posture report: %w", err)
	}
	if err := writeOptionalScanArtifacts(posture, outDir, emitSARIF, emitCBOM); err != nil {
		return model.Posture{}, "", err
	}
	if cfg.Scan.FailOnError && posture.Summary.ScanErrors > 0 {
		return posture, posturePath, fmt.Errorf("scan encountered %d file/path errors", posture.Summary.ScanErrors)
	}
	return posture, posturePath, nil
}

func writeOptionalScanArtifacts(posture model.Posture, outDir string, emitSARIF, emitCBOM bool) error {
	if emitSARIF {
		sarifPath := filepath.Join(outDir, "posture.sarif")
		sarifBytes, err := sarif.FromPosture(posture)
		if err != nil {
			return fmt.Errorf("failed to build SARIF report: %w", err)
		}
		sarifBytes = append(sarifBytes, '\n')
		if err := os.WriteFile(sarifPath, sarifBytes, 0o644); err != nil {
			return fmt.Errorf("failed to write SARIF report: %w", err)
		}
	}
	if emitCBOM {
		cbomPath := filepath.Join(outDir, "cbom.json")
		cbomBytes, err := cbom.FromPosture(posture)
		if err != nil {
			return fmt.Errorf("failed to build CBOM report: %w", err)
		}
		cbomBytes = append(cbomBytes, '\n')
		if err := os.WriteFile(cbomPath, cbomBytes, 0o644); err != nil {
			return fmt.Errorf("failed to write CBOM report: %w", err)
		}
	}
	return nil
}

func runRangeScan(repo, outDir, baseRef, headRef string, cfg config.Config, emitSARIF, emitCBOM bool) error {
	absRepo, err := filepath.Abs(repo)
	if err != nil {
		return err
	}
	tmpDir, err := os.MkdirTemp("", "cryptodiff-range-scan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	baseWT := filepath.Join(tmpDir, "base-wt")
	headWT := filepath.Join(tmpDir, "head-wt")
	cleanup := func(path string) {
		_ = exec.Command("git", "-C", absRepo, "worktree", "remove", "--force", path).Run()
	}
	defer cleanup(baseWT)
	defer cleanup(headWT)

	if out, err := exec.Command("git", "-C", absRepo, "worktree", "add", "--detach", baseWT, baseRef).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create base worktree: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("git", "-C", absRepo, "worktree", "add", "--detach", headWT, headRef).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create head worktree: %v (%s)", err, strings.TrimSpace(string(out)))
	}

	baseOut := filepath.Join(outDir, "base")
	headOut := filepath.Join(outDir, "head")
	basePosture, basePosturePath, err := runScanForRepo(baseWT, baseOut, cfg, emitSARIF, emitCBOM)
	if err != nil {
		return err
	}
	headPosture, headPosturePath, err := runScanForRepo(headWT, headOut, cfg, emitSARIF, emitCBOM)
	if err != nil {
		return err
	}

	report := diff.Compare(basePosture, headPosture)
	if err := validate.Diff(report); err != nil {
		return fmt.Errorf("invalid diff artifact: %w", err)
	}
	if err := validate.ArtifactAgainstEmbeddedSchema("diff.schema.json", report); err != nil {
		return fmt.Errorf("diff schema validation failed: %w", err)
	}

	diffJSONPath := filepath.Join(outDir, "diff.json")
	diffMDPath := filepath.Join(outDir, "diff.md")
	j, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode diff report: %w", err)
	}
	j = append(j, '\n')
	if err := os.WriteFile(diffJSONPath, j, 0o644); err != nil {
		return fmt.Errorf("failed to write diff.json: %w", err)
	}
	if err := os.WriteFile(diffMDPath, []byte(diff.Markdown(report)), 0o644); err != nil {
		return fmt.Errorf("failed to write diff.md: %w", err)
	}

	fmt.Printf("wrote %s (%d findings)\n", basePosturePath, len(basePosture.Findings))
	fmt.Printf("wrote %s (%d findings)\n", headPosturePath, len(headPosture.Findings))
	fmt.Printf("wrote %s and %s\n", diffJSONPath, diffMDPath)
	return nil
}

func runAudit(args []string) int {
	opts, err := parseRunAuditArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	policyDoc, err := policy.Load(opts.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policy: %v\n", err)
		return 2
	}

	report, err := evaluateAuditFromInput(opts, policyDoc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	report, err = applyAuditFilters(report, opts.baselinePath, opts.exceptionsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}

	if err := validate.Audit(report); err != nil {
		fmt.Fprintf(os.Stderr, "invalid audit artifact: %v\n", err)
		return 2
	}
	if err := validate.ArtifactAgainstEmbeddedSchema("audit.schema.json", report); err != nil {
		fmt.Fprintf(os.Stderr, "audit schema validation failed: %v\n", err)
		return 2
	}

	auditPath, err := writeAuditArtifact(report, opts.outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 2
	}
	fmt.Printf("wrote %s\n", auditPath)
	if report.Result == "fail" {
		return 1
	}
	return 0
}

type runAuditOptions struct {
	policyPath     string
	mode           string
	failLevel      string
	snapshotPath   string
	diffPath       string
	baselinePath   string
	exceptionsPath string
	outDir         string
}

func parseRunAuditArgs(args []string) (runAuditOptions, error) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configPath := fs.String("config", "cryptodiff.yaml", "Path to cryptodiff config file")
	policyPath := fs.String("policy", "policy/cryptodiff-policy.yaml", "Path to policy file")
	mode := fs.String("mode", "report", "Audit mode: report or gate")
	failLevel := fs.String("fail-level", "high", "Fail level: info|low|medium|high|critical")
	snapshotPath := fs.String("snapshot", "", "Path to posture.json")
	diffPath := fs.String("diff", "", "Path to diff.json")
	baselinePath := fs.String("baseline", "", "Optional path to baseline json")
	exceptionsPath := fs.String("exceptions", "", "Optional path to exceptions file (yaml/json)")
	outDir := fs.String("out-dir", "cryptodiff-out", "Output directory for audit artifact")

	if err := fs.Parse(args); err != nil {
		return runAuditOptions{}, err
	}
	setFlags := visitSetFlags(fs)
	cfg, err := loadCommandConfig(setFlags, *configPath)
	if err != nil {
		return runAuditOptions{}, fmt.Errorf("failed to load config: %v", err)
	}
	resolvedPolicyPath := resolveString(setFlags, "policy", *policyPath, "CRYPTODIFF_POLICY_FILE", "policy/cryptodiff-policy.yaml")
	resolvedMode := resolveString(setFlags, "mode", *mode, "CRYPTODIFF_POLICY_MODE", cfg.Policy.Mode)
	resolvedFailLevel := resolveString(setFlags, "fail-level", *failLevel, "CRYPTODIFF_FAIL_LEVEL", cfg.Policy.FailLevel)
	resolvedOutDir := resolveString(setFlags, "out-dir", *outDir, "CRYPTODIFF_OUT_DIR", cfg.Outputs.OutDir)

	hasSnapshot := strings.TrimSpace(*snapshotPath) != ""
	hasDiff := strings.TrimSpace(*diffPath) != ""
	if hasSnapshot == hasDiff {
		return runAuditOptions{}, fmt.Errorf("exactly one of --snapshot or --diff is required")
	}
	return runAuditOptions{
		policyPath:     resolvedPolicyPath,
		mode:           resolvedMode,
		failLevel:      resolvedFailLevel,
		snapshotPath:   strings.TrimSpace(*snapshotPath),
		diffPath:       strings.TrimSpace(*diffPath),
		baselinePath:   strings.TrimSpace(*baselinePath),
		exceptionsPath: strings.TrimSpace(*exceptionsPath),
		outDir:         resolvedOutDir,
	}, nil
}

func evaluateAuditFromInput(opts runAuditOptions, policyDoc model.Policy) (model.AuditReport, error) {
	evalOpts := audit.Options{
		Mode:      opts.mode,
		FailLevel: opts.failLevel,
	}
	if opts.snapshotPath != "" {
		posture, err := diff.LoadPosture(opts.snapshotPath)
		if err != nil {
			return model.AuditReport{}, fmt.Errorf("failed to read snapshot: %v", err)
		}
		return audit.EvaluateSnapshot(posture.Findings, policyDoc, evalOpts), nil
	}
	d, err := audit.LoadDiff(opts.diffPath)
	if err != nil {
		return model.AuditReport{}, fmt.Errorf("failed to read diff: %v", err)
	}
	return audit.EvaluateDiff(d, policyDoc, evalOpts), nil
}

func applyAuditFilters(report model.AuditReport, baselinePath, exceptionsPath string) (model.AuditReport, error) {
	if baselinePath != "" {
		before := len(report.Violations)
		b, err := baseline.Load(baselinePath)
		if err != nil {
			return model.AuditReport{}, fmt.Errorf("failed to load baseline: %v", err)
		}
		report = baseline.ApplyToAuditReport(report, b)
		report.Summary.Suppressed += before - len(report.Violations)
	}
	if exceptionsPath != "" {
		before := len(report.Violations)
		ex, err := exception.Load(exceptionsPath)
		if err != nil {
			return model.AuditReport{}, fmt.Errorf("failed to load exceptions: %v", err)
		}
		var stats exception.ApplyStats
		report, stats = exception.ApplyWithStats(report, ex, time.Now().UTC())
		report.Summary.Excepted += before - len(report.Violations)
		report.InvalidExceptions = stats.InvalidExceptions
	}
	return report, nil
}

func writeAuditArtifact(report model.AuditReport, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	auditPath := filepath.Join(outDir, "audit.json")
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to encode audit report: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(auditPath, b, 0o644); err != nil {
		return "", fmt.Errorf("failed to write audit report: %v", err)
	}
	return auditPath, nil
}

func runBaseline(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	snapshotPath := fs.String("snapshot", "", "Path to posture.json source")
	auditPath := fs.String("audit", "", "Path to audit.json source")
	writePath := fs.String("write", "baseline/cryptodiff-baseline.json", "Output baseline path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := visitSetFlags(fs)
	resolvedWritePath := resolveString(setFlags, "write", *writePath, "CRYPTODIFF_BASELINE_FILE", "baseline/cryptodiff-baseline.json")

	hasSnapshot := strings.TrimSpace(*snapshotPath) != ""
	hasAudit := strings.TrimSpace(*auditPath) != ""
	if hasSnapshot == hasAudit {
		fmt.Fprintln(os.Stderr, "exactly one of --snapshot or --audit is required")
		return 2
	}

	var out model.Baseline
	if hasSnapshot {
		p, err := diff.LoadPosture(*snapshotPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read snapshot: %v\n", err)
			return 2
		}
		out = baseline.BuildFromFindings(p.Findings)
	} else {
		var ar model.AuditReport
		raw, err := os.ReadFile(*auditPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read audit report: %v\n", err)
			return 2
		}
		if err := json.Unmarshal(raw, &ar); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse audit report: %v\n", err)
			return 2
		}
		out = baseline.BuildFromViolations(ar.Violations)
	}

	if err := os.MkdirAll(filepath.Dir(resolvedWritePath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create baseline directory: %v\n", err)
		return 2
	}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode baseline: %v\n", err)
		return 2
	}
	enc = append(enc, '\n')
	if err := os.WriteFile(resolvedWritePath, enc, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write baseline: %v\n", err)
		return 2
	}

	fmt.Printf("wrote %s (%d entries)\n", resolvedWritePath, len(out.Entries))
	return 0
}

func runExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	snapshotPath := fs.String("snapshot", "cryptodiff-out/posture.json", "Path to posture.json")
	findingID := fs.String("finding-id", "", "Finding ID to explain")
	fingerprint := fs.String("fingerprint", "", "Finding fingerprint to explain")
	ruleID := fs.String("rule-id", "", "Rule ID to explain (selects first matching finding)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	setFlags := visitSetFlags(fs)
	resolvedSnapshotPath := resolveString(setFlags, "snapshot", *snapshotPath, "CRYPTODIFF_SNAPSHOT_PATH", "cryptodiff-out/posture.json")

	selected := 0
	if strings.TrimSpace(*findingID) != "" {
		selected++
	}
	if strings.TrimSpace(*fingerprint) != "" {
		selected++
	}
	if strings.TrimSpace(*ruleID) != "" {
		selected++
	}
	if selected != 1 {
		fmt.Fprintln(os.Stderr, "exactly one selector is required: --finding-id, --fingerprint, or --rule-id")
		return 2
	}

	p, err := diff.LoadPosture(resolvedSnapshotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read snapshot: %v\n", err)
		return 2
	}

	f, ok := explain.SelectFinding(p, explain.Selector{
		FindingID:   strings.TrimSpace(*findingID),
		Fingerprint: strings.TrimSpace(*fingerprint),
		RuleID:      strings.TrimSpace(*ruleID),
	})
	if !ok {
		fmt.Fprintln(os.Stderr, "no matching finding found in snapshot")
		return 2
	}

	fmt.Print(explain.Render(f))
	return 0
}

func visitSetFlags(fs *flag.FlagSet) map[string]bool {
	out := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		out[f.Name] = true
	})
	return out
}

func resolveString(set map[string]bool, name string, flagValue string, envKey string, fallback string) string {
	if set[name] {
		v := strings.TrimSpace(flagValue)
		if v != "" {
			return v
		}
	}
	if v, ok := lookupEnvString(envKey); ok {
		return v
	}
	return strings.TrimSpace(fallback)
}

func loadCommandConfig(set map[string]bool, configFlagValue string) (config.Config, error) {
	resolvedConfigPath, explicitConfigPath := resolveConfigPath(set, configFlagValue)
	if explicitConfigPath {
		if _, err := os.Stat(resolvedConfigPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return config.Config{}, fmt.Errorf("explicit config path not found: %s", resolvedConfigPath)
			}
			return config.Config{}, fmt.Errorf("cannot access explicit config path %q: %w", resolvedConfigPath, err)
		}
	}
	return config.Load(resolvedConfigPath)
}

func resolveConfigPath(set map[string]bool, configFlagValue string) (string, bool) {
	if set["config"] {
		v := strings.TrimSpace(configFlagValue)
		if v != "" {
			return v, true
		}
	}
	if v, ok := lookupEnvString("CRYPTODIFF_CONFIG"); ok {
		return v, true
	}
	return "cryptodiff.yaml", false
}

func resolveBool(set map[string]bool, name string, flagValue bool, envKey string, fallback bool) bool {
	if set[name] {
		return flagValue
	}
	if v, ok := lookupEnvBool(envKey); ok {
		return v
	}
	return fallback
}

func lookupEnvString(key string) (string, bool) {
	if strings.TrimSpace(key) == "" {
		return "", false
	}
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

func lookupEnvBool(key string) (bool, bool) {
	v, ok := lookupEnvString(key)
	if !ok {
		return false, false
	}
	b, err := strconv.ParseBool(strings.ToLower(v))
	if err != nil {
		return false, false
	}
	return b, true
}

func parseCSV(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}
