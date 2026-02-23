package model

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Source struct {
	RepoPath string `json:"repoPath"`
	Commit   string `json:"commit,omitempty"`
	Ref      string `json:"ref,omitempty"`
}

type Evidence struct {
	Path        string `json:"path"`
	Line        int    `json:"line,omitempty"`
	SnippetHash string `json:"snippetHash,omitempty"`
}

type Finding struct {
	ID          string         `json:"id"`
	RuleID      string         `json:"ruleId"`
	Severity    string         `json:"severity"`
	Category    string         `json:"category"`
	Confidence  string         `json:"confidence"`
	Subject     string         `json:"subject"`
	Attributes  map[string]any `json:"attributes,omitempty"`
	Evidence    []Evidence     `json:"evidence"`
	Fingerprint string         `json:"fingerprint"`
}

type Posture struct {
	SchemaVersion string             `json:"schemaVersion"`
	GeneratedAt   string             `json:"generatedAt"`
	Tool          Tool               `json:"tool"`
	Source        Source             `json:"source"`
	Summary       PostureSummary     `json:"summary,omitempty"`
	Suppressions  SuppressionSummary `json:"suppressions,omitempty"`
	ScanErrors    []ScanError        `json:"scanErrors,omitempty"`
	Findings      []Finding          `json:"findings"`
}

type PostureSummary struct {
	Findings   int `json:"findings"`
	Suppressed int `json:"suppressed,omitempty"`
	ScanErrors int `json:"scanErrors,omitempty"`
}

type SuppressionSummary struct {
	Inline         int `json:"inline,omitempty"`
	IgnoreFile     int `json:"ignoreFile,omitempty"`
	ConfigPath     int `json:"configPath,omitempty"`
	ConfigRule     int `json:"configRule,omitempty"`
	ConfigCategory int `json:"configCategory,omitempty"`
}

type ScanError struct {
	Path    string `json:"path,omitempty"`
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type DiffSummary struct {
	AddedCount        int            `json:"addedCount"`
	RemovedCount      int            `json:"removedCount"`
	ChangedCount      int            `json:"changedCount"`
	UnchangedCount    int            `json:"unchangedCount"`
	AddedBySeverity   map[string]int `json:"addedBySeverity,omitempty"`
	RemovedBySeverity map[string]int `json:"removedBySeverity,omitempty"`
	ChangedBySeverity map[string]int `json:"changedBySeverity,omitempty"`
	AddedByCategory   map[string]int `json:"addedByCategory,omitempty"`
	RemovedByCategory map[string]int `json:"removedByCategory,omitempty"`
	ChangedByCategory map[string]int `json:"changedByCategory,omitempty"`
}

type ChangedFinding struct {
	Before        Finding  `json:"before"`
	After         Finding  `json:"after"`
	ChangedFields []string `json:"changedFields,omitempty"`
}

type DiffReport struct {
	SchemaVersion string           `json:"schemaVersion"`
	GeneratedAt   string           `json:"generatedAt"`
	BaseSource    Source           `json:"baseSource"`
	HeadSource    Source           `json:"headSource"`
	Summary       DiffSummary      `json:"summary"`
	Added         []Finding        `json:"added"`
	Removed       []Finding        `json:"removed"`
	Changed       []ChangedFinding `json:"changed"`
	Unchanged     []Finding        `json:"unchanged"`
}

type PolicyRuleMatch struct {
	Category  string   `json:"category,omitempty"`
	Attribute string   `json:"attribute,omitempty"`
	Op        string   `json:"op,omitempty"`
	Value     any      `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
}

type PolicyRule struct {
	ID    string          `json:"id"`
	Level string          `json:"level"`
	Match PolicyRuleMatch `json:"match"`
}

type Policy struct {
	Version string       `json:"version"`
	Rules   []PolicyRule `json:"rules"`
}

type AuditViolation struct {
	RuleID        string `json:"ruleId"`
	Level         string `json:"level"`
	Fingerprint   string `json:"fingerprint"`
	Subject       string `json:"subject"`
	Category      string `json:"category"`
	DetectedValue string `json:"detectedValue,omitempty"`
}

type AuditSummary struct {
	EvaluatedFindings int `json:"evaluatedFindings"`
	Violations        int `json:"violations"`
	Suppressed        int `json:"suppressed,omitempty"`
	Excepted          int `json:"excepted,omitempty"`
}

type InvalidException struct {
	ID          string `json:"id,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
}

type AuditReport struct {
	SchemaVersion     string             `json:"schemaVersion"`
	GeneratedAt       string             `json:"generatedAt"`
	Mode              string             `json:"mode"`
	FailLevel         string             `json:"failLevel"`
	PolicyVersion     string             `json:"policyVersion"`
	Result            string             `json:"result"`
	Summary           AuditSummary       `json:"summary"`
	Violations        []AuditViolation   `json:"violations"`
	InvalidExceptions []InvalidException `json:"invalidExceptions,omitempty"`
}

type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"ruleId,omitempty"`
	Subject     string `json:"subject,omitempty"`
	AddedAt     string `json:"addedAt,omitempty"`
}

type Baseline struct {
	SchemaVersion string          `json:"schemaVersion"`
	GeneratedAt   string          `json:"generatedAt"`
	Entries       []BaselineEntry `json:"entries"`
}

type ExceptionEntry struct {
	ID          string `json:"id,omitempty"`
	RuleID      string `json:"ruleId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
}

type ExceptionsFile struct {
	SchemaVersion string           `json:"schemaVersion,omitempty"`
	GeneratedAt   string           `json:"generatedAt,omitempty"`
	Entries       []ExceptionEntry `json:"entries"`
}
