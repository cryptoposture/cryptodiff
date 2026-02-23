package explain

import (
	"fmt"
	"strings"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

type Selector struct {
	FindingID   string
	Fingerprint string
	RuleID      string
}

func SelectFinding(p model.Posture, s Selector) (model.Finding, bool) {
	for _, f := range p.Findings {
		if s.FindingID != "" && f.ID == s.FindingID {
			return f, true
		}
		if s.Fingerprint != "" && f.Fingerprint == s.Fingerprint {
			return f, true
		}
		if s.RuleID != "" && f.RuleID == s.RuleID {
			return f, true
		}
	}
	return model.Finding{}, false
}

func Render(f model.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Finding: %s\n", f.ID))
	b.WriteString(fmt.Sprintf("Rule: %s\n", f.RuleID))
	b.WriteString(fmt.Sprintf("Severity: %s\n", strings.ToUpper(f.Severity)))
	b.WriteString(fmt.Sprintf("Category: %s\n", f.Category))
	b.WriteString(fmt.Sprintf("Subject: %s\n", f.Subject))
	if len(f.Evidence) > 0 {
		b.WriteString(fmt.Sprintf("Evidence: %s", f.Evidence[0].Path))
		if f.Evidence[0].Line > 0 {
			b.WriteString(fmt.Sprintf(":%d", f.Evidence[0].Line))
		}
		b.WriteString("\n")
	}

	b.WriteString("\nWhy this matters:\n")
	b.WriteString("This finding indicates a cryptography posture risk that may violate policy or weaken resilience against modern threats.\n")
	b.WriteString("\nRecommended action:\n")
	b.WriteString(ruleRecommendation(f.RuleID))
	b.WriteString("\n")
	return b.String()
}

func ruleRecommendation(ruleID string) string {
	switch ruleID {
	case "CRYPTO.TLS.MIN_VERSION":
		return "- Raise the minimum TLS version to 1.2 or 1.3 and remove support for legacy TLS versions."
	case "CRYPTO.ALG.DISALLOWED":
		return "- Replace disallowed algorithms (for example md5/sha1/des/3des/rc4) with approved modern alternatives."
	default:
		return "- Review the evidence location and update configuration or code to meet the active cryptography policy."
	}
}
