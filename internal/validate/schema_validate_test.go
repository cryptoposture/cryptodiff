package validate

import (
	"testing"

	"github.com/cryptoposture/cryptodiff/internal/model"
)

func TestArtifactAgainstEmbeddedSchemaPassesForValidPosture(t *testing.T) {
	p := model.Posture{
		SchemaVersion: "0.2.0",
		GeneratedAt:   "2026-02-22T00:00:00Z",
		Summary: model.PostureSummary{
			Findings:   1,
			Suppressed: 0,
		},
		Suppressions: model.SuppressionSummary{},
		Tool: model.Tool{
			Name:    "cryptodiff",
			Version: "0.2.0-dev",
		},
		Source: model.Source{
			RepoPath: "/tmp/repo",
		},
		Findings: []model.Finding{
			{
				ID:          "finding-1",
				RuleID:      "CRYPTO.ALG.DISALLOWED",
				Severity:    "critical",
				Category:    "algorithm",
				Confidence:  "high",
				Subject:     "Disallowed algorithm reference: md5",
				Fingerprint: "fp1",
				Evidence:    []model.Evidence{{Path: "a.yaml", Line: 1}},
			},
		},
	}
	if err := ArtifactAgainstEmbeddedSchema("posture.schema.json", p); err != nil {
		t.Fatalf("expected posture schema validation to pass, got error: %v", err)
	}
}

func TestArtifactAgainstEmbeddedSchemaFailsMissingRequired(t *testing.T) {
	bad := map[string]any{
		"schemaVersion": "0.2.0",
		"tool": map[string]any{
			"name":    "cryptodiff",
			"version": "0.2.0-dev",
		},
		"summary": map[string]any{
			"findings": 0,
		},
		"suppressions": map[string]any{},
		// source missing (required by schema)
		"findings": []any{},
	}
	if err := ArtifactAgainstEmbeddedSchema("posture.schema.json", bad); err == nil {
		t.Fatal("expected schema validation to fail for missing required fields")
	}
}

func TestArtifactAgainstEmbeddedSchemaPolicy(t *testing.T) {
	good := map[string]any{
		"version": "0.2",
		"rules": []any{
			map[string]any{
				"id":    "CRYPTO.ALG.DISALLOWED",
				"level": "critical",
				"match": map[string]any{
					"category":  "algorithm",
					"attribute": "name",
					"op":        "in",
					"values":    []any{"md5", "sha1"},
				},
			},
		},
	}
	if err := ArtifactAgainstEmbeddedSchema("policy.schema.json", good); err != nil {
		t.Fatalf("expected policy schema validation to pass, got error: %v", err)
	}

	bad := map[string]any{
		"version": "0.2",
		"rules": []any{
			map[string]any{
				"id":    "CRYPTO.ALG.DISALLOWED",
				"level": "critical",
				"match": map[string]any{
					"op": "nope",
				},
			},
		},
	}
	if err := ArtifactAgainstEmbeddedSchema("policy.schema.json", bad); err == nil {
		t.Fatal("expected policy schema validation to fail for invalid op")
	}
}

func TestArtifactAgainstEmbeddedSchemaDiffRejectsInvalidAdditionalPropertiesTypes(t *testing.T) {
	bad := map[string]any{
		"schemaVersion": "0.2.0",
		"summary": map[string]any{
			"addedCount":     1,
			"removedCount":   0,
			"changedCount":   0,
			"unchangedCount": 0,
			"addedBySeverity": map[string]any{
				"critical": "one",
			},
		},
		"added":     []any{},
		"removed":   []any{},
		"changed":   []any{},
		"unchanged": []any{},
	}

	if err := ArtifactAgainstEmbeddedSchema("diff.schema.json", bad); err == nil {
		t.Fatal("expected diff schema validation to fail for non-integer additionalProperties value")
	}
}

func TestSchemaValidatorHonorsAdditionalPropertiesFalse(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name": map[string]any{"type": "string"},
		},
		"additionalProperties": false,
	}
	instance := map[string]any{
		"name":  "ok",
		"extra": "not-allowed",
	}
	if err := validateJSONSchemaNode(schema, instance, "$"); err == nil {
		t.Fatal("expected validation to fail when additionalProperties is false and unknown key exists")
	}
}
