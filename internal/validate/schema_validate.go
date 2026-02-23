package validate

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"

	schemadata "github.com/cryptoposture/cryptodiff/schemas"
)

func ArtifactAgainstEmbeddedSchema(schemaFile string, artifact any) error {
	schemaBytes, err := schemadata.Load(schemaFile)
	if err != nil {
		return err
	}

	var schema any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		return fmt.Errorf("parse schema %q: %w", schemaFile, err)
	}

	artifactBytes, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("encode artifact for schema validation: %w", err)
	}
	var instance any
	if err := json.Unmarshal(artifactBytes, &instance); err != nil {
		return fmt.Errorf("decode artifact for schema validation: %w", err)
	}

	return validateJSONSchemaNode(schema, instance, "$")
}

func validateJSONSchemaNode(schema any, instance any, path string) error {
	schemaObj, ok := schema.(map[string]any)
	if !ok {
		return nil
	}

	if enumVals, ok := schemaObj["enum"].([]any); ok {
		if !containsEnum(enumVals, instance) {
			return fmt.Errorf("%s must be one of enum values", path)
		}
	}

	if t, ok := schemaObj["type"].(string); ok {
		if err := validateType(t, schemaObj, instance, path); err != nil {
			return err
		}
	}
	return nil
}

func validateType(t string, schemaObj map[string]any, instance any, path string) error {
	validators := map[string]func(map[string]any, any, string) error{
		"object":  validateObjectType,
		"array":   validateArrayType,
		"string":  validateStringType,
		"integer": validateIntegerType,
		"number":  validateNumberType,
		"boolean": validateBooleanType,
	}
	if validator, ok := validators[t]; ok {
		return validator(schemaObj, instance, path)
	}
	return nil
}

func validateObjectType(schemaObj map[string]any, instance any, path string) error {
	obj, ok := instance.(map[string]any)
	if !ok {
		return fmt.Errorf("%s must be object", path)
	}
	if err := validateRequiredFields(schemaObj, obj, path); err != nil {
		return err
	}
	if err := validateObjectProperties(schemaObj, obj, path); err != nil {
		return err
	}
	return validateAdditionalProperties(schemaObj, obj, path)
}

func validateRequiredFields(schemaObj map[string]any, obj map[string]any, path string) error {
	required, ok := schemaObj["required"].([]any)
	if !ok {
		return nil
	}
	for _, r := range required {
		key, _ := r.(string)
		if key == "" {
			continue
		}
		if _, exists := obj[key]; !exists {
			return fmt.Errorf("%s.%s is required", path, key)
		}
	}
	return nil
}

func validateObjectProperties(schemaObj map[string]any, obj map[string]any, path string) error {
	props, ok := schemaObj["properties"].(map[string]any)
	if !ok {
		return nil
	}
	for key, sub := range props {
		v, exists := obj[key]
		if !exists {
			continue
		}
		if err := validateJSONSchemaNode(sub, v, path+"."+key); err != nil {
			return err
		}
	}
	return nil
}

func validateAdditionalProperties(schemaObj map[string]any, obj map[string]any, path string) error {
	props, _ := schemaObj["properties"].(map[string]any)
	additional, hasAdditional := schemaObj["additionalProperties"]
	if !hasAdditional {
		return nil
	}

	switch ap := additional.(type) {
	case bool:
		if ap {
			return nil
		}
		for key := range obj {
			if _, exists := props[key]; exists {
				continue
			}
			return fmt.Errorf("%s.%s is not allowed", path, key)
		}
		return nil
	case map[string]any:
		for key, value := range obj {
			if _, exists := props[key]; exists {
				continue
			}
			if err := validateJSONSchemaNode(ap, value, path+"."+key); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func validateArrayType(schemaObj map[string]any, instance any, path string) error {
	arr, ok := instance.([]any)
	if !ok {
		return fmt.Errorf("%s must be array", path)
	}
	if err := validateArrayMinItems(schemaObj, arr, path); err != nil {
		return err
	}
	return validateArrayItems(schemaObj, arr, path)
}

func validateArrayMinItems(schemaObj map[string]any, arr []any, path string) error {
	minItems, ok := toInt(schemaObj["minItems"])
	if ok && len(arr) < minItems {
		return fmt.Errorf("%s must contain at least %d items", path, minItems)
	}
	return nil
}

func validateArrayItems(schemaObj map[string]any, arr []any, path string) error {
	itemsSchema, exists := schemaObj["items"]
	if !exists {
		return nil
	}
	for i, item := range arr {
		if err := validateJSONSchemaNode(itemsSchema, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func validateStringType(_ map[string]any, instance any, path string) error {
	if _, ok := instance.(string); !ok {
		return fmt.Errorf("%s must be string", path)
	}
	return nil
}

func validateIntegerType(schemaObj map[string]any, instance any, path string) error {
	n, ok := instance.(float64)
	if !ok || math.Trunc(n) != n {
		return fmt.Errorf("%s must be integer", path)
	}
	return validateMinimum(schemaObj, n, path)
}

func validateNumberType(schemaObj map[string]any, instance any, path string) error {
	n, ok := instance.(float64)
	if !ok {
		return fmt.Errorf("%s must be number", path)
	}
	return validateMinimum(schemaObj, n, path)
}

func validateMinimum(schemaObj map[string]any, n float64, path string) error {
	if minVal, ok := toFloat(schemaObj["minimum"]); ok && n < minVal {
		return fmt.Errorf("%s must be >= %v", path, minVal)
	}
	return nil
}

func validateBooleanType(_ map[string]any, instance any, path string) error {
	if _, ok := instance.(bool); !ok {
		return fmt.Errorf("%s must be boolean", path)
	}
	return nil
}

func containsEnum(enumVals []any, instance any) bool {
	for _, v := range enumVals {
		if reflect.DeepEqual(v, instance) {
			return true
		}
	}
	return false
}

func toInt(v any) (int, bool) {
	n, ok := toFloat(v)
	if !ok {
		return 0, false
	}
	if math.Trunc(n) != n {
		return 0, false
	}
	return int(n), true
}

func toFloat(v any) (float64, bool) {
	n, ok := v.(float64)
	return n, ok
}
