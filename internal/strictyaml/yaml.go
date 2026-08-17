// Package strictyaml provides the single bounded YAML trust boundary used for
// tracked and local GitSeal documents.
package strictyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/raydalsayf/gitseal/internal/limits"
	"go.yaml.in/yaml/v3"
)

func Decode(data []byte, out any) error {
	if int64(len(data)) > limits.MaxYAMLBytes {
		return fmt.Errorf("YAML exceeds %d-byte limit", limits.MaxYAMLBytes)
	}
	if !utf8.Valid(data) {
		return errors.New("YAML is not valid UTF-8")
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return errors.New("YAML must contain exactly one non-empty document")
	}
	if err := inspect(document.Content[0], 1); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("parse trailing YAML document: %w", err)
		}
		return errors.New("YAML must contain exactly one document")
	}

	typed := yaml.NewDecoder(bytes.NewReader(data))
	typed.KnownFields(true)
	if err := typed.Decode(out); err != nil {
		return fmt.Errorf("decode typed YAML: %w", err)
	}
	if err := typed.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("YAML must contain exactly one document")
	}
	return nil
}

func Encode(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	if int64(out.Len()) > limits.MaxYAMLBytes {
		return nil, fmt.Errorf("encoded YAML exceeds %d-byte limit", limits.MaxYAMLBytes)
	}
	return out.Bytes(), nil
}

func inspect(node *yaml.Node, depth int) error {
	if depth > limits.MaxYAMLDepth {
		return fmt.Errorf("YAML nesting exceeds depth %d", limits.MaxYAMLDepth)
	}
	if node.Alias != nil || node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("YAML aliases and anchors are not allowed")
	}
	if !allowedTag(node.Tag) {
		return fmt.Errorf("YAML tag %q is not allowed", node.Tag)
	}
	if node.Kind == yaml.ScalarNode && len(node.Value) > limits.MaxYAMLScalarBytes {
		return fmt.Errorf("YAML scalar exceeds %d-byte limit", limits.MaxYAMLScalarBytes)
	}
	if node.Kind == yaml.MappingNode {
		if len(node.Content)%2 != 0 {
			return errors.New("invalid YAML mapping")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return errors.New("YAML mapping keys must be strings")
			}
			if key.Value == "<<" {
				return errors.New("YAML merge keys are not allowed")
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate YAML mapping key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspect(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func allowedTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool", "!!null":
		return true
	default:
		return false
	}
}
