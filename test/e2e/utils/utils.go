/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v4"
)

func EnvOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func ModuleRoot(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w: %s", err, string(out))
	}
	goMod := strings.TrimSpace(string(out))
	if goMod == "" || goMod == os.DevNull {
		return "", fmt.Errorf("GOMOD not set")
	}
	return filepath.Dir(goMod), nil
}

// canonicalizeMultiDocYAML normalizes YAML by sorting documents by kind, namespace, and name.
// This makes YAML comparison more reliable by eliminating ordering differences.
func canonicalizeMultiDocYAML(in []byte) ([]byte, error) {
	// Split multi-doc YAML into individual docs.
	dec := yaml.NewDecoder(bytes.NewReader(in))

	type doc struct {
		Raw map[string]any
	}
	var docs []doc

	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to decode yaml: %w", err)
		}
		if len(m) == 0 {
			continue
		}
		docs = append(docs, doc{Raw: m})
	}

	// Extract Kind/Name for sorting.
	type keyedDoc struct {
		kind      string
		namespace string
		name      string
		raw       map[string]any
	}

	var kd []keyedDoc
	for _, d := range docs {
		md, _ := d.Raw["metadata"].(map[string]any)
		kind, _ := d.Raw["kind"].(string)
		name, _ := md["name"].(string)
		ns, _ := md["namespace"].(string)
		kd = append(kd, keyedDoc{
			kind:      kind,
			namespace: ns,
			name:      name,
			raw:       d.Raw,
		})
	}

	sort.Slice(kd, func(i, j int) bool {
		if kd[i].kind != kd[j].kind {
			return kd[i].kind < kd[j].kind
		}
		if kd[i].namespace != kd[j].namespace {
			return kd[i].namespace < kd[j].namespace
		}
		return kd[i].name < kd[j].name
	})

	// Re-encode in canonical order.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)

	for _, d := range kd {
		if err := enc.Encode(d.raw); err != nil {
			return nil, fmt.Errorf("failed to encode yaml: %w", err)
		}
	}
	_ = enc.Close()

	return buf.Bytes(), nil
}

// CompareAndGenerateOutput runs ingress2gateway, compares the output with expected output,
// and writes the generated output to a temporary file. Returns the path to the generated output file.
func CompareAndGenerateOutput(ctx context.Context, t *testing.T, emitter, root, inputFile, expectedOutputFile string) (string, error) {
	t.Helper()

	// Run ingress2gateway to generate output
	generatedYAML, err := RunIngress2Gateway(ctx, emitter, root, inputFile)
	if err != nil {
		return "", fmt.Errorf("failed to run ingress2gateway: %w", err)
	}

	// Read expected output
	expectedYAML, err := os.ReadFile(expectedOutputFile)
	if err != nil {
		return "", fmt.Errorf("failed to read expected output file %q: %w", expectedOutputFile, err)
	}

	// Canonicalize both YAMLs for comparison
	generatedCanonical, err := canonicalizeMultiDocYAML(bytes.TrimSpace(generatedYAML))
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize generated YAML: %w", err)
	}

	expectedCanonical, err := canonicalizeMultiDocYAML(bytes.TrimSpace(expectedYAML))
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize expected YAML: %w", err)
	}

	// Compare canonicalized outputs
	if diff := cmp.Diff(string(expectedCanonical), string(generatedCanonical)); diff != "" {
		t.Fatalf("generated output does not match expected output (-want +got):\n%s", diff)
	}

	// Write generated output to a temporary file
	tmpFile, err := os.CreateTemp("", "i2g-generated-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(generatedYAML); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed to write generated YAML to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	return tmpPath, nil
}
