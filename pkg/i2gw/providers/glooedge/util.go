/*
Copyright 2026 The Kubernetes Authors.

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

package glooedge

import (
	"bytes"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
)

var versionKind = schema.GroupVersionKind{
	Group:   "gateway.solo.io",
	Version: "v1",
	Kind:    "VirtualService",
}

func readObjectsFromFile(filename, defaultNamespace string) ([]*unstructured.Unstructured, error) {
	stream, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	decoder := kubeyaml.NewYAMLOrJSONDecoder(bytes.NewReader(stream), 4096)
	var objects []*unstructured.Unstructured

	for {
		u := &unstructured.Unstructured{}
		err := decoder.Decode(u)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("failed to decode object: %w", err)
		}

		if u.GetName() == "" {
			continue
		}

		if u.GetNamespace() == "" {
			u.SetNamespace(defaultNamespace)
		}

		objects = append(objects, u)
	}

	return objects, nil
}