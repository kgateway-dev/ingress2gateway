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