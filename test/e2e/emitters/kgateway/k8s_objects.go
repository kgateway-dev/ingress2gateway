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

package kgateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

func decodeObjects(path string) ([]unstructured.Unstructured, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := k8syaml.NewYAMLOrJSONDecoder(f, 4096)

	var objs []unstructured.Unstructured
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		u := unstructured.Unstructured{Object: raw}
		if u.GetKind() == "List" {
			items, found, _ := unstructured.NestedSlice(u.Object, "items")
			if found {
				for _, it := range items {
					m, ok := it.(map[string]any)
					if ok && len(m) > 0 {
						objs = append(objs, unstructured.Unstructured{Object: m})
					}
				}
			}
			continue
		}
		objs = append(objs, u)
	}
	return objs, nil
}

func filterKind(objs []unstructured.Unstructured, kind string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, o := range objs {
		if o.GetKind() == kind {
			out = append(out, o)
		}
	}
	return out
}

func firstIngressHost(ing unstructured.Unstructured) (string, bool) {
	rules, found, _ := unstructured.NestedSlice(ing.Object, "spec", "rules")
	if !found || len(rules) == 0 {
		return "", false
	}
	r0, ok := rules[0].(map[string]any)
	if !ok {
		return "", false
	}
	h, _ := r0["host"].(string)
	return h, h != ""
}

func firstHTTPRouteHost(objs []unstructured.Unstructured) string {
	for _, o := range objs {
		if o.GetKind() != "HTTPRoute" {
			continue
		}
		hosts, found, _ := unstructured.NestedStringSlice(o.Object, "spec", "hostnames")
		if found && len(hosts) > 0 && hosts[0] != "" {
			return hosts[0]
		}
	}
	return ""
}

func firstTLSRouteHost(objs []unstructured.Unstructured) string {
	for _, o := range objs {
		if o.GetKind() != "TLSRoute" {
			continue
		}
		hosts, found, _ := unstructured.NestedStringSlice(o.Object, "spec", "hostnames")
		if found && len(hosts) > 0 && hosts[0] != "" {
			return hosts[0]
		}
	}
	return ""
}

func getIngressAddress(ctx context.Context, ns, name string) (string, error) {
	u, err := getUnstructured(ctx, "ingress", ns, name)
	if err != nil {
		return "", err
	}
	ings, found, _ := unstructured.NestedSlice(u.Object, "status", "loadBalancer", "ingress")
	if !found || len(ings) == 0 {
		return "", fmt.Errorf("no status.loadBalancer.ingress yet")
	}
	m, ok := ings[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected ingress status shape")
	}
	if ip, _ := m["ip"].(string); ip != "" {
		return ip, nil
	}
	if hn, _ := m["hostname"].(string); hn != "" {
		return hn, nil
	}
	return "", fmt.Errorf("no ip/hostname in status.loadBalancer.ingress[0]")
}

func hasTopLevelCondition(u unstructured.Unstructured, typ, status string) bool {
	conds, found, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	if !found {
		return false
	}
	return anyConditionEquals(conds, typ, status)
}

func hasRouteParentCondition(u unstructured.Unstructured, typ, status string) bool {
	parents, found, _ := unstructured.NestedSlice(u.Object, "status", "parents")
	if !found {
		return false
	}
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		conds, found, _ := unstructured.NestedSlice(pm, "conditions")
		if !found {
			continue
		}
		if anyConditionEquals(conds, typ, status) {
			return true
		}
	}
	return false
}

func anyConditionEquals(conds []any, typ, status string) bool {
	for _, c := range conds {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := cm["type"].(string)
		s, _ := cm["status"].(string)
		if t == typ && s == status {
			return true
		}
	}
	return false
}

func getGatewayStatusAddress(u unstructured.Unstructured) string {
	addrs, found, _ := unstructured.NestedSlice(u.Object, "status", "addresses")
	if !found || len(addrs) == 0 {
		return ""
	}
	m, ok := addrs[0].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := m["value"].(string)
	return v
}

func getUnstructured(ctx context.Context, resource, ns, name string) (unstructured.Unstructured, error) {
	args := []string{"get", resource, name, "-o", "json"}
	if ns != "" {
		args = append([]string{"-n", ns}, args...)
	}
	out, err := kubectl(ctx, args...)
	if err != nil {
		return unstructured.Unstructured{}, err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return unstructured.Unstructured{}, err
	}
	return unstructured.Unstructured{Object: obj}, nil
}
