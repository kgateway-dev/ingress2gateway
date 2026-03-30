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
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestBasicVirtualServiceConversion(t *testing.T) {
	// Create a test VirtualService
	vs := &VirtualService{
		Name:      "example-vs",
		Namespace: "default",
		Spec: VirtualServiceSpec{
			Hosts: []string{"example.com"},
			VirtualHost: VirtualHost{
				Routes: []Route{
					{
						Matchers: []Matcher{
							{Prefix: "/api"},
						},
						RouteAction: RouteAction{
							Single: SingleUpstream{
								Upstream: Upstream{
									Name:      "my-service",
									Namespace: "default",
								},
							},
						},
					},
				},
			},
		},
	}

	// Create storage and add the VirtualService
	storage := newResourcesStorage()
	storage.addVirtualService(vs)

	// Create converter and convert
	converter := newResourcesToIRConverter()
	ir, errs := converter.convert(storage)

	// Validate
	if len(errs) > 0 {
		t.Fatalf("Expected no errors, got: %v", errs)
	}

	// Check HTTPRoute was created
	expectedKey := types.NamespacedName{
		Namespace: "default",
		Name:      "example-vs-example-com",
	}

	if _, ok := ir.HTTPRoutes[expectedKey]; !ok {
		t.Fatalf("Expected HTTPRoute %s/%s to be created", expectedKey.Namespace, expectedKey.Name)
	}

	httpRoute := ir.HTTPRoutes[expectedKey]

	// Verify hostnames
	if len(httpRoute.HTTPRoute.Spec.Hostnames) != 1 {
		t.Fatalf("Expected 1 hostname, got %d", len(httpRoute.HTTPRoute.Spec.Hostnames))
	}

	if string(httpRoute.HTTPRoute.Spec.Hostnames[0]) != "example.com" {
		t.Fatalf("Expected hostname example.com, got %s", httpRoute.HTTPRoute.Spec.Hostnames[0])
	}

	// Verify rules
	if len(httpRoute.HTTPRoute.Spec.Rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(httpRoute.HTTPRoute.Spec.Rules))
	}

	rule := httpRoute.HTTPRoute.Spec.Rules[0]
	if len(rule.BackendRefs) != 1 {
		t.Fatalf("Expected 1 backend ref, got %d", len(rule.BackendRefs))
	}

	if rule.BackendRefs[0].BackendRef.BackendObjectReference.Name != "my-service" {
		t.Fatalf("Expected backend name my-service, got %s", rule.BackendRefs[0].BackendRef.BackendObjectReference.Name)
	}

	t.Log("✅ Test passed!")
}
