/*
Copyright 2025 The Kubernetes Authors.

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
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// uniquePolicyIndices returns a slice of PolicyIndex values with duplicates
// removed. Uniqueness is defined by the (Rule, Backend) pair.
func uniquePolicyIndices(indices []providerir.PolicyIndex) []providerir.PolicyIndex {
	if len(indices) == 0 {
		return indices
	}

	seen := make(map[providerir.PolicyIndex]struct{}, len(indices))
	out := make([]providerir.PolicyIndex, 0, len(indices))

	for _, idx := range indices {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}

// ensureTrafficPolicy returns the TrafficPolicy for the given ingressName,
// creating and initializing it if needed.
func ensureTrafficPolicy(
	tp map[string]*kgateway.TrafficPolicy,
	ingressName, namespace string,
) *kgateway.TrafficPolicy {
	if existing, ok := tp[ingressName]; ok {
		return existing
	}

	newTP := &kgateway.TrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: namespace,
		},
		Spec: kgateway.TrafficPolicySpec{},
	}
	newTP.SetGroupVersionKind(TrafficPolicyGVK)

	tp[ingressName] = newTP
	return newTP
}

func numRules(hr gatewayv1.HTTPRoute) int {
	n := 0
	for _, r := range hr.Spec.Rules {
		n += len(r.BackendRefs)
	}
	return n
}

// toUnstructured converts a runtime.Object to unstructured.Unstructured
func toUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: unstructuredObj}, nil
}
