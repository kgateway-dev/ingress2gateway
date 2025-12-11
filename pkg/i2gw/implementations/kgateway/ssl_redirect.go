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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applySSLRedirectPolicy applies SSL redirect by adding a RequestRedirect filter
// to HTTPRoute rules when SSLRedirect is enabled in the policy.
//
// Semantics:
//   - If SSLRedirect is enabled, add a RequestRedirect filter to rule-level Filters
//   - The filter redirects HTTP to HTTPS with a 301 status code
//   - The filter is applied to all rules covered by the policy
func applySSLRedirectPolicy(
	pol intermediate.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteContext *intermediate.HTTPRouteContext,
	coverage []intermediate.PolicyIndex,
) {
	if pol.SSLRedirect == nil || !*pol.SSLRedirect {
		return
	}

	// Get unique rule indices from coverage
	ruleSet := make(map[int]struct{})
	for _, idx := range coverage {
		ruleSet[idx.Rule] = struct{}{}
	}

	// Add RequestRedirect filter to each covered rule
	for ruleIdx := range ruleSet {
		if ruleIdx >= len(httpRouteContext.Spec.Rules) {
			continue
		}

		// Check if RequestRedirect filter already exists
		hasRedirect := false
		for _, filter := range httpRouteContext.Spec.Rules[ruleIdx].Filters {
			if filter.Type == gwv1.HTTPRouteFilterRequestRedirect {
				hasRedirect = true
				break
			}
		}

		if !hasRedirect {
			// Add RequestRedirect filter to redirect HTTP to HTTPS
			httpRouteContext.Spec.Rules[ruleIdx].Filters = append(
				httpRouteContext.Spec.Rules[ruleIdx].Filters,
				gwv1.HTTPRouteFilter{
					Type: gwv1.HTTPRouteFilterRequestRedirect,
					RequestRedirect: &gwv1.HTTPRequestRedirectFilter{
						Scheme:     ptr.To("https"),
						StatusCode: ptr.To(301),
					},
				},
			)
		}
	}
}
