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
	"fmt"
	"sort"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyRewriteTargetPolicies projects ingress-nginx rewrite-target into *per-rule* Kgateway TrafficPolicies
// and attaches them via ExtensionRef filters to the covered backendRefs.
//
// Why per-rule?
//   - The regex rewrite pattern must align with the rule's path regex so capture groups ($1, $2, ...)
//     behave like ingress-nginx.
//
// Assumptions:
//   - applyRegexPathMatchingForHost(...) has already run (if host-wide regex location mode is enabled),
//     so rule path matches will already be RegularExpression where needed.
func applyRewriteTargetPolicies(
	pol intermediate.Policy,
	sourceIngressName, namespace string,
	httpRouteCtx *intermediate.HTTPRouteContext,
	tp map[string]*kgateway.TrafficPolicy,
) {
	if pol.RewriteTarget == nil || *pol.RewriteTarget == "" {
		return
	}
	if httpRouteCtx == nil {
		return
	}

	// Group covered backendRefs by rule index.
	// ruleIdx -> set(backendIdx)
	byRule := map[int]map[int]struct{}{}
	for _, idx := range pol.RuleBackendSources {
		if idx.Rule < 0 || idx.Backend < 0 {
			continue
		}
		if _, ok := byRule[idx.Rule]; !ok {
			byRule[idx.Rule] = map[int]struct{}{}
		}
		byRule[idx.Rule][idx.Backend] = struct{}{}
	}
	if len(byRule) == 0 {
		return
	}

	// Deterministic iteration for stable goldens.
	ruleIdxs := make([]int, 0, len(byRule))
	for r := range byRule {
		ruleIdxs = append(ruleIdxs, r)
	}
	sort.Ints(ruleIdxs)

	for _, ruleIdx := range ruleIdxs {
		if ruleIdx >= len(httpRouteCtx.Spec.Rules) {
			continue
		}

		pattern := deriveRulePathRegexPattern(httpRouteCtx.Spec.Rules[ruleIdx])

		// Name is unique per ingress + rule, so we can safely create multiple TPs per ingress.
		tpName := fmt.Sprintf("%s-rewrite-%d", sourceIngressName, ruleIdx)
		t := ensureTrafficPolicy(tp, tpName, namespace)

		t.Spec.UrlRewrite = &kgateway.URLRewrite{
			PathRegex: &kgateway.PathRegexRewrite{
				Pattern:      pattern,
				Substitution: *pol.RewriteTarget,
			},
		}

		// Attach this rewrite TP to every covered backendRef in the rule via ExtensionRef filter.
		backendSet := byRule[ruleIdx]
		backendIdxs := make([]int, 0, len(backendSet))
		for b := range backendSet {
			backendIdxs = append(backendIdxs, b)
		}
		sort.Ints(backendIdxs)

		for _, backendIdx := range backendIdxs {
			if backendIdx >= len(httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs) {
				continue
			}

			httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs[backendIdx].Filters =
				append(
					httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs[backendIdx].Filters,
					gwv1.HTTPRouteFilter{
						Type: gwv1.HTTPRouteFilterExtensionRef,
						ExtensionRef: &gwv1.LocalObjectReference{
							Group: gwv1.Group(TrafficPolicyGVK.Group),
							Kind:  gwv1.Kind(TrafficPolicyGVK.Kind),
							Name:  gwv1.ObjectName(t.Name),
						},
					},
				)
		}
	}
}

// deriveRulePathRegexPattern returns a single regex pattern for the rule if possible.
// If the rule has:
//   - exactly one distinct RegularExpression path value -> return it
//   - zero or multiple distinct regex values            -> fall back to "^(.*)"
//
// Note: If a rule has multiple *different* path regex matches, we can't represent
// match-specific rewrites without splitting the rule, so we choose a safe fallback.
func deriveRulePathRegexPattern(rule gwv1.HTTPRouteRule) string {
	patterns := map[string]struct{}{}

	for i := range rule.Matches {
		m := rule.Matches[i]
		if m.Path == nil || m.Path.Type == nil || m.Path.Value == nil {
			continue
		}
		if *m.Path.Type != gwv1.PathMatchRegularExpression {
			continue
		}
		if v := *m.Path.Value; v != "" {
			patterns[v] = struct{}{}
		}
	}

	if len(patterns) == 1 {
		for p := range patterns {
			return p
		}
	}

	return "^(.*)"
}
