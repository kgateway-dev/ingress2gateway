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

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyRewriteTargetPolicies projects ingress-nginx rewrite-target into *per-rule* Kgateway TrafficPolicies.
func applyRewriteTargetPolicies(
	pol providerir.Policy,
	sourceIngressName, namespace string,
	httpRouteCtx *emitterir.HTTPRouteContext,
	tp map[string]*kgateway.TrafficPolicy,
) {
	if pol.RewriteTarget == nil || *pol.RewriteTarget == "" {
		return
	}
	if httpRouteCtx == nil {
		return
	}

	// Group covered backendRefs by rule index.
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

		// Regex rewrite only when use-regex=true.
		if pol.UseRegexPaths != nil && *pol.UseRegexPaths {
			pattern := deriveRulePathRegexPattern(httpRouteCtx.Spec.Rules[ruleIdx])
			tpName := fmt.Sprintf("%s-rewrite-%d", sourceIngressName, ruleIdx)
			t := ensureTrafficPolicy(tp, tpName, namespace)
			t.Spec.UrlRewrite = &kgateway.URLRewrite{
				PathRegex: &kgateway.PathRegexRewrite{
					Pattern:      pattern,
					Substitution: *pol.RewriteTarget,
				},
			}

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
				httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs[backendIdx].Filters = append(
					httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs[backendIdx].Filters,
					gatewayv1.HTTPRouteFilter{
						Type: gatewayv1.HTTPRouteFilterExtensionRef,
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: gatewayv1.Group(TrafficPolicyGVK.Group),
							Kind:  gatewayv1.Kind(TrafficPolicyGVK.Kind),
							Name:  gatewayv1.ObjectName(t.Name),
						},
					},
				)
			}
			continue
		}

		// Non-regex: use native Gateway API URLRewrite/ReplaceFullPath at the rule level.
		ensureRuleURLRewriteReplaceFullPath(&httpRouteCtx.Spec.Rules[ruleIdx], *pol.RewriteTarget)
	}
}

// deriveRulePathRegexPattern returns a single regex pattern for the rule if possible.
func deriveRulePathRegexPattern(rule gatewayv1.HTTPRouteRule) string {
	patterns := map[string]struct{}{}

	for i := range rule.Matches {
		m := rule.Matches[i]
		if m.Path == nil || m.Path.Type == nil || m.Path.Value == nil {
			continue
		}
		if *m.Path.Type != gatewayv1.PathMatchRegularExpression {
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

// ensureRuleURLRewriteReplaceFullPath ensures the given rule has a URLRewrite filter.
func ensureRuleURLRewriteReplaceFullPath(rule *gatewayv1.HTTPRouteRule, replaceFullPath string) {
	// Update existing URLRewrite filter if present.
	for i := range rule.Filters {
		if rule.Filters[i].Type != gatewayv1.HTTPRouteFilterURLRewrite {
			continue
		}
		if rule.Filters[i].URLRewrite == nil {
			rule.Filters[i].URLRewrite = &gatewayv1.HTTPURLRewriteFilter{}
		}
		if rule.Filters[i].URLRewrite.Path == nil {
			rule.Filters[i].URLRewrite.Path = &gatewayv1.HTTPPathModifier{}
		}
		rule.Filters[i].URLRewrite.Path.Type = gatewayv1.FullPathHTTPPathModifier
		rule.Filters[i].URLRewrite.Path.ReplaceFullPath = &replaceFullPath
		return
	}

	// Otherwise append a new URLRewrite filter.
	rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterURLRewrite,
		URLRewrite: &gatewayv1.HTTPURLRewriteFilter{
			Path: &gatewayv1.HTTPPathModifier{
				Type:            gatewayv1.FullPathHTTPPathModifier,
				ReplaceFullPath: &replaceFullPath,
			},
		},
	})
}
