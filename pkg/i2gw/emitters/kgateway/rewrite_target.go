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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EmitPathRewrite projects provider-neutral rewrite intent into either native
// HTTPRoute filters or section-scoped Kgateway TrafficPolicies for regex capture
// group rewrites.
func (e *Emitter) EmitPathRewrite(ir emitterir.EmitterIR, gwResources *i2gw.GatewayResources) {
	for httpRouteKey, ctx := range ir.HTTPRoutes {
		changed := false

		for idx, rewrite := range ctx.PathRewriteByRuleIdx {
			if rewrite == nil || idx < 0 || idx >= len(ctx.Spec.Rules) {
				continue
			}

			if rewrite.RegexCaptureGroupReferences {
				sectionName := e.getSectionName(ctx, idx)
				trafficPolicy := e.getOrBuildTrafficPolicy(ctx, sectionName, idx)
				trafficPolicy.Spec.UrlRewrite = &kgateway.URLRewrite{
					PathRegex: &kgateway.PathRegexRewrite{
						Pattern:      deriveRulePathRegexPattern(ctx.Spec.Rules[idx]),
						Substitution: rewrite.ReplaceFullPath,
					},
				}
			} else {
				ensureRuleURLRewriteReplaceFullPath(&ctx.Spec.Rules[idx], rewrite.ReplaceFullPath)
				changed = true
			}

			if len(rewrite.Headers) > 0 {
				ensureRuleRequestHeaderModifierSet(&ctx.Spec.Rules[idx], rewrite.Headers)
				changed = true
			}
		}

		if changed {
			ir.HTTPRoutes[httpRouteKey] = ctx
			gwResources.HTTPRoutes[httpRouteKey] = ctx.HTTPRoute
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

// ensureRuleURLRewriteReplaceFullPath ensures the given rule has a URLRewrite filter
// that performs a ReplaceFullPath with the given value.
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

func ensureRuleRequestHeaderModifierSet(rule *gatewayv1.HTTPRouteRule, headers map[string]string) {
	for i := range rule.Filters {
		if rule.Filters[i].Type != gatewayv1.HTTPRouteFilterRequestHeaderModifier {
			continue
		}
		if rule.Filters[i].RequestHeaderModifier == nil {
			rule.Filters[i].RequestHeaderModifier = &gatewayv1.HTTPHeaderFilter{}
		}
		upsertRequestHeaders(rule.Filters[i].RequestHeaderModifier, headers)
		return
	}

	filter := &gatewayv1.HTTPHeaderFilter{}
	upsertRequestHeaders(filter, headers)
	rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{
		Type:                  gatewayv1.HTTPRouteFilterRequestHeaderModifier,
		RequestHeaderModifier: filter,
	})
}

func upsertRequestHeaders(filter *gatewayv1.HTTPHeaderFilter, headers map[string]string) {
	for name, value := range headers {
		found := false
		for i := range filter.Set {
			if string(filter.Set[i].Name) == name {
				filter.Set[i].Value = value
				found = true
				break
			}
		}
		if !found {
			filter.Set = append(filter.Set, gatewayv1.HTTPHeader{
				Name:  gatewayv1.HTTPHeaderName(name),
				Value: value,
			})
		}
	}
}
