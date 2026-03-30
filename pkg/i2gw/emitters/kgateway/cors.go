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
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitters/utils"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EmitCors projects provider-neutral per-rule CORS intent into section-scoped
// Kgateway TrafficPolicies and strips upstream CORS response headers on the
// affected HTTPRoute rules.
func (e *Emitter) EmitCors(ir emitterir.EmitterIR, gwResources *i2gw.GatewayResources) {
	for httpRouteKey, ctx := range ir.HTTPRoutes {
		httpRoute := gwResources.HTTPRoutes[httpRouteKey]
		appliedRules := map[int]struct{}{}
		for idx := range httpRoute.Spec.Rules {
			if idx < 0 || idx >= len(ctx.Spec.Rules) {
				continue
			}

			rule := &httpRoute.Spec.Rules[idx]

			var filter *gatewayv1.HTTPCORSFilter
			newFilters := make([]gatewayv1.HTTPRouteFilter, 0, len(rule.Filters))
			for _, existingFilter := range rule.Filters {
				if existingFilter.Type == gatewayv1.HTTPRouteFilterCORS && existingFilter.CORS != nil {
					cfg := &emitterir.CORSConfig{HTTPCORSFilter: *existingFilter.CORS}
					filter = buildCorsFilter(corsConfigToPolicy(cfg))
					continue
				}
				newFilters = append(newFilters, existingFilter)
			}

			if filter == nil {
				filter = buildCorsFilter(corsConfigToPolicy(ctx.CorsPolicyByRuleIdx[idx]))
			}
			if filter == nil {
				continue
			}

			trafficPolicy := e.getOrBuildTrafficPolicy(ctx, e.getSectionName(ctx, idx), idx)
			trafficPolicy.Spec.Cors = &kgateway.CorsPolicy{
				HTTPCORSFilter: filter,
			}
			rule.Filters = newFilters
			appliedRules[idx] = struct{}{}
		}

		if len(appliedRules) == 0 {
			continue
		}

		utils.EnsureStripUpstreamCORSHeadersForRules(&httpRoute, appliedRules)
		gwResources.HTTPRoutes[httpRouteKey] = httpRoute
	}
}

func corsConfigToPolicy(cfg *emitterir.CORSConfig) *emitterir.CorsPolicy {
	if cfg == nil {
		return nil
	}

	policy := &emitterir.CorsPolicy{
		Enable: true,
	}
	for _, origin := range cfg.AllowOrigins {
		policy.AllowOrigin = append(policy.AllowOrigin, string(origin))
	}
	if cfg.AllowCredentials != nil {
		value := *cfg.AllowCredentials
		policy.AllowCredentials = &value
	}
	for _, header := range cfg.AllowHeaders {
		policy.AllowHeaders = append(policy.AllowHeaders, string(header))
	}
	for _, header := range cfg.ExposeHeaders {
		policy.ExposeHeaders = append(policy.ExposeHeaders, string(header))
	}
	for _, method := range cfg.AllowMethods {
		policy.AllowMethods = append(policy.AllowMethods, string(method))
	}
	if cfg.MaxAge > 0 {
		value := cfg.MaxAge
		policy.MaxAge = &value
	}
	return policy
}

func buildCorsFilter(cors *emitterir.CorsPolicy) *gatewayv1.HTTPCORSFilter {
	if cors == nil || !cors.Enable || len(cors.AllowOrigin) == 0 {
		return nil
	}

	// AllowOrigins: dedupe while preserving order.
	seenOrigins := make(map[string]struct{}, len(cors.AllowOrigin))
	var origins []gatewayv1.CORSOrigin
	for _, o := range cors.AllowOrigin {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if _, ok := seenOrigins[o]; ok {
			continue
		}
		seenOrigins[o] = struct{}{}
		origins = append(origins, gatewayv1.CORSOrigin(o))
	}
	if len(origins) == 0 {
		return nil
	}

	// AllowHeaders: dedupe (case-insensitive) and map to HTTPHeaderName.
	var allowHeaders []gatewayv1.HTTPHeaderName
	if len(cors.AllowHeaders) > 0 {
		seenHeaders := make(map[string]struct{}, len(cors.AllowHeaders))
		for _, h := range cors.AllowHeaders {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			key := strings.ToLower(h)
			if _, ok := seenHeaders[key]; ok {
				continue
			}
			seenHeaders[key] = struct{}{}
			allowHeaders = append(allowHeaders, gatewayv1.HTTPHeaderName(h))
		}
	}

	// ExposeHeaders: dedupe (case-insensitive) and map to HTTPHeaderName.
	var exposeHeaders []gatewayv1.HTTPHeaderName
	if len(cors.ExposeHeaders) > 0 {
		seenHeaders := make(map[string]struct{}, len(cors.ExposeHeaders))
		for _, h := range cors.ExposeHeaders {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			key := strings.ToLower(h)
			if _, ok := seenHeaders[key]; ok {
				continue
			}
			seenHeaders[key] = struct{}{}
			exposeHeaders = append(exposeHeaders, gatewayv1.HTTPHeaderName(h))
		}
	}

	// AllowMethods: normalize to upper-case, filter to Gateway API enum, dedupe.
	var methods []gatewayv1.HTTPMethodWithWildcard
	if len(cors.AllowMethods) > 0 {
		seenMethods := make(map[string]struct{}, len(cors.AllowMethods))
		for _, m := range cors.AllowMethods {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			upper := strings.ToUpper(m)
			if _, ok := seenMethods[upper]; ok {
				continue
			}

			switch upper {
			case "*",
				string(gatewayv1.HTTPMethodGet),
				string(gatewayv1.HTTPMethodHead),
				string(gatewayv1.HTTPMethodPost),
				string(gatewayv1.HTTPMethodPut),
				string(gatewayv1.HTTPMethodDelete),
				string(gatewayv1.HTTPMethodConnect),
				string(gatewayv1.HTTPMethodOptions),
				string(gatewayv1.HTTPMethodTrace),
				string(gatewayv1.HTTPMethodPatch):
				methods = append(methods, gatewayv1.HTTPMethodWithWildcard(upper))
				seenMethods[upper] = struct{}{}
			default:
				// Ignore unsupported method strings to avoid generating invalid objects.
			}
		}
	}

	filter := &gatewayv1.HTTPCORSFilter{
		AllowOrigins: origins,
	}
	if cors.AllowCredentials != nil {
		filter.AllowCredentials = cors.AllowCredentials
	}
	if len(allowHeaders) > 0 {
		filter.AllowHeaders = allowHeaders
	}
	if len(exposeHeaders) > 0 {
		filter.ExposeHeaders = exposeHeaders
	}
	if len(methods) > 0 {
		filter.AllowMethods = methods
	}
	if cors.MaxAge != nil && *cors.MaxAge > 0 {
		filter.MaxAge = *cors.MaxAge
	}

	return filter
}
