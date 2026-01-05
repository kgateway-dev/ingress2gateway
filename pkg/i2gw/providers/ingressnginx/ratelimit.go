/*
Copyright 2024 The Kubernetes Authors.

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

package ingressnginx

import (
	"strconv"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate/ingressnginx"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	nginxLimitRPS             = "nginx.ingress.kubernetes.io/limit-rps"
	nginxLimitRPM             = "nginx.ingress.kubernetes.io/limit-rpm"
	nginxLimitBurstMultiplier = "nginx.ingress.kubernetes.io/limit-burst-multiplier"
)

// rateLimitPolicyFeature parses the rate limiting annotations from Ingresses
// and records them as ingress-nginx specific IR Policies.
func rateLimitPolicyFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Build a map of raw per-Ingress RateLimitPolicy
	perIngress := map[string]*ingressnginx.RateLimitPolicy{}

	for _, ing := range ingresses {
		anns := ing.GetAnnotations()
		if anns == nil {
			continue
		}

		var (
			limit     int32
			unit      ingressnginx.RateLimitUnit
			hasLimit  bool
			burstMult int32 = 1
		)

		// Prefer RPS over RPM
		if v, ok := anns[nginxLimitRPS]; ok && v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				limit = int32(parsed)
				unit = ingressnginx.RateLimitUnitRPS
				hasLimit = true
			}
		}
		if !hasLimit {
			if v, ok := anns[nginxLimitRPM]; ok && v != "" {
				if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
					limit = int32(parsed)
					unit = ingressnginx.RateLimitUnitRPM
					hasLimit = true
				}
			}
		}

		if !hasLimit {
			continue
		}

		if v, ok := anns[nginxLimitBurstMultiplier]; ok && v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				burstMult = int32(parsed)
			}
		}

		perIngress[ing.Name] = &ingressnginx.RateLimitPolicy{
			Limit:           limit,
			Unit:            unit,
			BurstMultiplier: burstMult,
		}
	}

	if len(perIngress) == 0 {
		return errs // nothing to do
	}

	// For each HTTPRoute, map sources to provider-specific IR Policies
	for routeKey, httpCtx := range ir.HTTPRoutes {
		// Ensure provider IR exists
		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx =
				&ingressnginx.HTTPRouteIR{Policies: map[string]ingressnginx.Policy{}}
		}
		if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]ingressnginx.Policy{}
		}

		// Group PolicyIndex entries by ingress name
		sourceIndexes := map[string][]ingressnginx.PolicyIndex{}
		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}
				name := src.Ingress.Name
				sourceIndexes[name] = append(
					sourceIndexes[name],
					ingressnginx.PolicyIndex{Rule: ruleIdx, Backend: backIdx},
				)
			}
		}

		// For each ingress source, attach the rate limit policy
		for ingressName, idxs := range sourceIndexes {
			rl, exists := perIngress[ingressName]
			if !exists {
				continue
			}

			// Fetch/Create provider policy
			existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName]

			// Merge rate limit settings
			if existing.RateLimit == nil {
				existing.RateLimit = rl
			} else {
				// Merge semantics = "last writer wins" (consistent with other providers)
				existing.RateLimit.Limit = rl.Limit
				existing.RateLimit.Unit = rl.Unit
				if rl.BurstMultiplier > 0 {
					existing.RateLimit.BurstMultiplier = rl.BurstMultiplier
				}
			}

			// Dedupe (rule, backend) pairs.
			existing = existing.AddRuleBackendSources(idxs)

			httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName] = existing
		}

		// Write back updated route context
		ir.HTTPRoutes[routeKey] = httpCtx
	}

	return errs
}
