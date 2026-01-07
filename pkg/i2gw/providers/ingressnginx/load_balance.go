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

package ingressnginx

import (
	"strings"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate/ingressnginx"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const loadBalanceAnnotation = "nginx.ingress.kubernetes.io/load-balance"

// loadBalancingFeature is a FeatureParser that projects load-balancing–related
// annotations into the Ingress NGINX ProviderSpecificIR.
func loadBalancingFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Build per-Ingress policy from the load-balance annotation.
	ing2pol := make(map[string]ingressnginx.Policy, len(ingresses))

	for _, ing := range ingresses {
		if ing.Annotations == nil {
			continue
		}

		raw, ok := ing.Annotations[loadBalanceAnnotation]
		if !ok {
			continue
		}

		value := strings.TrimSpace(strings.ToLower(raw))
		if value == "" {
			continue
		}

		// Only support round_robin; everything else is reported as an error.
		switch value {
		case "round_robin":
			pol := ing2pol[ing.Name]
			if pol.LoadBalancing == nil {
				pol.LoadBalancing = &ingressnginx.LoadBalancingPolicy{}
			}
			pol.LoadBalancing.Strategy = ingressnginx.LoadBalancingStrategyRoundRobin
			ing2pol[ing.Name] = pol
		default:
			// Unsupported modes (ewma, ip_hash, etc.).
			errs = append(errs, field.Invalid(
				field.NewPath("ingress", ing.Namespace, ing.Name, "metadata", "annotations").Key(loadBalanceAnnotation),
				raw,
				`unsupported load balancing strategy; only "round_robin" is supported`,
			))
		}
	}

	if len(ing2pol) == 0 {
		return errs
	}

	// Map policies onto HTTPRoute rules/backends using BackendSource.
	for key, httpCtx := range ir.HTTPRoutes {
		// Group BackendSources by source Ingress name.
		srcByIngress := map[string][]ingressnginx.PolicyIndex{}

		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}
				ingressName := src.Ingress.Name
				srcByIngress[ingressName] = append(
					srcByIngress[ingressName],
					ingressnginx.PolicyIndex{Rule: ruleIdx, Backend: backendIdx},
				)
			}
		}

		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &ingressnginx.HTTPRouteIR{
				Policies: map[string]ingressnginx.Policy{},
			}
		} else if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]ingressnginx.Policy{}
		}

		for ingressName, idxs := range srcByIngress {
			pol, ok := ing2pol[ingressName]
			if !ok || pol.LoadBalancing == nil {
				continue
			}

			existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName]

			// Merge load-balancing strategy into existing policy for this Ingress (if any).
			if existing.LoadBalancing == nil {
				existing.LoadBalancing = pol.LoadBalancing
			} else {
				// Latest strategy wins for now.
				existing.LoadBalancing.Strategy = pol.LoadBalancing.Strategy
			}

			// Dedupe (rule, backend) pairs.
			existing = existing.AddRuleBackendSources(idxs)

			httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName] = existing
		}

		// Write back mutated HTTPRouteContext into IR.
		ir.HTTPRoutes[key] = httpCtx
	}

	return errs
}
