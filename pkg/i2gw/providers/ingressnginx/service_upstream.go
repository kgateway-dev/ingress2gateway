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

const serviceUpstreamAnnotation = "nginx.ingress.kubernetes.io/service-upstream"

// serviceUpstreamFeature is a FeatureParser that projects the
// nginx.ingress.kubernetes.io/service-upstream annotation into the
// Ingress NGINX provider-specific IR by creating static Backends that
// point to a single upstream (Service IP/port) rather than per-Endpoint
// Pod IPs.
//
// It does NOT change the HTTPRoute here; instead it populates
// Policy.Backends and Policy.RuleBackendSources, which an emitter
// can later use to:
//  1. Emit implementation-specific backend CRs, and
//  2. Rewrite HTTPRoute backendRefs to reference those Backend CRs.
func serviceUpstreamFeature(
	ingresses []networkingv1.Ingress,
	servicePorts map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// First, determine which Ingresses have service-upstream enabled.
	//
	// We follow the same pattern as loadBalancingFeature and key by Ingress
	// name; HTTPRoutes are already namespaced, so we disambiguate via the
	// HTTPRoute namespace later.
	ingSvcUpstream := make(map[string]bool, len(ingresses))
	for _, ing := range ingresses {
		if ing.Annotations == nil {
			continue
		}
		raw, ok := ing.Annotations[serviceUpstreamAnnotation]
		if !ok {
			continue
		}
		value := strings.TrimSpace(strings.ToLower(raw))
		if value == "true" {
			ingSvcUpstream[ing.Name] = true
		}
	}

	if len(ingSvcUpstream) == 0 {
		return errs
	}

	// Walk all HTTPRoutes in the IR and project service-upstream Ingresses
	// into provider-specific policies.
	for key, httpCtx := range ir.HTTPRoutes {
		// Group BackendSources by source Ingress name.
		srcByIng := map[string][]ingressnginx.PolicyIndex{}

		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}
				ingName := src.Ingress.Name
				srcByIng[ingName] = append(
					srcByIng[ingName],
					ingressnginx.PolicyIndex{Rule: ruleIdx, Backend: backendIdx},
				)
			}
		}

		if len(srcByIng) == 0 {
			continue
		}

		// Ensure provider-specific IR is initialized.
		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &ingressnginx.HTTPRouteIR{
				Policies: map[string]ingressnginx.Policy{},
			}
		} else if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]ingressnginx.Policy{}
		}

		ingPolicies := httpCtx.ProviderSpecificIR.IngressNginx.Policies

		for ingName, idxs := range srcByIng {
			// Only process Ingresses that have service-upstream enabled.
			if !ingSvcUpstream[ingName] {
				continue
			}

			pol := ingPolicies[ingName]
			if pol.Backends == nil {
				pol.Backends = map[types.NamespacedName]ingressnginx.Backend{}
			}

			for _, idx := range idxs {
				// Bounds checks.
				if idx.Rule >= len(httpCtx.Spec.Rules) {
					continue
				}
				rule := httpCtx.Spec.Rules[idx.Rule]
				if idx.Backend >= len(rule.BackendRefs) {
					continue
				}
				br := rule.BackendRefs[idx.Backend]

				// Only rewrite core Service backends.
				if br.Group != nil && string(*br.Group) != "" {
					continue
				}
				if br.Kind != nil && string(*br.Kind) != "" && string(*br.Kind) != "Service" {
					continue
				}
				if br.Name == "" {
					continue
				}

				svcKey := types.NamespacedName{
					Namespace: key.Namespace,
					Name:      string(br.Name),
				}

				// Resolve port.
				var port int32
				if br.Port != nil {
					port = int32(*br.Port)
				}

				if port == 0 {
					// Cannot determine port; skip this backendRef.
					// TODO [danehans]: Emit a notification/warning.
					continue
				}

				// Derive a stable Backend name; the emitter will create a Backend with this name.
				backendName := svcKey.Name + "-service-upstream"
				backendKey := types.NamespacedName{
					Namespace: svcKey.Namespace,
					Name:      backendName,
				}

				// Host: if you later add ClusterIP into the IR, set Backend.IP
				// to that value instead. For now we use in-cluster DNS.
				host := svcKey.Name + "." + svcKey.Namespace + ".svc.cluster.local"

				pol.Backends[backendKey] = ingressnginx.Backend{
					Namespace: backendKey.Namespace,
					Name:      backendKey.Name,
					Port:      port,
					Host:      host,
				}
			}

			if len(pol.Backends) > 0 {
				// Track which (rule, backend) indices this Policy applies to;
				// the emitter will use this to rewrite backendRefs to Backend.
				pol = pol.AddRuleBackendSources(idxs)
				ingPolicies[ingName] = pol
			}
		}

		httpCtx.ProviderSpecificIR.IngressNginx.Policies = ingPolicies
		// Write back mutated HTTPRouteContext into IR.
		ir.HTTPRoutes[key] = httpCtx
	}

	return errs
}
