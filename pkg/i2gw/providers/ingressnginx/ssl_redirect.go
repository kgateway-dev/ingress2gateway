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
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	sslRedirectAnnotation      = "nginx.ingress.kubernetes.io/ssl-redirect"
	forceSSLRedirectAnnotation = "nginx.ingress.kubernetes.io/force-ssl-redirect"
)

// sslRedirectFeature extracts the "ssl-redirect" and "force-ssl-redirect" annotations
// and projects them into the provider-specific IR similarly to other annotation features.
// Both annotations are treated the same way - if either is "true", SSL redirect is enabled.
func sslRedirectFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {

	var errs field.ErrorList
	ingressPolicies := map[types.NamespacedName]*intermediate.Policy{}

	for i := range ingresses {
		ing := &ingresses[i]
		if ing.Annotations == nil {
			continue
		}

		// Check both annotations - either one can enable SSL redirect
		sslRedirectRaw := strings.TrimSpace(ing.Annotations[sslRedirectAnnotation])
		forceSSLRedirectRaw := strings.TrimSpace(ing.Annotations[forceSSLRedirectAnnotation])

		// If neither annotation is present, skip this ingress
		if sslRedirectRaw == "" && forceSSLRedirectRaw == "" {
			continue
		}

		// Parse boolean values - "true" (case-insensitive) enables SSL redirect
		// If either annotation is "true", enable SSL redirect
		sslRedirect := strings.EqualFold(sslRedirectRaw, "true") || strings.EqualFold(forceSSLRedirectRaw, "true")

		key := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		pol := ingressPolicies[key]
		if pol == nil {
			pol = &intermediate.Policy{}
			ingressPolicies[key] = pol
		}

		pol.SSLRedirect = &sslRedirect
	}

	if len(ingressPolicies) == 0 {
		return errs
	}

	// Map policies to HTTPRoutes
	ruleGroups := common.GetRuleGroups(ingresses)

	for _, rg := range ruleGroups {
		routeKey := types.NamespacedName{
			Namespace: rg.Namespace,
			Name:      common.RouteName(rg.Name, rg.Host),
		}

		httpCtx, ok := ir.HTTPRoutes[routeKey]
		if !ok {
			continue
		}

		for ruleIdx, backendSources := range httpCtx.RuleBackendSources {
			for backendIdx, src := range backendSources {
				if src.Ingress == nil {
					continue
				}

				ingKey := types.NamespacedName{
					Namespace: src.Ingress.Namespace,
					Name:      src.Ingress.Name,
				}

				pol := ingressPolicies[ingKey]
				if pol == nil || pol.SSLRedirect == nil {
					continue
				}

				// Ensure provider-specific IR exists
				if httpCtx.ProviderSpecificIR.IngressNginx == nil {
					httpCtx.ProviderSpecificIR.IngressNginx = &intermediate.IngressNginxHTTPRouteIR{
						Policies: map[string]intermediate.Policy{},
					}
				} else if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
					httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]intermediate.Policy{}
				}

				existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name]
				if existing.SSLRedirect == nil {
					existing.SSLRedirect = pol.SSLRedirect
				}

				// Dedupe (rule, backend) pairs.
				existing = existing.AddRuleBackendSources([]intermediate.PolicyIndex{
					{Rule: ruleIdx, Backend: backendIdx},
				})

				httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name] = existing
			}
		}

		ir.HTTPRoutes[routeKey] = httpCtx
	}

	return errs
}
