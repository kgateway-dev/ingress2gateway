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

package ingressnginx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate/ingressnginx"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
)

const nginxUseRegexAnnotation = "nginx.ingress.kubernetes.io/use-regex"

// useRegexFeature parses the nginx.ingress.kubernetes.io/use-regex annotation and sets
// HTTPRoute.ProviderSpecificIR.IngressNginx.RegexLocationForHost using host-group semantics.
//
// Semantics:
//   - Per ingress, parse boolean.
//   - For a given host-group (merged HTTPRoute), RegexForcedByUseRegex is true if ANY ingress
//     contributing a rule to that host-group has use-regex=true.
func useRegexFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Track which ingress keys have use-regex=true
	useRegexTrue := map[types.NamespacedName]bool{}

	for i := range ingresses {
		ing := &ingresses[i]
		anns := ing.Annotations
		if anns == nil {
			continue
		}

		raw, ok := anns[nginxUseRegexAnnotation]
		if !ok {
			continue
		}

		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}

		b, err := strconv.ParseBool(s)
		if err != nil {
			errs = append(errs, field.Invalid(
				field.NewPath("ingress", ing.Namespace, ing.Name, "metadata", "annotations").Key(nginxUseRegexAnnotation),
				raw,
				"use-regex must be a boolean (true/false)",
			))
			continue
		}

		if !b {
			continue
		}

		ingKey := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
		useRegexTrue[ingKey] = true

		// Validate: use-regex=true  affinity=cookie requires session-cookie-path.
		if strings.TrimSpace(anns[nginxAffinityAnnotation]) == "cookie" {
			if strings.TrimSpace(anns[nginxSessionCookiePathAnnotation]) == "" {
				errs = append(errs, field.Required(
					field.NewPath("ingress", ing.Namespace, ing.Name, "metadata", "annotations").Key(nginxSessionCookiePathAnnotation),
					"session-cookie-path must be set when use-regex=true and affinity=cookie; session cookie paths do not support regex",
				))
			}
		}
	}

	if len(useRegexTrue) == 0 {
		return errs
	}

	// Apply host-scoped derived flag per route group.
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

		// Determine if any ingress contributing to this host-group has use-regex=true.
		anyTrue := false
		for _, r := range rg.Rules {
			ing := r.Ingress
			if useRegexTrue[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}] {
				anyTrue = true
				break
			}
		}
		if !anyTrue {
			continue
		}

		// Initialize ProviderSpecificIR.IngressNginx (if needed).
		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &ingressnginx.HTTPRouteIR{
				Policies: map[string]ingressnginx.Policy{},
			}
		}
		if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]ingressnginx.Policy{}
		}

		// Host-wide: mark RegexForcedByUseRegex = true
		httpCtx.ProviderSpecificIR.IngressNginx.RegexForcedByUseRegex = true

		// If RegexLocationForHost already set, keep it OR'd.
		if httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost = ptr.To(true)
		} else {
			*httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost =
				*httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost || true
		}

		// Notification: use-regex + cookie affinity + session-cookie-path => warn/info.
		// Emit once per ingress contributing to this host-group.
		notified := map[types.NamespacedName]bool{}
		for _, r := range rg.Rules {
			ing := r.Ingress
			ingKey := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
			if notified[ingKey] || !useRegexTrue[ingKey] {
				continue
			}
			anns := ing.Annotations
			if anns == nil {
				continue
			}
			if strings.TrimSpace(anns[nginxAffinityAnnotation]) != "cookie" {
				continue
			}
			if strings.TrimSpace(anns[nginxSessionCookiePathAnnotation]) == "" {
				// Missing path is already reported as an error above.
				continue
			}

			notify(
				notifications.InfoNotification,
				fmt.Sprintf("Session cookie paths do not support regex (ingress %s/%s): %s is used for affinity=cookie while %s=true; ensure the session cookie path is a literal path",
					ing.Namespace, ing.Name,
					nginxSessionCookiePathAnnotation,
					nginxUseRegexAnnotation,
				),
				&httpCtx.HTTPRoute,
			)
			notified[ingKey] = true
		}

		// policy-scoped: attach use regex to each ingress policy with coverage.
		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}

				ingKey := types.NamespacedName{Namespace: src.Ingress.Namespace, Name: src.Ingress.Name}
				if !useRegexTrue[ingKey] {
					continue
				}

				p := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name]
				p.UseRegexPaths = ptr.To(true)
				p = p.AddRuleBackendSources([]ingressnginx.PolicyIndex{{Rule: ruleIdx, Backend: backendIdx}})
				httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name] = p
			}
		}

		ir.HTTPRoutes[routeKey] = httpCtx
	}

	return errs
}
