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
	"strconv"
	"strings"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	corsEnabledAnnotation          = "nginx.ingress.kubernetes.io/enable-cors"
	corsAllowOriginAnnotation      = "nginx.ingress.kubernetes.io/cors-allow-origin"
	corsAllowCredentialsAnnotation = "nginx.ingress.kubernetes.io/cors-allow-credentials"
	corsAllowHeadersAnnotation     = "nginx.ingress.kubernetes.io/cors-allow-headers"
	corsExposeHeadersAnnotation    = "nginx.ingress.kubernetes.io/cors-expose-headers"
	corsAllowMethodsAnnotation     = "nginx.ingress.kubernetes.io/cors-allow-methods"
	corsMaxAgeAnnotation           = "nginx.ingress.kubernetes.io/cors-max-age"
)

// corsPolicyFeature is a FeatureParser that projects CORS-related annotations into
// the Ingress NGINX ProviderSpecificIR.
func corsPolicyFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Build per-Ingress policy from the CORS annotations.
	ing2pol := make(map[string]providerir.Policy, len(ingresses))

	for _, ing := range ingresses {
		if ing.Annotations == nil {
			continue
		}

		enableRaw := strings.TrimSpace(ing.Annotations[corsEnabledAnnotation])
		if enableRaw == "" || enableRaw != "true" {
			continue
		}

		// Handle allow-origin annotation.
		allowRaw := strings.TrimSpace(ing.Annotations[corsAllowOriginAnnotation])
		if allowRaw == "" {
			// Common nginx behavior is to default to "*".
			allowRaw = "*"
		}

		var origins []string
		for _, part := range strings.Split(allowRaw, ",") {
			v := strings.TrimSpace(part)
			if v != "" {
				origins = append(origins, v)
			}
		}
		if len(origins) == 0 {
			// No valid origins (nothing to do).
			continue
		}

		// Handle allow-credentials annotation.
		var allowCreds *bool
		if raw := strings.TrimSpace(ing.Annotations[corsAllowCredentialsAnnotation]); raw != "" {
			switch {
			case strings.EqualFold(raw, "true"):
				v := true
				allowCreds = &v
			case strings.EqualFold(raw, "false"):
				v := false
				allowCreds = &v
			default:
				// Ignore invalid values.
			}
		}

		// Handle allow-headers annotation.
		var allowHeaders []string
		if raw := strings.TrimSpace(ing.Annotations[corsAllowHeadersAnnotation]); raw != "" {
			for _, part := range strings.Split(raw, ",") {
				v := strings.TrimSpace(part)
				if v != "" {
					allowHeaders = append(allowHeaders, v)
				}
			}
		}

		// Handle expose-headers annotation.
		var exposeHeaders []string
		if raw := strings.TrimSpace(ing.Annotations[corsExposeHeadersAnnotation]); raw != "" {
			for _, part := range strings.Split(raw, ",") {
				v := strings.TrimSpace(part)
				if v != "" {
					exposeHeaders = append(exposeHeaders, v)
				}
			}
		}

		// Handle allow-methods annotation.
		var allowMethods []string
		if raw := strings.TrimSpace(ing.Annotations[corsAllowMethodsAnnotation]); raw != "" {
			for _, part := range strings.Split(raw, ",") {
				v := strings.TrimSpace(part)
				if v != "" {
					allowMethods = append(allowMethods, v)
				}
			}
		}

		// Handle max-age annotation.
		var maxAge *int32
		if raw := strings.TrimSpace(ing.Annotations[corsMaxAgeAnnotation]); raw != "" {
			if secs, err := strconv.ParseInt(raw, 10, 32); err == nil && secs > 0 {
				v := int32(secs)
				maxAge = &v
			}
		}

		pol := ing2pol[ing.Name]
		if pol.Cors == nil {
			pol.Cors = &providerir.CorsPolicy{}
		}

		pol.Cors.Enable = true
		pol.Cors.AllowOrigin = append(pol.Cors.AllowOrigin, origins...)

		if allowCreds != nil {
			pol.Cors.AllowCredentials = allowCreds
		}
		if len(allowHeaders) > 0 {
			pol.Cors.AllowHeaders = append(pol.Cors.AllowHeaders, allowHeaders...)
		}
		if len(exposeHeaders) > 0 {
			pol.Cors.ExposeHeaders = append(pol.Cors.ExposeHeaders, exposeHeaders...)
		}
		if len(allowMethods) > 0 {
			pol.Cors.AllowMethods = append(pol.Cors.AllowMethods, allowMethods...)
		}
		if maxAge != nil {
			pol.Cors.MaxAge = maxAge
		}

		ing2pol[ing.Name] = pol
	}

	if len(ing2pol) == 0 {
		return errs
	}

	// Map policies onto HTTPRoute rules/backends using BackendSource.
	for key, httpCtx := range ir.HTTPRoutes {
		// Group BackendSources by source Ingress name.
		srcByIngress := map[string][]providerir.PolicyIndex{}

		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}
				ingressName := src.Ingress.Name
				srcByIngress[ingressName] = append(
					srcByIngress[ingressName],
					providerir.PolicyIndex{Rule: ruleIdx, Backend: backendIdx},
				)
			}
		}

		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &providerir.IngressNginxHTTPRouteIR{
				Policies: map[string]providerir.Policy{},
			}
		} else if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]providerir.Policy{}
		}

		for ingressName, idxs := range srcByIngress {
			pol, ok := ing2pol[ingressName]
			if !ok || pol.Cors == nil {
				continue
			}

			existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName]

			// Merge CORS into existing policy for this Ingress (if any).
			if existing.Cors == nil {
				existing.Cors = pol.Cors
			} else {
				existing.Cors.Enable = existing.Cors.Enable || pol.Cors.Enable

				// Origins: append and dedupe later in the emitter.
				existing.Cors.AllowOrigin = append(existing.Cors.AllowOrigin, pol.Cors.AllowOrigin...)

				// Latest non-nil AllowCredentials wins.
				if pol.Cors.AllowCredentials != nil {
					existing.Cors.AllowCredentials = pol.Cors.AllowCredentials
				}

				// Headers and methods: append and dedupe later in the emitter.
				if len(pol.Cors.AllowHeaders) > 0 {
					existing.Cors.AllowHeaders = append(existing.Cors.AllowHeaders, pol.Cors.AllowHeaders...)
				}
				if len(pol.Cors.ExposeHeaders) > 0 {
					existing.Cors.ExposeHeaders = append(existing.Cors.ExposeHeaders, pol.Cors.ExposeHeaders...)
				}
				if len(pol.Cors.AllowMethods) > 0 {
					existing.Cors.AllowMethods = append(existing.Cors.AllowMethods, pol.Cors.AllowMethods...)
				}

				// Latest non-nil MaxAge wins.
				if pol.Cors.MaxAge != nil {
					existing.Cors.MaxAge = pol.Cors.MaxAge
				}
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
