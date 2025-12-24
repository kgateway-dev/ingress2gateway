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

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"

	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyCorsPolicy projects the CORS policy IR into a Kgateway TrafficPolicy,
// returning true if it modified/created a TrafficPolicy for the given ingress.
func applyCorsPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
) bool {
	if pol.Cors == nil || !pol.Cors.Enable || len(pol.Cors.AllowOrigin) == 0 {
		return false
	}

	// AllowOrigins: dedupe while preserving order.
	seenOrigins := make(map[string]struct{}, len(pol.Cors.AllowOrigin))
	var origins []gwv1.CORSOrigin
	for _, o := range pol.Cors.AllowOrigin {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if _, ok := seenOrigins[o]; ok {
			continue
		}
		seenOrigins[o] = struct{}{}
		origins = append(origins, gwv1.CORSOrigin(o))
	}
	if len(origins) == 0 {
		return false
	}

	// AllowHeaders: dedupe (case-insensitive) and map to HTTPHeaderName.
	var allowHeaders []gwv1.HTTPHeaderName
	if len(pol.Cors.AllowHeaders) > 0 {
		seenHeaders := make(map[string]struct{}, len(pol.Cors.AllowHeaders))
		for _, h := range pol.Cors.AllowHeaders {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			key := strings.ToLower(h)
			if _, ok := seenHeaders[key]; ok {
				continue
			}
			seenHeaders[key] = struct{}{}
			allowHeaders = append(allowHeaders, gwv1.HTTPHeaderName(h))
		}
	}

	// ExposeHeaders: dedupe (case-insensitive) and map to HTTPHeaderName.
	var exposeHeaders []gwv1.HTTPHeaderName
	if len(pol.Cors.ExposeHeaders) > 0 {
		seenHeaders := make(map[string]struct{}, len(pol.Cors.ExposeHeaders))
		for _, h := range pol.Cors.ExposeHeaders {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			key := strings.ToLower(h)
			if _, ok := seenHeaders[key]; ok {
				continue
			}
			seenHeaders[key] = struct{}{}
			exposeHeaders = append(exposeHeaders, gwv1.HTTPHeaderName(h))
		}
	}

	// AllowMethods: normalize to upper-case, filter to Gateway API enum, dedupe.
	var methods []gwv1.HTTPMethodWithWildcard
	if len(pol.Cors.AllowMethods) > 0 {
		seenMethods := make(map[string]struct{}, len(pol.Cors.AllowMethods))
		for _, m := range pol.Cors.AllowMethods {
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
				string(gwv1.HTTPMethodGet),
				string(gwv1.HTTPMethodHead),
				string(gwv1.HTTPMethodPost),
				string(gwv1.HTTPMethodPut),
				string(gwv1.HTTPMethodDelete),
				string(gwv1.HTTPMethodConnect),
				string(gwv1.HTTPMethodOptions),
				string(gwv1.HTTPMethodTrace),
				string(gwv1.HTTPMethodPatch):
				methods = append(methods, gwv1.HTTPMethodWithWildcard(upper))
				seenMethods[upper] = struct{}{}
			default:
				// Ignore unsupported method strings to avoid generating invalid objects.
			}
		}
	}

	t := ensureTrafficPolicy(tp, ingressName, namespace)

	if t.Spec.Cors == nil {
		t.Spec.Cors = &kgateway.CorsPolicy{}
	}
	if t.Spec.Cors.HTTPCORSFilter == nil {
		t.Spec.Cors.HTTPCORSFilter = &gwv1.HTTPCORSFilter{}
	}

	f := t.Spec.Cors.HTTPCORSFilter

	// Required-ish for nginx semantics: we only emit if we have at least one origin.
	f.AllowOrigins = origins

	// Optional knobs: only set when present in the IR.
	if pol.Cors.AllowCredentials != nil {
		f.AllowCredentials = pol.Cors.AllowCredentials
	}
	if len(allowHeaders) > 0 {
		f.AllowHeaders = allowHeaders
	}
	if len(exposeHeaders) > 0 {
		f.ExposeHeaders = exposeHeaders
	}
	if len(methods) > 0 {
		f.AllowMethods = methods
	}
	if pol.Cors.MaxAge != nil && *pol.Cors.MaxAge > 0 {
		f.MaxAge = *pol.Cors.MaxAge
	}

	return true
}
