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

package utils

import (
	"strings"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var corsResponseHeadersToStrip = []string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
}

func EnsureStripUpstreamCORSHeaders(hr *gatewayv1.HTTPRoute) {
	if hr == nil {
		return
	}
	for i := range hr.Spec.Rules {
		upsertStripUpstreamCORSHeaders(&hr.Spec.Rules[i])
	}
}

// For partial coverage, e.g. kgateway, strip only for selected rules.
func EnsureStripUpstreamCORSHeadersForRules(hr *gatewayv1.HTTPRoute, ruleIdxs map[int]struct{}) {
	if hr == nil {
		return
	}
	for i := range hr.Spec.Rules {
		if _, ok := ruleIdxs[i]; !ok {
			continue
		}
		upsertStripUpstreamCORSHeaders(&hr.Spec.Rules[i])
	}
}

func upsertStripUpstreamCORSHeaders(rule *gatewayv1.HTTPRouteRule) {
	for i := range rule.Filters {
		f := &rule.Filters[i]
		if f.Type != gatewayv1.HTTPRouteFilterResponseHeaderModifier {
			continue
		}
		if f.ResponseHeaderModifier == nil {
			f.ResponseHeaderModifier = &gatewayv1.HTTPHeaderFilter{}
		}
		seen := map[string]struct{}{}
		for _, h := range f.ResponseHeaderModifier.Remove {
			seen[strings.ToLower(h)] = struct{}{}
		}
		for _, h := range corsResponseHeadersToStrip {
			if _, ok := seen[strings.ToLower(h)]; ok {
				continue
			}
			f.ResponseHeaderModifier.Remove = append(f.ResponseHeaderModifier.Remove, h)
		}
		return
	}

	rule.Filters = append(rule.Filters, gatewayv1.HTTPRouteFilter{
		Type: gatewayv1.HTTPRouteFilterResponseHeaderModifier,
		ResponseHeaderModifier: &gatewayv1.HTTPHeaderFilter{
			Remove: append([]string(nil), corsResponseHeadersToStrip...),
		},
	})
}
