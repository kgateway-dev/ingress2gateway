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

package kgateway

import (
	"regexp"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyRegexPathMatchingForHost mutates the HTTPRouteContext in-place to use
// Gateway API RegularExpression path matches when the provider indicates that
// ingress-nginx "regex location modifier" semantics are enforced for the host.
//
// This is the emitter-side realization of host-wide regex enforcement driven by:
//   - nginx.ingress.kubernetes.io/use-regex=true, and/or
//   - nginx.ingress.kubernetes.io/rewrite-target present anywhere for the host.
//
// Behavior:
//   - If RegexLocationForHost is true, convert any PathPrefix/Exact matches into RegularExpression matches.
//   - The regex is anchored to mimic NGINX-ish location behavior:
//   - PathPrefix "/foo"  -> "^/foo"
//   - Exact "/foo"       -> "^/foo$"
//   - Existing RegularExpression matches are preserved.
func applyRegexPathMatchingForHost(
	ingx *intermediate.IngressNginxHTTPRouteIR,
	httpRouteCtx *intermediate.HTTPRouteContext,
) bool {
	if ingx == nil || ingx.RegexLocationForHost == nil || !*ingx.RegexLocationForHost {
		return false
	}

	// Rules contributed by an ingress with use-regex=true should NOT be escaped.
	userRegexRule := map[int]bool{}
	if ingx.Policies != nil {
		for _, pol := range ingx.Policies {
			if pol.UseRegexPaths != nil && *pol.UseRegexPaths {
				for _, idx := range pol.RuleBackendSources {
					userRegexRule[idx.Rule] = true
				}
			}
		}
	}

	mutated := false
	for ri := range httpRouteCtx.Spec.Rules {
		rule := &httpRouteCtx.Spec.Rules[ri]
		for mi := range rule.Matches {
			m := &rule.Matches[mi]
			if m.Path == nil || m.Path.Value == nil || *m.Path.Value == "" {
				continue
			}

			// Preserve explicitly-regex matches.
			if m.Path.Type != nil && *m.Path.Type == gwv1.PathMatchRegularExpression {
				continue
			}

			// Default match type is PathPrefix if nil.
			matchType := gwv1.PathMatchPathPrefix
			if m.Path.Type != nil {
				matchType = *m.Path.Type
			}

			val := *m.Path.Value
			isUserRegex := userRegexRule[ri]
			lit := val
			if !isUserRegex {
				lit = regexp.QuoteMeta(val)
			}

			var re string
			switch matchType {
			case gwv1.PathMatchExact:
				re = "^" + lit + "$"
			case gwv1.PathMatchPathPrefix:
				re = "^" + lit
			default:
				continue
			}

			t := gwv1.PathMatchRegularExpression
			m.Path.Type = &t
			m.Path.Value = &re
			mutated = true
		}
	}

	return mutated
}
