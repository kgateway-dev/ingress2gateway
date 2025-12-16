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
	"fmt"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applySSLRedirectPolicy marks rules that need SSL redirect handling.
// The actual route splitting happens later in the emitter.
//
// Semantics:
//   - If SSLRedirect is enabled, mark the HTTPRoute for later splitting
//   - Returns true if SSL redirect is enabled for this policy
func applySSLRedirectPolicy(
	pol intermediate.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteContext *intermediate.HTTPRouteContext,
	coverage []intermediate.PolicyIndex,
) bool {
	if pol.SSLRedirect == nil || !*pol.SSLRedirect {
		return false
	}
	// SSL redirect will be handled by splitting the route later
	// Don't modify the route here - preserve backendRefs for the HTTPS route
	return true
}

// splitHTTPRouteForSSLRedirect splits an HTTPRoute into two routes when SSL redirect is enabled:
// 1. HTTP redirect route: bound to HTTP listener, has RequestRedirect filter, no backendRefs
// 2. HTTPS backend route: bound to HTTPS listener, has backendRefs, no redirect filter
//
// Returns the HTTP redirect route, HTTPS backend route, and whether splitting was successful.
func splitHTTPRouteForSSLRedirect(
	httpRouteContext intermediate.HTTPRouteContext,
	httpRouteKey types.NamespacedName,
	gatewayCtx *intermediate.GatewayContext,
) (*intermediate.HTTPRouteContext, *intermediate.HTTPRouteContext, bool) {
	// Find HTTP and HTTPS listeners by hostname
	var httpListenerName, httpsListenerName *gwv1.SectionName
	hostname := ""
	if len(httpRouteContext.Spec.Hostnames) > 0 {
		hostname = string(httpRouteContext.Spec.Hostnames[0])
	}

	for _, listener := range gatewayCtx.Spec.Listeners {
		if listener.Protocol == gwv1.HTTPProtocolType {
			// Check if hostname matches
			if hostname == "" || (listener.Hostname != nil && string(*listener.Hostname) == hostname) {
				name := listener.Name
				httpListenerName = &name
			}
		} else if listener.Protocol == gwv1.HTTPSProtocolType {
			// Check if hostname matches
			if hostname == "" || (listener.Hostname != nil && string(*listener.Hostname) == hostname) {
				name := listener.Name
				httpsListenerName = &name
			}
		}
	}

	// If HTTPS listener doesn't exist, we can't create the HTTPS route
	// Still create HTTP redirect route though
	if httpsListenerName == nil {
		// Only create HTTP redirect route if HTTP listener exists
		if httpListenerName == nil {
			return nil, nil, false
		}
	}

	// Create HTTP redirect route
	httpRedirectRoute := intermediate.HTTPRouteContext{
		HTTPRoute:          *httpRouteContext.HTTPRoute.DeepCopy(),
		ProviderSpecificIR: httpRouteContext.ProviderSpecificIR,
		RuleBackendSources: httpRouteContext.RuleBackendSources,
	}
	httpRedirectRoute.ObjectMeta.Name = fmt.Sprintf("%s-http-redirect", httpRouteKey.Name)
	httpRedirectRoute.ObjectMeta.Namespace = httpRouteKey.Namespace

	// Update parentRefs to bind to HTTP listener
	if len(httpRedirectRoute.Spec.ParentRefs) > 0 && httpListenerName != nil {
		httpRedirectRoute.Spec.ParentRefs[0].SectionName = httpListenerName
	}

	// Add RequestRedirect filter and remove backendRefs from all rules
	for i := range httpRedirectRoute.Spec.Rules {
		// Add RequestRedirect filter
		hasRedirect := false
		for _, filter := range httpRedirectRoute.Spec.Rules[i].Filters {
			if filter.Type == gwv1.HTTPRouteFilterRequestRedirect {
				hasRedirect = true
				break
			}
		}
		if !hasRedirect {
			httpRedirectRoute.Spec.Rules[i].Filters = append(
				httpRedirectRoute.Spec.Rules[i].Filters,
				gwv1.HTTPRouteFilter{
					Type: gwv1.HTTPRouteFilterRequestRedirect,
					RequestRedirect: &gwv1.HTTPRequestRedirectFilter{
						Scheme:     ptr.To("https"),
						StatusCode: ptr.To(308),
					},
				},
			)
		}
		// Remove backendRefs (RequestRedirect filters cannot coexist with backendRefs)
		httpRedirectRoute.Spec.Rules[i].BackendRefs = nil
	}

	// Create HTTPS backend route (only if HTTPS listener exists)
	var httpsBackendRoute *intermediate.HTTPRouteContext
	if httpsListenerName != nil {
		route := intermediate.HTTPRouteContext{
			HTTPRoute:          *httpRouteContext.HTTPRoute.DeepCopy(),
			ProviderSpecificIR: httpRouteContext.ProviderSpecificIR,
			RuleBackendSources: httpRouteContext.RuleBackendSources,
		}
		route.ObjectMeta.Name = fmt.Sprintf("%s-https", httpRouteKey.Name)
		route.ObjectMeta.Namespace = httpRouteKey.Namespace
		httpsBackendRoute = &route

		// Update parentRefs to bind to HTTPS listener
		if len(httpsBackendRoute.Spec.ParentRefs) > 0 {
			httpsBackendRoute.Spec.ParentRefs[0].SectionName = httpsListenerName
		}

		// Remove any RequestRedirect filters from HTTPS route
		for i := range httpsBackendRoute.Spec.Rules {
			var filtersWithoutRedirect []gwv1.HTTPRouteFilter
			for _, filter := range httpsBackendRoute.Spec.Rules[i].Filters {
				if filter.Type != gwv1.HTTPRouteFilterRequestRedirect {
					filtersWithoutRedirect = append(filtersWithoutRedirect, filter)
				}
			}
			httpsBackendRoute.Spec.Rules[i].Filters = filtersWithoutRedirect
		}
		// Keep backendRefs for HTTPS route
	}

	return &httpRedirectRoute, httpsBackendRoute, true
}
