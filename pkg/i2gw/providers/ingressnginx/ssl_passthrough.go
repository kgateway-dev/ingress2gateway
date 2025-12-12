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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const (
	sslPassthroughAnnotation = "nginx.ingress.kubernetes.io/ssl-passthrough"
)

// sslPassthroughFeature extracts the "ssl-passthrough" annotation and converts
// HTTPRoutes to TLSRoutes with TLS passthrough Gateway listeners.
// When ssl-passthrough is enabled, TLS termination happens at the backend service
// rather than at the ingress controller, requiring TLSRoute instead of HTTPRoute.
func sslPassthroughFeature(
	ingresses []networkingv1.Ingress,
	servicePorts map[types.NamespacedName]map[string]int32,
	ir *intermediate.IR,
) field.ErrorList {

	var errs field.ErrorList

	// Track ingresses with ssl-passthrough enabled
	passthroughIngresses := make(map[types.NamespacedName]bool)

	// First pass: identify ingresses with ssl-passthrough annotation
	for i := range ingresses {
		ing := &ingresses[i]
		if ing.Annotations == nil {
			continue
		}

		sslPassthroughRaw := strings.TrimSpace(ing.Annotations[sslPassthroughAnnotation])
		if strings.EqualFold(sslPassthroughRaw, "true") {
			key := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
			passthroughIngresses[key] = true
		}
	}

	if len(passthroughIngresses) == 0 {
		return errs
	}

	// Get rule groups to map ingresses to HTTPRoutes
	ruleGroups := common.GetRuleGroups(ingresses)

	// Track HTTPRoutes to remove and TLSRoutes to create
	routesToRemove := make(map[types.NamespacedName]struct{})
	tlsRoutesToAdd := make(map[types.NamespacedName]gatewayv1alpha2.TLSRoute)

	// Second pass: process HTTPRoutes and convert passthrough ones to TLSRoutes
	for _, rg := range ruleGroups {
		// Check if any ingress in this rule group has ssl-passthrough
		hasPassthrough := false
		for _, rule := range rg.Rules {
			ingKey := types.NamespacedName{
				Namespace: rule.Ingress.Namespace,
				Name:      rule.Ingress.Name,
			}
			if passthroughIngresses[ingKey] {
				hasPassthrough = true
				break
			}
		}

		if !hasPassthrough {
			continue
		}

		// Find the corresponding HTTPRoute
		routeKey := types.NamespacedName{
			Namespace: rg.Namespace,
			Name:      common.RouteName(rg.Name, rg.Host),
		}

		httpRouteCtx, ok := ir.HTTPRoutes[routeKey]
		if !ok {
			continue
		}

		// Mark HTTPRoute for removal
		routesToRemove[routeKey] = struct{}{}

		// Create TLSRoute
		tlsRoute := gatewayv1alpha2.TLSRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      routeKey.Name,
				Namespace: routeKey.Namespace,
			},
			Spec: gatewayv1alpha2.TLSRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: httpRouteCtx.Spec.ParentRefs,
				},
			},
			Status: gatewayv1alpha2.TLSRouteStatus{
				RouteStatus: gatewayv1.RouteStatus{
					Parents: []gatewayv1.RouteParentStatus{},
				},
			},
		}
		tlsRoute.SetGroupVersionKind(common.TLSRouteGVK)

		// Set hostnames if present
		if len(httpRouteCtx.Spec.Hostnames) > 0 {
			tlsRoute.Spec.Hostnames = httpRouteCtx.Spec.Hostnames
		}

		// Convert HTTPRoute rules to TLSRoute rules
		// For TLS passthrough, we need to route to backend services on port 443 (or the port specified)
		for _, httpRule := range httpRouteCtx.Spec.Rules {
			tlsRule := gatewayv1alpha2.TLSRouteRule{}

			// Convert backendRefs from HTTPBackendRef to BackendRef
			for _, httpBackendRef := range httpRule.BackendRefs {
				backendRef := gatewayv1.BackendRef{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: httpBackendRef.Name,
					},
				}

				// Copy namespace if specified
				if httpBackendRef.Namespace != nil {
					backendRef.Namespace = httpBackendRef.Namespace
				}

				// Copy port (default to 443 for TLS if not specified)
				if httpBackendRef.Port != nil {
					backendRef.Port = httpBackendRef.Port
				} else {
					port443 := gatewayv1.PortNumber(443)
					backendRef.Port = &port443
				}

				// Copy weight if specified
				if httpBackendRef.Weight != nil {
					backendRef.Weight = httpBackendRef.Weight
				}

				tlsRule.BackendRefs = append(tlsRule.BackendRefs, backendRef)
			}

			if len(tlsRule.BackendRefs) > 0 {
				tlsRoute.Spec.Rules = append(tlsRoute.Spec.Rules, tlsRule)
			}
		}

		if len(tlsRoute.Spec.Rules) > 0 {
			tlsRoutesToAdd[routeKey] = tlsRoute
		}
	}

	// Remove HTTPRoutes
	for routeKey := range routesToRemove {
		delete(ir.HTTPRoutes, routeKey)
	}

	// Add TLSRoutes
	for routeKey, tlsRoute := range tlsRoutesToAdd {
		ir.TLSRoutes[routeKey] = tlsRoute
	}

	// Modify Gateways to add TLS passthrough listeners
	for routeKey, tlsRoute := range tlsRoutesToAdd {
		// Get parent gateway references
		for _, parentRef := range tlsRoute.Spec.ParentRefs {
			gatewayNamespace := routeKey.Namespace
			if parentRef.Namespace != nil {
				gatewayNamespace = string(*parentRef.Namespace)
			}

			gatewayName := string(parentRef.Name)
			if gatewayName == "" {
				continue
			}

			gatewayKey := types.NamespacedName{
				Namespace: gatewayNamespace,
				Name:      gatewayName,
			}

			gatewayCtx, ok := ir.Gateways[gatewayKey]
			if !ok {
				continue
			}

			// Determine listener name and port
			// Use port 8443 as shown in the user's example, or 443 if hostname is specified
			listenerPort := gatewayv1.PortNumber(8443)
			listenerName := "tls-passthrough"

			// If hostname is specified, create a more specific listener name
			if len(tlsRoute.Spec.Hostnames) > 0 && tlsRoute.Spec.Hostnames[0] != "" {
				hostname := string(tlsRoute.Spec.Hostnames[0])
				listenerName = common.NameFromHost(hostname) + "-tls-passthrough"
				listenerPort = 443 // Use standard HTTPS port when hostname is specified
			}

			// Check if TLS passthrough listener already exists
			listenerExists := false
			for _, existingListener := range gatewayCtx.Spec.Listeners {
				if existingListener.Name == gatewayv1.SectionName(listenerName) {
					listenerExists = true
					break
				}
			}

			// Remove HTTP listeners that were created for this passthrough ingress
			// The common converter creates HTTP listeners, but for TLS passthrough we only want TLS listeners
			var filteredListeners []gatewayv1.Listener
			for _, existingListener := range gatewayCtx.Spec.Listeners {
				// Remove HTTP listeners that match the hostname of this TLSRoute
				if existingListener.Protocol == gatewayv1.HTTPProtocolType {
					if len(tlsRoute.Spec.Hostnames) > 0 && tlsRoute.Spec.Hostnames[0] != "" {
						hostname := string(tlsRoute.Spec.Hostnames[0])
						if existingListener.Hostname != nil && string(*existingListener.Hostname) == hostname {
							// Skip this HTTP listener as it's for passthrough
							continue
						}
					}
				}
				filteredListeners = append(filteredListeners, existingListener)
			}
			gatewayCtx.Spec.Listeners = filteredListeners

			if !listenerExists {
				// Create TLS passthrough listener
				tlsMode := gatewayv1.TLSModePassthrough
				listener := gatewayv1.Listener{
					Name:     gatewayv1.SectionName(listenerName),
					Protocol: gatewayv1.TLSProtocolType,
					Port:     listenerPort,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: &tlsMode,
					},
				}

				// Set hostname if specified
				if len(tlsRoute.Spec.Hostnames) > 0 && tlsRoute.Spec.Hostnames[0] != "" {
					hostname := gatewayv1.Hostname(tlsRoute.Spec.Hostnames[0])
					listener.Hostname = &hostname
				}

				gatewayCtx.Spec.Listeners = append(gatewayCtx.Spec.Listeners, listener)
				ir.Gateways[gatewayKey] = gatewayCtx

				// Update TLSRoute parentRef to reference the specific listener
				for i := range ir.TLSRoutes[routeKey].Spec.ParentRefs {
					sectionName := gatewayv1.SectionName(listenerName)
					ir.TLSRoutes[routeKey].Spec.ParentRefs[i].SectionName = &sectionName
				}
			}
		}
	}

	return errs
}
