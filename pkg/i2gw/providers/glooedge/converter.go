/*
Copyright The Kubernetes Authors.

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

package glooedge

import (
	"fmt"
	"regexp"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type resourcesToIRConverter struct {
	featureParsers []func(*storage, *providerir.ProviderIR) field.ErrorList
}

func newResourcesToIRConverter() *resourcesToIRConverter {
	return &resourcesToIRConverter{
		featureParsers: []func(*storage, *providerir.ProviderIR) field.ErrorList{
			basicRoutingFeature,
		},
	}
}

func (c *resourcesToIRConverter) convert(storage *storage) (providerir.ProviderIR, field.ErrorList) {
	ir := providerir.ProviderIR{
		Gateways:   make(map[types.NamespacedName]providerir.GatewayContext),
		HTTPRoutes: make(map[types.NamespacedName]providerir.HTTPRouteContext),
	}

	var errs field.ErrorList

	for _, parseFunc := range c.featureParsers {
		parseErrs := parseFunc(storage, &ir)
		errs = append(errs, parseErrs...)
	}

	return ir, errs
}

func basicRoutingFeature(storage *storage, ir *providerir.ProviderIR) field.ErrorList {
	var errs field.ErrorList

	// Track gateways and listeners by namespace
	gatewaysByNamespace := make(map[string]*gatewayv1.Gateway)
	listenersByNamespaceHost := make(map[string]map[string]*gatewayv1.Listener)

	for _, vs := range storage.VirtualServices {
		// Initialize namespace gateway if needed
		if _, exists := gatewaysByNamespace[vs.Namespace]; !exists {
			gatewaysByNamespace[vs.Namespace] = &gatewayv1.Gateway{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "gateway.networking.k8s.io/v1",
					Kind:       "Gateway",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gloo-edge",
					Namespace: vs.Namespace,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "gloo-edge",
					Listeners:        []gatewayv1.Listener{},
				},
			}
		}

		if _, exists := listenersByNamespaceHost[vs.Namespace]; !exists {
			listenersByNamespaceHost[vs.Namespace] = make(map[string]*gatewayv1.Listener)
		}

		// Create one HTTPRoute per host in the VirtualService
		for _, host := range vs.Spec.Hosts {
			routeName := fmt.Sprintf("%s-%s", vs.Name, sanitizeHostname(host))
			routeKey := types.NamespacedName{
				Namespace: vs.Namespace,
				Name:      routeName,
			}

			// Create listener for this host if not exists
			if _, exists := listenersByNamespaceHost[vs.Namespace][host]; !exists {
				listenerName := fmt.Sprintf("%s-http", sanitizeHostname(host))
				listenersByNamespaceHost[vs.Namespace][host] = &gatewayv1.Listener{
					Name:     gatewayv1.SectionName(listenerName),
					Hostname: ptrTo(gatewayv1.Hostname(host)),
					Port:     80,
					Protocol: "HTTP",
				}
			}

			// Create HTTPRoute context
			httpRouteContext := providerir.HTTPRouteContext{
				HTTPRoute: gatewayv1.HTTPRoute{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "gateway.networking.k8s.io/v1",
						Kind:       "HTTPRoute",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      routeName,
						Namespace: vs.Namespace,
					},
					Spec: gatewayv1.HTTPRouteSpec{
						CommonRouteSpec: gatewayv1.CommonRouteSpec{
							ParentRefs: []gatewayv1.ParentReference{
								{
									Name: "gloo-edge",
								},
							},
						},
						Hostnames: []gatewayv1.Hostname{gatewayv1.Hostname(host)},
					},
				},
				RuleBackendSources: [][]providerir.BackendSource{},
			}

			// Convert routes to HTTPRoute rules
			for _, route := range vs.Spec.VirtualHost.Routes {
				rule := gatewayv1.HTTPRouteRule{}

				// Add path matches from Gloo Edge matchers
				if len(route.Matchers) > 0 {
					rule.Matches = []gatewayv1.HTTPRouteMatch{}
					for _, matcher := range route.Matchers {
						if matcher.Prefix != "" {
							rule.Matches = append(rule.Matches, gatewayv1.HTTPRouteMatch{
								Path: &gatewayv1.HTTPPathMatch{
									Type:  ptrTo(gatewayv1.PathMatchPathPrefix),
									Value: ptrTo(matcher.Prefix),
								},
							})
						}
					}
				}

				// Add backend ref from upstream
				if route.RouteAction.Single.Upstream.Name != "" {
					upstreamKey := types.NamespacedName{
						Name:      route.RouteAction.Single.Upstream.Name,
						Namespace: route.RouteAction.Single.Upstream.Namespace,
					}

					// Resolve upstream from storage
					upstream, exists := storage.Upstreams[upstreamKey]
					if !exists {
						// Fallback: create basic upstream reference with port 0
						upstream = &Upstream{
							Name:      route.RouteAction.Single.Upstream.Name,
							Namespace: route.RouteAction.Single.Upstream.Namespace,
							Port:      0,
						}
					}

					backendRef := gatewayv1.HTTPBackendRef{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name:      gatewayv1.ObjectName(upstream.Name),
								Namespace: ptrTo(gatewayv1.Namespace(upstream.Namespace)),
								Port:      ptrTo(gatewayv1.PortNumber(upstream.Port)),
							},
						},
					}
					rule.BackendRefs = []gatewayv1.HTTPBackendRef{backendRef}
				}

				httpRouteContext.HTTPRoute.Spec.Rules = append(httpRouteContext.HTTPRoute.Spec.Rules, rule)
				httpRouteContext.RuleBackendSources = append(httpRouteContext.RuleBackendSources, []providerir.BackendSource{})
			}

			ir.HTTPRoutes[routeKey] = httpRouteContext
		}
	}

	// Create Gateways with collected listeners
	for namespace, gateway := range gatewaysByNamespace {
		listeners := make([]gatewayv1.Listener, 0)
		for _, listener := range listenersByNamespaceHost[namespace] {
			listeners = append(listeners, *listener)
		}
		gateway.Spec.Listeners = listeners

		gatewayKey := types.NamespacedName{
			Namespace: namespace,
			Name:      "gloo-edge",
		}
		ir.Gateways[gatewayKey] = providerir.GatewayContext{
			Gateway: *gateway,
		}
	}

	return errs
}

func sanitizeHostname(host string) string {
	// Replace dots and special chars with hyphens for valid k8s name
	reg := regexp.MustCompile("[^a-zA-Z0-9]+")
	return reg.ReplaceAllString(host, "-")
}

func ptrTo[T any](v T) *T {
	return &v
}
