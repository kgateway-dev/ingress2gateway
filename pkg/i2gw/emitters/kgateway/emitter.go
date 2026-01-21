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

package kgateway

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitters/utils"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func init() {
	i2gw.EmitterConstructorByName["kgateway"] = NewEmitter
}

type Emitter struct{}

// NewEmitter returns a new instance of KgatewayEmitter.
func NewEmitter(_ *i2gw.EmitterConf) i2gw.Emitter {
	return &Emitter{}
}

// Emit converts EmitterIR to Gateway API resources plus kgateway-specific extensions.
func (e *Emitter) Emit(ir emitterir.EmitterIR) (i2gw.GatewayResources, field.ErrorList) {
	gatewayResources, errs := utils.ToGatewayResources(ir)
	if len(errs) > 0 {
		return gatewayResources, errs
	}

	// Set GatewayClassName to "kgateway" for all Gateways
	for key := range gatewayResources.Gateways {
		gateway := gatewayResources.Gateways[key]
		gateway.Spec.GatewayClassName = "kgateway"
		gatewayResources.Gateways[key] = gateway
	}

	// Track kgateway-specific resources
	var kgatewayObjs []client.Object

	// One BackendConfigPolicy per Ingress name (per namespace), aggregating all
	// Services that Ingress routes to, when BackendConfigPolicy applicable is set.
	backendCfg := map[types.NamespacedName]*kgateway.BackendConfigPolicy{}
	svcTimeouts := map[types.NamespacedName]map[string]*metav1.Duration{}

	// Track HTTPListenerPolicies per Gateway (for access logging).
	httpListenerPolicies := map[types.NamespacedName]*kgateway.HTTPListenerPolicy{}

	// Track GatewayExtensions per ingress name (for external auth).
	gatewayExtensions := map[string]*kgateway.GatewayExtension{}

	// Track Backends per (namespace, svcName) for backend-dependent features, i.e. service-upstream.
	backends := map[types.NamespacedName]*kgateway.Backend{}

	// De-dupe backend-protocol patch notifications by (ns, svc, port, appProtocol).
	backendProtoPatchSeen := map[backendProtoPatchKey]struct{}{}

	// Track HTTPRoutes that need SSL redirect splitting
	routesToSplitForSSLRedirect := map[types.NamespacedName]bool{}

	for httpRouteKey, httpRouteContext := range ir.HTTPRoutes {
		ingx := httpRouteContext.IngressNginx
		if ingx == nil {
			continue
		}

		// One TrafficPolicy per source Ingress name.
		tp := map[string]*kgateway.TrafficPolicy{}

		// Apply host-wide regex enforcement first (so rule path regex is finalized)
		applyRegexPathMatchingForHost(ingx, &httpRouteContext)

		// deterministic policy iteration
		policyNames := make([]string, 0, len(ingx.Policies))
		for name := range ingx.Policies {
			policyNames = append(policyNames, name)
		}
		sort.Strings(policyNames)

		// Rewrite-target pass: creates per-rule TPs and attaches filters itself.
		for _, name := range policyNames {
			pol := ingx.Policies[name]
			applyRewriteTargetPolicies(pol, name, httpRouteKey.Namespace, &httpRouteContext, tp)
		}

		for polSourceIngressName, pol := range ingx.Policies {
			// Normalize (rule, backend) coverage to unique pairs to avoid
			// generating duplicate filters on the same backendRef.
			coverage := uniquePolicyIndices(pol.RuleBackendSources)

			// Apply feature-specific projections (buffer, CORS, etc.).
			touched := false

			if applyBufferPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp) {
				touched = true
			}
			if applyCorsPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp) {
				touched = true
			}
			if applyRateLimitPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp) {
				touched = true
			}
			if applyTimeoutPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp) {
				touched = true
			}

			// Apply proxy-connect-timeout via BackendConfigPolicy.
			// Note: "touched" is not updated here, as this does not affect TrafficPolicy.
			applyProxyConnectTimeoutPolicy(
				pol,
				polSourceIngressName,
				httpRouteKey,
				httpRouteContext,
				backendCfg,
				svcTimeouts,
			)

			// Apply session affinity via BackendConfigPolicy.
			// Note: "touched" is not updated here, as this does not affect TrafficPolicy.
			applySessionAffinityPolicy(
				pol,
				httpRouteKey,
				httpRouteContext,
				backendCfg,
			)

			// Apply explicit round_robin load balancing via BackendConfigPolicy.
			// Note: This must come AFTER applySessionAffinityPolicy so ring-hash
			// (session affinity) always takes precedence for a given Service.
			applyLoadBalancingPolicy(
				pol,
				httpRouteKey,
				httpRouteContext,
				backendCfg,
			)

			// Apply backend TLS via BackendConfigPolicy.
			// Note: "touched" is not updated here, as this does not affect TrafficPolicy.
			applyBackendTLSPolicy(
				pol,
				httpRouteKey,
				httpRouteContext,
				backendCfg,
			)

			// backend-protocol: do NOT emit/patch Services.
			// Instead, emit an INFO notification with a safe kubectl patch command for the user
			// (and skip when service-upstream rewrote the backendRef to a kgateway Backend).
			emitBackendProtocolPatchNotifications(
				pol,
				polSourceIngressName,
				httpRouteKey,
				httpRouteContext,
				backendProtoPatchSeen,
			)

			// Apply service-upstream via Backend and HTTPRoute backendRef rewrites.
			applyServiceUpstream(
				pol,
				polSourceIngressName,
				httpRouteKey,
				&httpRouteContext,
				backends,
			)

			// Apply backend-protocol via Backend and HTTPRoute backendRef rewrites.
			applyBackendProtocol(
				pol,
				polSourceIngressName,
				httpRouteKey,
				&httpRouteContext,
				backends,
			)

			// Apply enable-access-log via HTTPListenerPolicy.
			applyAccessLogPolicy(
				pol,
				httpRouteKey,
				httpRouteContext,
				httpListenerPolicies,
			)

			// Apply auth-url via GatewayExtension and ExtAuthPolicy.
			if applyExtAuthPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp, gatewayExtensions) {
				touched = true
			}

			// Apply basic auth via TrafficPolicy.
			if applyBasicAuthPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, tp) {
				touched = true
			}

			// Check if SSL redirect is enabled (but don't apply it yet - will split route later)
			if applySSLRedirectPolicy(pol, httpRouteKey, &httpRouteContext, coverage) {
				// Mark this HTTPRoute for SSL redirect splitting
				routesToSplitForSSLRedirect[httpRouteKey] = true
			}

			if !touched {
				// No TrafficPolicy fields set for this policy; skip coverage wiring.
				continue
			}

			t := tp[polSourceIngressName]
			if t == nil {
				// Should not happen, but guard just in case.
				continue
			}

			// Coverage logic is shared across all features:
			// - If this policy covers all route backends, attach via targetRefs.
			// - Otherwise, attach via ExtensionRef filters on the covered backendRefs.
			if len(coverage) == numRules(httpRouteContext.HTTPRoute) {
				// Full coverage via targetRefs.
				t.Spec.TargetRefs = []shared.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
						Group: gatewayv1.Group("gateway.networking.k8s.io"),
						Kind:  gatewayv1.Kind("HTTPRoute"),
						Name:  gatewayv1.ObjectName(httpRouteKey.Name),
					},
				}}
			} else {
				// Partial coverage via ExtensionRef filters on backendRefs.
				for _, idx := range coverage {
					httpRouteContext.Spec.Rules[idx.Rule].BackendRefs[idx.Backend].Filters =
						append(
							httpRouteContext.Spec.Rules[idx.Rule].BackendRefs[idx.Backend].Filters,
							gatewayv1.HTTPRouteFilter{
								Type: gatewayv1.HTTPRouteFilterExtensionRef,
								ExtensionRef: &gatewayv1.LocalObjectReference{
									Group: gatewayv1.Group(TrafficPolicyGVK.Group),
									Kind:  gatewayv1.Kind(TrafficPolicyGVK.Kind),
									Name:  gatewayv1.ObjectName(t.Name),
								},
							},
						)
				}
			}
		}

		// Write back the mutated HTTPRouteContext into the IR.
		ir.HTTPRoutes[httpRouteKey] = httpRouteContext

		// Update gatewayResources with modified HTTPRoute
		gatewayResources.HTTPRoutes[httpRouteKey] = httpRouteContext.HTTPRoute

		// Collect TrafficPolicies for this HTTPRoute.
		for _, tp := range tp {
			kgatewayObjs = append(kgatewayObjs, tp)
		}
	}

	// Split HTTPRoutes that have SSL redirect enabled
	for httpRouteKey := range routesToSplitForSSLRedirect {
		httpRouteContext, exists := ir.HTTPRoutes[httpRouteKey]
		if !exists {
			continue
		}

		// Get the Gateway for this HTTPRoute
		var gatewayCtx *emitterir.GatewayContext
		if len(httpRouteContext.Spec.ParentRefs) > 0 {
			parentRef := httpRouteContext.Spec.ParentRefs[0]
			gatewayNamespace := httpRouteKey.Namespace
			if parentRef.Namespace != nil {
				gatewayNamespace = string(*parentRef.Namespace)
			}
			gatewayName := string(parentRef.Name)
			if gatewayName != "" {
				gatewayKey := types.NamespacedName{
					Namespace: gatewayNamespace,
					Name:      gatewayName,
				}
				if gw, ok := ir.Gateways[gatewayKey]; ok {
					gatewayCtx = &gw
				}
			}
		}

		if gatewayCtx == nil {
			continue
		}

		// Split the route
		httpRedirectRoute, httpsBackendRoute, success := splitHTTPRouteForSSLRedirect(
			httpRouteContext,
			httpRouteKey,
			gatewayCtx,
		)

		if success {
			// Remove the original route
			delete(ir.HTTPRoutes, httpRouteKey)
			delete(gatewayResources.HTTPRoutes, httpRouteKey)

			// Add the HTTP redirect route
			httpRedirectKey := types.NamespacedName{
				Namespace: httpRedirectRoute.Namespace,
				Name:      httpRedirectRoute.Name,
			}
			ir.HTTPRoutes[httpRedirectKey] = *httpRedirectRoute
			gatewayResources.HTTPRoutes[httpRedirectKey] = httpRedirectRoute.HTTPRoute

			// Add the HTTPS backend route if it was created
			if httpsBackendRoute != nil {
				httpsBackendKey := types.NamespacedName{
					Namespace: httpsBackendRoute.Namespace,
					Name:      httpsBackendRoute.Name,
				}
				ir.HTTPRoutes[httpsBackendKey] = *httpsBackendRoute
				gatewayResources.HTTPRoutes[httpsBackendKey] = httpsBackendRoute.HTTPRoute
			}
		}
	}

	// Collect all static Backends computed across HTTPRoutes.
	for _, b := range backends {
		kgatewayObjs = append(kgatewayObjs, b)
	}

	// Collect all BackendConfigPolicies computed across HTTPRoutes.
	for _, bcp := range backendCfg {
		kgatewayObjs = append(kgatewayObjs, bcp)
	}

	// Collect all HTTPListenerPolicies computed across HTTPRoutes.
	for _, hlp := range httpListenerPolicies {
		kgatewayObjs = append(kgatewayObjs, hlp)
	}

	// Collect all GatewayExtensions computed across HTTPRoutes.
	for _, ge := range gatewayExtensions {
		kgatewayObjs = append(kgatewayObjs, ge)
	}

	// Emit warnings for conflicting service timeouts
	for svc, ingressMap := range svcTimeouts {
		if len(ingressMap) <= 1 {
			continue
		}

		// Build message
		parts := []string{}
		for ing, d := range ingressMap {
			parts = append(parts, fmt.Sprintf("%s=%s", ing, d.Duration))
		}

		msg := fmt.Sprintf(
			"Multiple Ingresses set conflicting proxy-connect-timeout for Service %s/%s. Using lowest value. Values: %s",
			svc.Namespace,
			svc.Name,
			strings.Join(parts, ", "),
		)

		notifications.NotificationAggr.DispatchNotification(
			notifications.NewNotification(
				notifications.WarningNotification,
				msg,
			),
			"ingress-nginx",
		)
	}

	// Sort by Kind, then Namespace, then Name to make output deterministic for testing.
	sort.SliceStable(kgatewayObjs, func(i, j int) bool {
		oi, oj := kgatewayObjs[i], kgatewayObjs[j]

		gvki := oi.GetObjectKind().GroupVersionKind()
		gvkj := oj.GetObjectKind().GroupVersionKind()

		ki, kj := gvki.Kind, gvkj.Kind
		if ki != kj {
			return ki < kj
		}

		nsi, nsj := oi.GetNamespace(), oj.GetNamespace()
		if nsi != nsj {
			return nsi < nsj
		}

		return oi.GetName() < oj.GetName()
	})

	// Convert kgateway objects to unstructured and add to GatewayExtensions
	for _, obj := range kgatewayObjs {
		u, err := toUnstructured(obj)
		if err != nil {
			errs = append(errs, field.InternalError(field.NewPath("kgateway"), err))
			continue
		}
		gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *u)
	}

	return gatewayResources, errs
}
