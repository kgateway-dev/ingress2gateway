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
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyProxyConnectTimeoutPolicy projects the ProxyConnectTimeout IR policy into one or more
// Kgateway BackendConfigPolicies.
func applyProxyConnectTimeoutPolicy(
	pol providerir.Policy,
	ingressName string,
	httpRouteKey types.NamespacedName,
	httpRouteCtx emitterir.HTTPRouteContext,
	backendCfg map[types.NamespacedName]*kgateway.BackendConfigPolicy,
	svcTimeouts map[types.NamespacedName]map[string]*metav1.Duration,
) bool {
	if pol.ProxyConnectTimeout == nil {
		return false
	}

	for _, idx := range pol.RuleBackendSources {
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := rule.BackendRefs[idx.Backend]

		if br.BackendRef.Group != nil && *br.BackendRef.Group != "" {
			continue
		}
		if br.BackendRef.Kind != nil && *br.BackendRef.Kind != "Service" {
			continue
		}

		svcName := string(br.BackendRef.Name)
		if svcName == "" {
			continue
		}

		svcKey := types.NamespacedName{
			Namespace: httpRouteKey.Namespace,
			Name:      svcName,
		}

		// Track per-Service timeout contributors
		if svcTimeouts[svcKey] == nil {
			svcTimeouts[svcKey] = map[string]*metav1.Duration{}
		}
		svcTimeouts[svcKey][ingressName] = pol.ProxyConnectTimeout

		// Create or reuse BackendConfigPolicy per Service
		bcp, exists := backendCfg[svcKey]
		if !exists {
			// Use a generic name that works for all backend config features
			policyName := svcName + "-backend-config"
			bcp = &kgateway.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: httpRouteKey.Namespace,
				},
				Spec: kgateway.BackendConfigPolicySpec{
					TargetRefs: []shared.LocalPolicyTargetReference{
						{
							Group: "",
							Kind:  "Service",
							Name:  gatewayv1.ObjectName(svcName),
						},
					},
					ConnectTimeout: pol.ProxyConnectTimeout,
				},
			}
			bcp.SetGroupVersionKind(BackendConfigPolicyGVK)
			backendCfg[svcKey] = bcp
		} else {
			// enforce "lowest timeout wins"
			cur := bcp.Spec.ConnectTimeout.Duration
			next := pol.ProxyConnectTimeout.Duration
			if next < cur {
				bcp.Spec.ConnectTimeout = pol.ProxyConnectTimeout
			}
		}
	}

	return true
}

// applySessionAffinityPolicy projects the SessionAffinity IR policy into one or more
// Kgateway BackendConfigPolicies.
func applySessionAffinityPolicy(
	pol providerir.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteCtx emitterir.HTTPRouteContext,
	backendCfg map[types.NamespacedName]*kgateway.BackendConfigPolicy,
) bool {
	if pol.SessionAffinity == nil {
		return false
	}

	sessionAffinity := pol.SessionAffinity

	for _, idx := range pol.RuleBackendSources {
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := rule.BackendRefs[idx.Backend]

		if br.BackendRef.Group != nil && *br.BackendRef.Group != "" {
			continue
		}
		if br.BackendRef.Kind != nil && *br.BackendRef.Kind != "Service" {
			continue
		}

		svcName := string(br.BackendRef.Name)
		if svcName == "" {
			continue
		}

		svcKey := types.NamespacedName{
			Namespace: httpRouteKey.Namespace,
			Name:      svcName,
		}

		// Create or reuse BackendConfigPolicy per Service
		bcp, exists := backendCfg[svcKey]
		if !exists {
			// Determine policy name - use a generic name that works for both
			// session affinity and other backend config features
			policyName := svcName + "-backend-config"
			bcp = &kgateway.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: httpRouteKey.Namespace,
				},
				Spec: kgateway.BackendConfigPolicySpec{
					TargetRefs: []shared.LocalPolicyTargetReference{
						{
							Group: "",
							Kind:  "Service",
							Name:  gatewayv1.ObjectName(svcName),
						},
					},
				},
			}
			bcp.SetGroupVersionKind(BackendConfigPolicyGVK)
			backendCfg[svcKey] = bcp
		}

		// Build hash policy with cookie configuration
		cookieHashPolicy := &kgateway.Cookie{
			Name: sessionAffinity.CookieName,
		}

		if sessionAffinity.CookiePath != "" {
			cookieHashPolicy.Path = ptr.To(sessionAffinity.CookiePath)
		}

		if sessionAffinity.CookieExpires != nil {
			cookieHashPolicy.TTL = sessionAffinity.CookieExpires
		}

		if sessionAffinity.CookieSecure != nil {
			cookieHashPolicy.Secure = ptr.To(*sessionAffinity.CookieSecure)
		}

		if sessionAffinity.CookieSameSite != "" {
			cookieHashPolicy.SameSite = ptr.To(sessionAffinity.CookieSameSite)
		}

		// Set loadBalancer.ringHash.hashPolicies
		if bcp.Spec.LoadBalancer == nil {
			bcp.Spec.LoadBalancer = &kgateway.LoadBalancer{}
		}
		if bcp.Spec.LoadBalancer.RingHash == nil {
			bcp.Spec.LoadBalancer.RingHash = &kgateway.LoadBalancerRingHashConfig{}
		}
		// Replace existing hash policies with the new cookie-based one
		// (only one hash policy per service is typically needed)
		bcp.Spec.LoadBalancer.RingHash.HashPolicies = []kgateway.HashPolicy{
			{
				Cookie: cookieHashPolicy,
			},
		}
	}

	return true
}

// applyAccessLogPolicy projects the EnableAccessLog IR policy into one or more
// Kgateway HTTPListenerPolicies.
func applyAccessLogPolicy(
	pol providerir.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteCtx emitterir.HTTPRouteContext,
	httpListenerPolicies map[types.NamespacedName]*kgateway.HTTPListenerPolicy,
) bool {
	if pol.EnableAccessLog == nil || !*pol.EnableAccessLog {
		return false
	}

	// Get Gateway references from HTTPRoute ParentRefs.
	if len(httpRouteCtx.Spec.ParentRefs) == 0 {
		return false
	}

	// Process each ParentRef (Gateway reference).
	for _, parentRef := range httpRouteCtx.Spec.ParentRefs {
		// Determine Gateway namespace (defaults to HTTPRoute namespace if not specified).
		gatewayNamespace := httpRouteKey.Namespace
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

		// Create HTTPListenerPolicy per Gateway if it doesn't exist.
		if _, exists := httpListenerPolicies[gatewayKey]; !exists {
			hlp := &kgateway.HTTPListenerPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gatewayName + "-access-log",
					Namespace: gatewayNamespace,
				},
				Spec: kgateway.HTTPListenerPolicySpec{
					TargetRefs: []shared.LocalPolicyTargetReference{
						{
							Group: "",
							Kind:  "Gateway",
							Name:  gatewayv1.ObjectName(gatewayName),
						},
					},
					HTTPSettings: kgateway.HTTPSettings{
						AccessLog: []kgateway.AccessLog{
							{
								FileSink: &kgateway.FileSink{
									Path:         "/dev/stdout",
									StringFormat: ptr.To(`[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%" %RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION% %RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)% "%REQ(X-FORWARDED-FOR)%" "%REQ(USER-AGENT)%" "%REQ(X-REQUEST-ID)%" "%REQ(:AUTHORITY)%" "%UPSTREAM_HOST%"%n`),
								},
							},
						},
					},
				},
			}
			hlp.SetGroupVersionKind(HTTPListenerPolicyGVK)
			httpListenerPolicies[gatewayKey] = hlp
		}
		// If policy already exists, we don't need to modify it since access log is already enabled.
	}

	return true
}
