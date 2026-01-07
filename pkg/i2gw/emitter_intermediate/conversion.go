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

package emitterir

import (
	kgtwir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate/kgateway"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	ingressnginx "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate/ingressnginx"

	"k8s.io/apimachinery/pkg/types"
)

// ToEmitterIR converts a ProviderIR to an EmitterIR.
func ToEmitterIR(pIR providerir.ProviderIR) EmitterIR {
	eIR := EmitterIR{
		Gateways:           make(map[types.NamespacedName]GatewayContext),
		HTTPRoutes:         make(map[types.NamespacedName]HTTPRouteContext),
		GatewayClasses:     make(map[types.NamespacedName]GatewayClassContext),
		TLSRoutes:          make(map[types.NamespacedName]TLSRouteContext),
		TCPRoutes:          make(map[types.NamespacedName]TCPRouteContext),
		UDPRoutes:          make(map[types.NamespacedName]UDPRouteContext),
		GRPCRoutes:         make(map[types.NamespacedName]GRPCRouteContext),
		BackendTLSPolicies: make(map[types.NamespacedName]BackendTLSPolicyContext),
		ReferenceGrants:    make(map[types.NamespacedName]ReferenceGrantContext),
	}

	for k, v := range pIR.Gateways {
		eIR.Gateways[k] = GatewayContext{Gateway: v.Gateway}
	}
	for k, v := range pIR.HTTPRoutes {
		// Convert BackendSource from provider_intermediate to emitter_intermediate
		ruleBackendSources := make([][]BackendSource, len(v.RuleBackendSources))
		for i, ruleSources := range v.RuleBackendSources {
			ruleBackendSources[i] = make([]BackendSource, len(ruleSources))
			for j, src := range ruleSources {
				ruleBackendSources[i][j] = BackendSource{
					Ingress:        src.Ingress,
					Path:           src.Path,
					DefaultBackend: src.DefaultBackend,
				}
			}
		}

		// Convert provider-specific IR to emitter-specific IR
		var kgw *kgtwir.HTTPRouteIR
		if v.ProviderSpecificIR.IngressNginx != nil {
			kgw = toKgatewayHTTPRouteIR(v.ProviderSpecificIR.IngressNginx)
		}

		eIR.HTTPRoutes[k] = HTTPRouteContext{
			HTTPRoute:          v.HTTPRoute,
			Kgateway:           kgw,
			RuleBackendSources: ruleBackendSources,
		}
	}

	for k, v := range pIR.GatewayClasses {
		eIR.GatewayClasses[k] = GatewayClassContext{GatewayClass: v}
	}
	for k, v := range pIR.TLSRoutes {
		eIR.TLSRoutes[k] = TLSRouteContext{TLSRoute: v}
	}
	for k, v := range pIR.TCPRoutes {
		eIR.TCPRoutes[k] = TCPRouteContext{TCPRoute: v}
	}
	for k, v := range pIR.UDPRoutes {
		eIR.UDPRoutes[k] = UDPRouteContext{UDPRoute: v}
	}
	for k, v := range pIR.GRPCRoutes {
		eIR.GRPCRoutes[k] = GRPCRouteContext{GRPCRoute: v}
	}
	for k, v := range pIR.BackendTLSPolicies {
		eIR.BackendTLSPolicies[k] = BackendTLSPolicyContext{BackendTLSPolicy: v}
	}
	for k, v := range pIR.ReferenceGrants {
		eIR.ReferenceGrants[k] = ReferenceGrantContext{ReferenceGrant: v}
	}

	return eIR
}

func toKgatewayHTTPRouteIR(src *ingressnginx.HTTPRouteIR) *kgtwir.HTTPRouteIR {
	if src == nil {
		return nil
	}
	out := &kgtwir.HTTPRouteIR{
		Policies:              make(map[string]kgtwir.Policy, len(src.Policies)),
		RegexLocationForHost:  src.RegexLocationForHost,
		RegexForcedByUseRegex: src.RegexForcedByUseRegex,
		RegexForcedByRewrite:  src.RegexForcedByRewrite,
	}
	for name, pol := range src.Policies {
		out.Policies[name] = toKgatewayPolicy(pol)
	}
	return out
}

func toKgatewayPolicy(src ingressnginx.Policy) kgtwir.Policy {
	out := kgtwir.Policy{
		ClientBodyBufferSize: src.ClientBodyBufferSize,
		ProxyBodySize:        src.ProxyBodySize,
		ProxySendTimeout:     src.ProxySendTimeout,
		ProxyReadTimeout:     src.ProxyReadTimeout,
		ProxyConnectTimeout:  src.ProxyConnectTimeout,
		EnableAccessLog:      src.EnableAccessLog,
		SSLRedirect:          src.SSLRedirect,
		RewriteTarget:        src.RewriteTarget,
		UseRegexPaths:        src.UseRegexPaths,
	}

	if src.Cors != nil {
		c := *src.Cors
		c.AllowOrigin = append([]string(nil), src.Cors.AllowOrigin...)
		c.AllowHeaders = append([]string(nil), src.Cors.AllowHeaders...)
		c.ExposeHeaders = append([]string(nil), src.Cors.ExposeHeaders...)
		c.AllowMethods = append([]string(nil), src.Cors.AllowMethods...)
		out.Cors = (*kgtwir.CorsPolicy)(&c)
	}
	if src.ExtAuth != nil {
		ea := *src.ExtAuth
		ea.ResponseHeaders = append([]string(nil), src.ExtAuth.ResponseHeaders...)
		out.ExtAuth = (*kgtwir.ExtAuthPolicy)(&ea)
	}
	if src.BasicAuth != nil {
		ba := *src.BasicAuth
		out.BasicAuth = (*kgtwir.BasicAuthPolicy)(&ba)
	}
	if src.SessionAffinity != nil {
		sa := *src.SessionAffinity
		out.SessionAffinity = (*kgtwir.SessionAffinityPolicy)(&sa)
	}
	if src.RateLimit != nil {
		out.RateLimit = toKgatewayRateLimitPolicy(src.RateLimit)
	}
	if src.LoadBalancing != nil {
		out.LoadBalancing = toKgatewayLoadBalancingPolicy(src.LoadBalancing)
	}
	if src.BackendTLS != nil {
		bt := *src.BackendTLS
		out.BackendTLS = (*kgtwir.BackendTLSPolicy)(&bt)
	}
	if src.BackendProtocol != nil {
		bp := kgtwir.BackendProtocol(*src.BackendProtocol)
		out.BackendProtocol = &bp
	}

	// RuleBackendSources
	if len(src.RuleBackendSources) > 0 {
		out.RuleBackendSources = make([]kgtwir.PolicyIndex, 0, len(src.RuleBackendSources))
		for _, idx := range src.RuleBackendSources {
			out.RuleBackendSources = append(out.RuleBackendSources, kgtwir.PolicyIndex{
				Rule:    idx.Rule,
				Backend: idx.Backend,
			})
		}
	}

	// Backends
	if len(src.Backends) > 0 {
		out.Backends = make(map[types.NamespacedName]kgtwir.Backend, len(src.Backends))
		for k, b := range src.Backends {
			outB := kgtwir.Backend{
				Namespace: b.Namespace,
				Name:      b.Name,
				Port:      b.Port,
				Host:      b.Host,
			}
			if b.Protocol != nil {
				p := kgtwir.BackendProtocol(*b.Protocol)
				outB.Protocol = &p
			}
			out.Backends[k] = outB
		}
	}

	return out
}

func toKgatewayRateLimitPolicy(src *ingressnginx.RateLimitPolicy) *kgtwir.RateLimitPolicy {
	if src == nil {
		return nil
	}
	return &kgtwir.RateLimitPolicy{
		Limit:           src.Limit,
		Unit:            kgtwir.RateLimitUnit(src.Unit), // string-based named-type conversion
		BurstMultiplier: src.BurstMultiplier,
	}
}

func toKgatewayLoadBalancingPolicy(src *ingressnginx.LoadBalancingPolicy) *kgtwir.LoadBalancingPolicy {
	if src == nil {
		return nil
	}
	return &kgtwir.LoadBalancingPolicy{
		Strategy: kgtwir.LoadBalancingStrategy(src.Strategy), // string-based conversion
	}
}
