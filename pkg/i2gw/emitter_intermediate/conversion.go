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
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
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
		eIR.HTTPRoutes[k] = HTTPRouteContext{
			HTTPRoute:          v.HTTPRoute,
			IngressNginx:       convertIngressNginxHTTPRouteIR(v.ProviderSpecificIR.IngressNginx),
			RuleBackendSources: convertBackendSources(v.RuleBackendSources),
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

func convertBackendSources(in [][]providerir.BackendSource) [][]BackendSource {
	if in == nil {
		return nil
	}
	out := make([][]BackendSource, len(in))
	for i, ruleSources := range in {
		out[i] = make([]BackendSource, len(ruleSources))
		for j, src := range ruleSources {
			out[i][j] = BackendSource{
				Ingress:        src.Ingress,
				Path:           src.Path,
				DefaultBackend: src.DefaultBackend,
			}
		}
	}
	return out
}

func convertIngressNginxHTTPRouteIR(in *providerir.IngressNginxHTTPRouteIR) *IngressNginxHTTPRouteIR {
	if in == nil {
		return nil
	}

	out := &IngressNginxHTTPRouteIR{
		RegexLocationForHost:  in.RegexLocationForHost,
		RegexForcedByUseRegex: in.RegexForcedByUseRegex,
		RegexForcedByRewrite:  in.RegexForcedByRewrite,
	}
	if in.Policies != nil {
		out.Policies = make(map[string]IngressNginxPolicy, len(in.Policies))
		for ingressName, policy := range in.Policies {
			out.Policies[ingressName] = convertIngressNginxPolicy(policy)
		}
	}

	return out
}

func convertIngressNginxPolicy(in providerir.IngressNginxPolicy) IngressNginxPolicy {
	out := IngressNginxPolicy{
		ClientBodyBufferSize: in.ClientBodyBufferSize,
		ProxyBodySize:        in.ProxyBodySize,
		Cors:                 convertIngressNginxCorsPolicy(in.Cors),
		RateLimit:            convertIngressNginxRateLimitPolicy(in.RateLimit),
		ProxySendTimeout:     in.ProxySendTimeout,
		ProxyReadTimeout:     in.ProxyReadTimeout,
		ProxyConnectTimeout:  in.ProxyConnectTimeout,
		EnableAccessLog:      in.EnableAccessLog,
		ExtAuth:              convertIngressNginxExtAuthPolicy(in.ExtAuth),
		BasicAuth:            convertIngressNginxBasicAuthPolicy(in.BasicAuth),
		SessionAffinity:      convertIngressNginxSessionAffinityPolicy(in.SessionAffinity),
		LoadBalancing:        convertIngressNginxBackendLoadBalancingPolicy(in.LoadBalancing),
		BackendTLS:           convertIngressNginxBackendTLSPolicy(in.BackendTLS),
		BackendProtocol:      convertIngressNginxBackendProtocol(in.BackendProtocol),
		SSLRedirect:          in.SSLRedirect,
		RewriteTarget:        in.RewriteTarget,
		UseRegexPaths:        in.UseRegexPaths,
		RuleBackendSources:   convertIngressNginxPolicyIndices(in.RuleBackendSources),
		Backends:             convertIngressNginxBackends(in.Backends),
	}
	if len(out.RuleBackendSources) > 0 {
		out.ruleBackendIndexSet = make(map[IngressNginxPolicyIndex]struct{}, len(out.RuleBackendSources))
		for _, idx := range out.RuleBackendSources {
			out.ruleBackendIndexSet[idx] = struct{}{}
		}
	}

	return out
}

func convertIngressNginxPolicyIndices(in []providerir.IngressNginxPolicyIndex) []IngressNginxPolicyIndex {
	if in == nil {
		return nil
	}
	out := make([]IngressNginxPolicyIndex, len(in))
	for i := range in {
		out[i] = IngressNginxPolicyIndex{
			Rule:    in[i].Rule,
			Backend: in[i].Backend,
		}
	}
	return out
}

func convertIngressNginxCorsPolicy(in *providerir.IngressNginxCorsPolicy) *IngressNginxCorsPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxCorsPolicy{
		Enable:           in.Enable,
		AllowOrigin:      cloneStringSlice(in.AllowOrigin),
		AllowCredentials: in.AllowCredentials,
		AllowHeaders:     cloneStringSlice(in.AllowHeaders),
		ExposeHeaders:    cloneStringSlice(in.ExposeHeaders),
		AllowMethods:     cloneStringSlice(in.AllowMethods),
		MaxAge:           in.MaxAge,
	}
}

func convertIngressNginxExtAuthPolicy(in *providerir.IngressNginxExtAuthPolicy) *IngressNginxExtAuthPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxExtAuthPolicy{
		AuthURL:         in.AuthURL,
		ResponseHeaders: cloneStringSlice(in.ResponseHeaders),
	}
}

func convertIngressNginxBasicAuthPolicy(in *providerir.IngressNginxBasicAuthPolicy) *IngressNginxBasicAuthPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxBasicAuthPolicy{
		SecretName: in.SecretName,
		AuthType:   in.AuthType,
	}
}

func convertIngressNginxSessionAffinityPolicy(in *providerir.IngressNginxSessionAffinityPolicy) *IngressNginxSessionAffinityPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxSessionAffinityPolicy{
		CookieName:     in.CookieName,
		CookiePath:     in.CookiePath,
		CookieDomain:   in.CookieDomain,
		CookieSameSite: in.CookieSameSite,
		CookieExpires:  in.CookieExpires,
		CookieSecure:   in.CookieSecure,
	}
}

func convertIngressNginxBackendTLSPolicy(in *providerir.IngressNginxBackendTLSPolicy) *IngressNginxBackendTLSPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxBackendTLSPolicy{
		SecretName: in.SecretName,
		Verify:     in.Verify,
		Hostname:   in.Hostname,
	}
}

func convertIngressNginxBackendLoadBalancingPolicy(in *providerir.IngressNginxBackendLoadBalancingPolicy) *IngressNginxBackendLoadBalancingPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxBackendLoadBalancingPolicy{
		Strategy: IngressNginxLoadBalancingStrategy(in.Strategy),
	}
}

func convertIngressNginxRateLimitPolicy(in *providerir.IngressNginxRateLimitPolicy) *IngressNginxRateLimitPolicy {
	if in == nil {
		return nil
	}
	return &IngressNginxRateLimitPolicy{
		Limit:           in.Limit,
		Unit:            IngressNginxRateLimitUnit(in.Unit),
		BurstMultiplier: in.BurstMultiplier,
	}
}

func convertIngressNginxBackendProtocol(in *providerir.IngressNginxBackendProtocol) *IngressNginxBackendProtocol {
	if in == nil {
		return nil
	}
	value := IngressNginxBackendProtocol(*in)
	return &value
}

func convertIngressNginxBackends(in map[types.NamespacedName]providerir.IngressNginxBackend) map[types.NamespacedName]IngressNginxBackend {
	if in == nil {
		return nil
	}
	out := make(map[types.NamespacedName]IngressNginxBackend, len(in))
	for key, backend := range in {
		out[key] = IngressNginxBackend{
			Namespace: backend.Namespace,
			Name:      backend.Name,
			Port:      backend.Port,
			Host:      backend.Host,
			Protocol:  convertIngressNginxBackendProtocol(backend.Protocol),
		}
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
