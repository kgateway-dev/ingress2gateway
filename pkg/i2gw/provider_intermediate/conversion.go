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

package providerir

import (
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"k8s.io/apimachinery/pkg/types"
)

// ToEmitterIR converts a ProviderIR to an EmitterIR.
func ToEmitterIR(pIR ProviderIR) emitterir.EmitterIR {
	eIR := emitterir.EmitterIR{
		Gateways:           make(map[types.NamespacedName]emitterir.GatewayContext),
		HTTPRoutes:         make(map[types.NamespacedName]emitterir.HTTPRouteContext),
		GatewayClasses:     make(map[types.NamespacedName]emitterir.GatewayClassContext),
		TLSRoutes:          make(map[types.NamespacedName]emitterir.TLSRouteContext),
		TCPRoutes:          make(map[types.NamespacedName]emitterir.TCPRouteContext),
		UDPRoutes:          make(map[types.NamespacedName]emitterir.UDPRouteContext),
		GRPCRoutes:         make(map[types.NamespacedName]emitterir.GRPCRouteContext),
		BackendTLSPolicies: make(map[types.NamespacedName]emitterir.BackendTLSPolicyContext),
		ReferenceGrants:    make(map[types.NamespacedName]emitterir.ReferenceGrantContext),
	}

	for key, gatewayCtx := range pIR.Gateways {
		eIR.Gateways[key] = emitterir.GatewayContext{Gateway: gatewayCtx.Gateway}
	}
	for key, httpRouteCtx := range pIR.HTTPRoutes {
		eIR.HTTPRoutes[key] = emitterir.HTTPRouteContext{
			HTTPRoute:          httpRouteCtx.HTTPRoute,
			IngressNginx:       convertIngressNginxHTTPRouteIR(httpRouteCtx.ProviderSpecificIR.IngressNginx),
			RuleBackendSources: convertBackendSources(httpRouteCtx.RuleBackendSources),
		}
	}
	for key, gatewayClassCtx := range pIR.GatewayClasses {
		eIR.GatewayClasses[key] = emitterir.GatewayClassContext{GatewayClass: gatewayClassCtx}
	}
	for key, tlsRouteCtx := range pIR.TLSRoutes {
		eIR.TLSRoutes[key] = emitterir.TLSRouteContext{TLSRoute: tlsRouteCtx}
	}
	for key, tcpRouteCtx := range pIR.TCPRoutes {
		eIR.TCPRoutes[key] = emitterir.TCPRouteContext{TCPRoute: tcpRouteCtx}
	}
	for key, udpRouteCtx := range pIR.UDPRoutes {
		eIR.UDPRoutes[key] = emitterir.UDPRouteContext{UDPRoute: udpRouteCtx}
	}
	for key, grpcRouteCtx := range pIR.GRPCRoutes {
		eIR.GRPCRoutes[key] = emitterir.GRPCRouteContext{GRPCRoute: grpcRouteCtx}
	}
	for key, backendTLSPolicyCtx := range pIR.BackendTLSPolicies {
		eIR.BackendTLSPolicies[key] = emitterir.BackendTLSPolicyContext{BackendTLSPolicy: backendTLSPolicyCtx}
	}
	for key, referenceGrantCtx := range pIR.ReferenceGrants {
		eIR.ReferenceGrants[key] = emitterir.ReferenceGrantContext{ReferenceGrant: referenceGrantCtx}
	}

	return eIR
}

func convertBackendSources(in [][]BackendSource) [][]emitterir.BackendSource {
	if in == nil {
		return nil
	}
	out := make([][]emitterir.BackendSource, len(in))
	for i, ruleSources := range in {
		out[i] = make([]emitterir.BackendSource, len(ruleSources))
		for j, src := range ruleSources {
			out[i][j] = emitterir.BackendSource{
				Ingress:        src.Ingress,
				Path:           src.Path,
				DefaultBackend: src.DefaultBackend,
			}
		}
	}
	return out
}

func convertIngressNginxHTTPRouteIR(in *IngressNginxHTTPRouteIR) *emitterir.IngressNginxHTTPRouteIR {
	if in == nil {
		return nil
	}

	out := &emitterir.IngressNginxHTTPRouteIR{
		RegexLocationForHost:  in.RegexLocationForHost,
		RegexForcedByUseRegex: in.RegexForcedByUseRegex,
		RegexForcedByRewrite:  in.RegexForcedByRewrite,
	}
	if in.Policies != nil {
		out.Policies = make(map[string]emitterir.IngressNginxPolicy, len(in.Policies))
		for ingressName, policy := range in.Policies {
			out.Policies[ingressName] = convertIngressNginxPolicy(policy)
		}
	}

	return out
}

func convertIngressNginxPolicy(in IngressNginxPolicy) emitterir.IngressNginxPolicy {
	return emitterir.IngressNginxPolicy{
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
}

func convertIngressNginxPolicyIndices(in []IngressNginxPolicyIndex) []emitterir.IngressNginxPolicyIndex {
	if in == nil {
		return nil
	}
	out := make([]emitterir.IngressNginxPolicyIndex, len(in))
	for i := range in {
		out[i] = emitterir.IngressNginxPolicyIndex{
			Rule:    in[i].Rule,
			Backend: in[i].Backend,
		}
	}
	return out
}

func convertIngressNginxCorsPolicy(in *IngressNginxCorsPolicy) *emitterir.IngressNginxCorsPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxCorsPolicy{
		Enable:           in.Enable,
		AllowOrigin:      cloneStringSlice(in.AllowOrigin),
		AllowCredentials: in.AllowCredentials,
		AllowHeaders:     cloneStringSlice(in.AllowHeaders),
		ExposeHeaders:    cloneStringSlice(in.ExposeHeaders),
		AllowMethods:     cloneStringSlice(in.AllowMethods),
		MaxAge:           in.MaxAge,
	}
}

func convertIngressNginxExtAuthPolicy(in *IngressNginxExtAuthPolicy) *emitterir.IngressNginxExtAuthPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxExtAuthPolicy{
		AuthURL:         in.AuthURL,
		ResponseHeaders: cloneStringSlice(in.ResponseHeaders),
	}
}

func convertIngressNginxBasicAuthPolicy(in *IngressNginxBasicAuthPolicy) *emitterir.IngressNginxBasicAuthPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxBasicAuthPolicy{
		SecretName: in.SecretName,
		AuthType:   in.AuthType,
	}
}

func convertIngressNginxSessionAffinityPolicy(in *IngressNginxSessionAffinityPolicy) *emitterir.IngressNginxSessionAffinityPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxSessionAffinityPolicy{
		CookieName:     in.CookieName,
		CookiePath:     in.CookiePath,
		CookieDomain:   in.CookieDomain,
		CookieSameSite: in.CookieSameSite,
		CookieExpires:  in.CookieExpires,
		CookieSecure:   in.CookieSecure,
	}
}

func convertIngressNginxBackendTLSPolicy(in *IngressNginxBackendTLSPolicy) *emitterir.IngressNginxBackendTLSPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxBackendTLSPolicy{
		SecretName: in.SecretName,
		Verify:     in.Verify,
		Hostname:   in.Hostname,
	}
}

func convertIngressNginxBackendLoadBalancingPolicy(in *IngressNginxBackendLoadBalancingPolicy) *emitterir.IngressNginxBackendLoadBalancingPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxBackendLoadBalancingPolicy{
		Strategy: emitterir.IngressNginxLoadBalancingStrategy(in.Strategy),
	}
}

func convertIngressNginxRateLimitPolicy(in *IngressNginxRateLimitPolicy) *emitterir.IngressNginxRateLimitPolicy {
	if in == nil {
		return nil
	}
	return &emitterir.IngressNginxRateLimitPolicy{
		Limit:           in.Limit,
		Unit:            emitterir.IngressNginxRateLimitUnit(in.Unit),
		BurstMultiplier: in.BurstMultiplier,
	}
}

func convertIngressNginxBackendProtocol(in *IngressNginxBackendProtocol) *emitterir.IngressNginxBackendProtocol {
	if in == nil {
		return nil
	}
	value := emitterir.IngressNginxBackendProtocol(*in)
	return &value
}

func convertIngressNginxBackends(in map[types.NamespacedName]IngressNginxBackend) map[types.NamespacedName]emitterir.IngressNginxBackend {
	if in == nil {
		return nil
	}
	out := make(map[types.NamespacedName]emitterir.IngressNginxBackend, len(in))
	for key, backend := range in {
		out[key] = emitterir.IngressNginxBackend{
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
