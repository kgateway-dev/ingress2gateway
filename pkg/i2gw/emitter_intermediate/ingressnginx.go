/*
Copyright 2026 The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// IngressNginxGatewayIR is the emitter-side ingress-nginx gateway IR.
type IngressNginxGatewayIR struct{}

// IngressNginxServiceIR is the emitter-side ingress-nginx service IR.
type IngressNginxServiceIR struct{}

// IngressNginxHTTPRouteIR contains ingress-nginx-specific fields for HTTPRoute.
type IngressNginxHTTPRouteIR struct {
	// Policies keyed by source Ingress name.
	Policies map[string]IngressNginxPolicy

	// RegexLocationForHost is true when ingress-nginx would enforce the "~*" (case-insensitive)
	// regex location modifier for all paths under a host.
	RegexLocationForHost *bool

	// RegexForcedByUseRegex is true when RegexLocationForHost is true specifically
	// because of the nginx.ingress.kubernetes.io/use-regex annotation.
	RegexForcedByUseRegex bool

	// RegexForcedByRewrite is true when RegexLocationForHost is true specifically
	// because of the nginx.ingress.kubernetes.io/rewrite-target annotation.
	RegexForcedByRewrite bool
}

// IngressNginxPolicyIndex identifies a (rule, backend) pair within a merged HTTPRoute.
type IngressNginxPolicyIndex struct {
	Rule    int
	Backend int
}

// IngressNginxCorsPolicy defines a CORS policy extracted from ingress-nginx annotations.
type IngressNginxCorsPolicy struct {
	Enable           bool
	AllowOrigin      []string
	AllowCredentials *bool
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowMethods     []string
	MaxAge           *int32
}

// IngressNginxExtAuthPolicy defines an external auth policy extracted from ingress-nginx annotations.
type IngressNginxExtAuthPolicy struct {
	AuthURL         string
	ResponseHeaders []string
}

// IngressNginxBasicAuthPolicy defines a basic auth policy extracted from ingress-nginx annotations.
type IngressNginxBasicAuthPolicy struct {
	SecretName string
	AuthType   string
}

// IngressNginxSessionAffinityPolicy defines a session affinity policy extracted from ingress-nginx annotations.
type IngressNginxSessionAffinityPolicy struct {
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSameSite string
	CookieExpires  *metav1.Duration
	CookieSecure   *bool
}

// IngressNginxBackendTLSPolicy defines a backend TLS policy extracted from ingress-nginx annotations.
type IngressNginxBackendTLSPolicy struct {
	SecretName string
	Verify     bool
	Hostname   string
}

// IngressNginxPolicy describes per-Ingress policy knobs projected from ingress-nginx.
type IngressNginxPolicy struct {
	ClientBodyBufferSize *resource.Quantity
	ProxyBodySize        *resource.Quantity
	Cors                 *IngressNginxCorsPolicy
	RateLimit            *IngressNginxRateLimitPolicy
	ProxySendTimeout     *metav1.Duration
	ProxyReadTimeout     *metav1.Duration
	ProxyConnectTimeout  *metav1.Duration
	EnableAccessLog      *bool
	ExtAuth              *IngressNginxExtAuthPolicy
	BasicAuth            *IngressNginxBasicAuthPolicy
	SessionAffinity      *IngressNginxSessionAffinityPolicy
	LoadBalancing        *IngressNginxBackendLoadBalancingPolicy
	BackendTLS           *IngressNginxBackendTLSPolicy
	BackendProtocol      *IngressNginxBackendProtocol
	SSLRedirect          *bool
	RewriteTarget        *string
	UseRegexPaths        *bool

	// RuleBackendSources lists covered (rule, backend) pairs in the merged HTTPRoute.
	RuleBackendSources []IngressNginxPolicyIndex

	// Backends holds all proxied backends that cannot be rendered as a standard k8s service.
	Backends map[types.NamespacedName]IngressNginxBackend

	// ruleBackendIndexSet is an internal helper used to deduplicate RuleBackendSources entries.
	ruleBackendIndexSet map[IngressNginxPolicyIndex]struct{}
}

// IngressNginxBackendProtocol defines the L7 protocol used to talk to a Backend.
type IngressNginxBackendProtocol string

// IngressNginxBackendProtocolGRPC is the gRPC protocol.
const IngressNginxBackendProtocolGRPC IngressNginxBackendProtocol = "grpc"

// IngressNginxBackend defines a proxied backend that cannot be rendered as a standard k8s Service.
type IngressNginxBackend struct {
	Namespace string
	Name      string
	Port      int32
	Host      string
	Protocol  *IngressNginxBackendProtocol
}

// IngressNginxRateLimitUnit defines the unit of rate limiting.
type IngressNginxRateLimitUnit string

const (
	// IngressNginxRateLimitUnitRPS defines rate limit in requests per second.
	IngressNginxRateLimitUnitRPS IngressNginxRateLimitUnit = "rps"
	// IngressNginxRateLimitUnitRPM defines rate limit in requests per minute.
	IngressNginxRateLimitUnitRPM IngressNginxRateLimitUnit = "rpm"
)

// IngressNginxRateLimitPolicy defines a rate limiting policy derived from ingress-nginx annotations.
type IngressNginxRateLimitPolicy struct {
	Limit           int32
	Unit            IngressNginxRateLimitUnit
	BurstMultiplier int32
}

// IngressNginxLoadBalancingStrategy represents upstream load-balancing mode.
type IngressNginxLoadBalancingStrategy string

// IngressNginxLoadBalancingStrategyRoundRobin is the supported round_robin strategy.
const IngressNginxLoadBalancingStrategyRoundRobin IngressNginxLoadBalancingStrategy = "round_robin"

// IngressNginxBackendLoadBalancingPolicy defines backend load-balancing policy.
type IngressNginxBackendLoadBalancingPolicy struct {
	Strategy IngressNginxLoadBalancingStrategy
}

// AddRuleBackendSources returns a copy of p with idxs added to RuleBackendSources,
// ensuring each (rule, backend) pair is unique.
func (p IngressNginxPolicy) AddRuleBackendSources(idxs []IngressNginxPolicyIndex) IngressNginxPolicy {
	pCopy := p

	if len(pCopy.RuleBackendSources) > 0 && pCopy.ruleBackendIndexSet == nil {
		pCopy.ruleBackendIndexSet = make(map[IngressNginxPolicyIndex]struct{}, len(pCopy.RuleBackendSources))
		for _, existing := range pCopy.RuleBackendSources {
			pCopy.ruleBackendIndexSet[existing] = struct{}{}
		}
	}
	if pCopy.ruleBackendIndexSet == nil {
		pCopy.ruleBackendIndexSet = make(map[IngressNginxPolicyIndex]struct{})
	}

	for _, idx := range idxs {
		if _, exists := pCopy.ruleBackendIndexSet[idx]; exists {
			continue
		}
		pCopy.RuleBackendSources = append(pCopy.RuleBackendSources, idx)
		pCopy.ruleBackendIndexSet[idx] = struct{}{}
	}

	return pCopy
}

// Type aliases for emitter code ergonomics.

type Policy = IngressNginxPolicy

type PolicyIndex = IngressNginxPolicyIndex

type CorsPolicy = IngressNginxCorsPolicy

type ExtAuthPolicy = IngressNginxExtAuthPolicy

type BasicAuthPolicy = IngressNginxBasicAuthPolicy

type SessionAffinityPolicy = IngressNginxSessionAffinityPolicy

type BackendTLSPolicy = IngressNginxBackendTLSPolicy

type BackendProtocol = IngressNginxBackendProtocol

const BackendProtocolGRPC = IngressNginxBackendProtocolGRPC

type Backend = IngressNginxBackend

type RateLimitUnit = IngressNginxRateLimitUnit

const RateLimitUnitRPS = IngressNginxRateLimitUnitRPS

const RateLimitUnitRPM = IngressNginxRateLimitUnitRPM

type RateLimitPolicy = IngressNginxRateLimitPolicy

type LoadBalancingStrategy = IngressNginxLoadBalancingStrategy

const LoadBalancingStrategyRoundRobin = IngressNginxLoadBalancingStrategyRoundRobin

type BackendLoadBalancingPolicy = IngressNginxBackendLoadBalancingPolicy
