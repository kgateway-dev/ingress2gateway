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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate/gce"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// ExtensionFeatureMetadata holds metadata about an Ingress extension feature, such as its source and any failure message if the feature is not supported.
type ExtensionFeatureMetadata struct {
	source         string
	paths          []*field.Path
	failureMessage string
}

func (e *ExtensionFeatureMetadata) Source() string {
	return e.source
}

func (e *ExtensionFeatureMetadata) Paths() []*field.Path {
	return e.paths
}

func (e *ExtensionFeatureMetadata) FailureMessage() string {
	return e.failureMessage
}

func NewExtensionFeatureMetadata(source string, paths []*field.Path, failureMessage string) ExtensionFeatureMetadata {
	return ExtensionFeatureMetadata{
		source:         source,
		paths:          paths,
		failureMessage: failureMessage,
	}
}

// EmitterIR holds specifications of Gateway Objects for supporting Ingress extensions,
// annotations, and proprietary API features not supported as Gateway core
// features. An EmitterIR field can be mapped to core Gateway-API fields,
// or provider-specific Gateway extensions.
type EmitterIR struct {
	Gateways   map[types.NamespacedName]GatewayContext
	HTTPRoutes map[types.NamespacedName]HTTPRouteContext

	GatewayClasses map[types.NamespacedName]GatewayClassContext
	TLSRoutes      map[types.NamespacedName]TLSRouteContext
	TCPRoutes      map[types.NamespacedName]TCPRouteContext
	UDPRoutes      map[types.NamespacedName]UDPRouteContext
	GRPCRoutes     map[types.NamespacedName]GRPCRouteContext

	BackendTLSPolicies map[types.NamespacedName]BackendTLSPolicyContext
	ReferenceGrants    map[types.NamespacedName]ReferenceGrantContext

	Services map[types.NamespacedName]ServiceContext

	GceServices map[types.NamespacedName]gce.ServiceIR
}

type SessionAffinity struct {
	Metadata     ExtensionFeatureMetadata
	Type         string
	CookieTTLSec *int64
}

type ServiceContext struct {
	SessionAffinity *SessionAffinity
}

func (s *ServiceContext) UnparsedExtensions() []*ExtensionFeatureMetadata {
	var unparsedExtensions []*ExtensionFeatureMetadata
	if s.SessionAffinity != nil {
		unparsedExtensions = append(unparsedExtensions, &s.SessionAffinity.Metadata)
	}
	return unparsedExtensions
}

type GatewayContext struct {
	gatewayv1.Gateway
	// Emitter IR should be provider/emitter neutral,
	// But we have GCE for backcompatibility.
	Gce *gce.GatewayIR
}

type HTTPRouteContext struct {
	gatewayv1.HTTPRoute
	// RuleBackendSources[i][j] is the source of the jth backend in the ith
	// element of HTTPRoute.Spec.Rules.
	RuleBackendSources [][]BackendSource

	// PoliciesBySourceIngressName tracks ingress-nginx policy intent keyed by
	// source Ingress name.
	PoliciesBySourceIngressName map[string]Policy

	// RegexLocationForHost indicates whether regex path matching was enabled for
	// any ingress contributing to this merged host-group route.
	RegexLocationForHost  *bool
	RegexForcedByUseRegex bool
	RegexForcedByRewrite  bool

	// TCPTimeoutsByRuleIdx holds provider TCP-level timeouts by HTTPRoute rule index.
	TCPTimeoutsByRuleIdx map[int]*TCPTimeouts

	// PathRewriteByRuleIdx maps HTTPRoute rule indices to path rewrite intent.
	// This is provider-neutral and applied by the common emitter.
	PathRewriteByRuleIdx map[int]*PathRewrite

	// BodySizeByRuleIdx maps HTTPRoute rule indices to body size intent.
	// This is provider-neutral and applied by each custom emitter.
	BodySizeByRuleIdx map[int]*BodySize

	// RateLimitByRuleIdx maps HTTPRoute rule indices to rate limit intent.
	// This is provider-neutral and applied by each custom emitter.
	RateLimitByRuleIdx map[int]*RateLimitPolicy

	// LoadBalancingByRuleIdx maps HTTPRoute rule indices to load balancing intent.
	// This is provider-neutral and applied by each custom emitter.
	LoadBalancingByRuleIdx map[int]*BackendLoadBalancingPolicy

	// EnableAccessLogByRuleIdx maps HTTPRoute rule indices to access log intent.
	// This is provider-neutral and applied by each custom emitter.
	EnableAccessLogByRuleIdx map[int]*AccessLog

	// CorsPolicyByRuleIdx maps HTTPRoute rule indices to CORS policy intent.
	// This map is populated by providers that support CORS (e.g., via annotations) and is
	// applied by the CommonEmitter. This separation allows the CORS logic to be provider-neutral
	// and consistently applied across different providers, subject to feature gating.
	CorsPolicyByRuleIdx map[int]*CORSConfig

	// IPRangeControlByRuleIdx maps HTTPRoute rule indices to IP range control intent.
	// This is provider-neutral and applied by each custom emitter.
	IPRangeControlByRuleIdx map[int]*IPRangeControl
}

func (h *HTTPRouteContext) UnparsedExtensions() []*ExtensionFeatureMetadata {
	var unparsedExtensions []*ExtensionFeatureMetadata
	for _, x := range h.BodySizeByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	for _, x := range h.RateLimitByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	for _, x := range h.LoadBalancingByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	for _, x := range h.EnableAccessLogByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	for _, x := range h.IPRangeControlByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	for _, x := range h.PathRewriteByRuleIdx {
		if x != nil {
			unparsedExtensions = append(unparsedExtensions, &x.Metadata)
		}
	}
	return unparsedExtensions
}

// TCPTimeouts holds TCP-level timeout configuration for a single HTTPRoute rule.
type TCPTimeouts struct {
	Connect *gatewayv1.Duration
	Read    *gatewayv1.Duration
	Write   *gatewayv1.Duration
}

// BackendSource tracks the source Ingress resource that contributed a specific
// BackendRef to an HTTPRoute rule.
type BackendSource struct {
	Ingress        *networkingv1.Ingress
	Path           *networkingv1.HTTPIngressPath
	DefaultBackend *networkingv1.IngressBackend
}

type PolicyIndex struct {
	Rule    int
	Backend int
}

// PathRewrite represents provider-neutral path rewrite intent.
// For now it only supports full-path replacement; more fields may be added later.
type PathRewrite struct {
	Metadata        ExtensionFeatureMetadata
	ReplaceFullPath string
	// Headers to add on path rewrite.
	Headers                     map[string]string
	RegexCaptureGroupReferences bool
}

// BodySize represents provider-neutral body size intent.
type BodySize struct {
	Metadata   ExtensionFeatureMetadata
	BufferSize *resource.Quantity
	MaxSize    *resource.Quantity
}

type RateLimitUnit string

const (
	RateLimitUnitRPS RateLimitUnit = "rps"
	RateLimitUnitRPM RateLimitUnit = "rpm"
)

// RateLimitPolicy represents provider-neutral rate limit intent.
type RateLimitPolicy struct {
	Metadata        ExtensionFeatureMetadata
	Limit           int32
	Unit            RateLimitUnit
	BurstMultiplier int32
}

type AccessLog struct {
	Metadata ExtensionFeatureMetadata
	Enabled  bool
}

// IPRangeControl represents provider-neutral IP range control intent.
type IPRangeControl struct {
	Metadata  ExtensionFeatureMetadata
	AllowList []string
	DenyList  []string
}

type CORSConfig struct {
	gatewayv1.HTTPCORSFilter
}

type CorsPolicy struct {
	Enable           bool
	AllowOrigin      []string
	AllowCredentials *bool
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowMethods     []string
	MaxAge           *int32
}

type ExtAuthPolicy struct {
	AuthURL         string
	ResponseHeaders []string
}

type BasicAuthPolicy struct {
	SecretName string
	AuthType   string
}

type SessionAffinityPolicy struct {
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSameSite string
	CookieExpires  *int64
	CookieSecure   *bool
}

type LoadBalancingStrategy string

const (
	LoadBalancingStrategyRoundRobin LoadBalancingStrategy = "round_robin"
)

type BackendLoadBalancingPolicy struct {
	Metadata ExtensionFeatureMetadata
	Strategy LoadBalancingStrategy
}

type BackendTLSPolicy struct {
	SecretName string
	Verify     bool
	Hostname   string
}

type BackendProtocol string

const (
	BackendProtocolGRPC BackendProtocol = "GRPC"
)

type Backend struct {
	Namespace string
	Name      string
	Port      int32
	Host      string
	Protocol  *BackendProtocol
}

type Policy struct {
	ClientBodyBufferSize *resource.Quantity
	ProxyBodySize        *resource.Quantity
	Cors                 *CorsPolicy
	RateLimit            *RateLimitPolicy
	ProxySendTimeout     *metav1.Duration
	ProxyReadTimeout     *metav1.Duration
	ProxyConnectTimeout  *metav1.Duration
	EnableAccessLog      *bool
	ExtAuth              *ExtAuthPolicy
	BasicAuth            *BasicAuthPolicy
	SessionAffinity      *SessionAffinityPolicy
	LoadBalancing        *BackendLoadBalancingPolicy
	BackendTLS           *BackendTLSPolicy
	BackendProtocol      *BackendProtocol
	SSLRedirect          *bool
	RewriteTarget        *string
	UseRegexPaths        *bool
	RuleBackendSources   []PolicyIndex
	Backends             map[types.NamespacedName]Backend
}

func (p Policy) AddRuleBackendSources(idxs []PolicyIndex) Policy {
	if len(idxs) == 0 {
		return p
	}

	seen := make(map[PolicyIndex]struct{}, len(p.RuleBackendSources)+len(idxs))
	deduped := make([]PolicyIndex, 0, len(p.RuleBackendSources)+len(idxs))
	for _, idx := range p.RuleBackendSources {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		deduped = append(deduped, idx)
	}
	for _, idx := range idxs {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		deduped = append(deduped, idx)
	}
	p.RuleBackendSources = deduped
	return p
}

type GatewayClassContext struct {
	gatewayv1.GatewayClass
}

type TLSRouteContext struct {
	gatewayv1alpha2.TLSRoute
}

type TCPRouteContext struct {
	gatewayv1alpha2.TCPRoute
}

type UDPRouteContext struct {
	gatewayv1alpha2.UDPRoute
}

type GRPCRouteContext struct {
	gatewayv1.GRPCRoute
}

type BackendTLSPolicyContext struct {
	gatewayv1.BackendTLSPolicy
}

type ReferenceGrantContext struct {
	gatewayv1beta1.ReferenceGrant
}
