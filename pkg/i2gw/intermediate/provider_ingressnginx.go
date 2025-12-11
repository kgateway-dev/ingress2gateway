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

package intermediate

import (
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// IngressNginxGatewayIR is the provider-specific IR for ingress-nginx.
type IngressNginxGatewayIR struct{}

// IngressNginxHTTPRouteIR contains ingress-nginx-specific fields for HTTPRoute.
type IngressNginxHTTPRouteIR struct {
	// Policies keyed by source Ingress name.
	Policies map[string]Policy
}

// IngressNginxServiceIR contains ingress-nginx-specific fields for Service.
type IngressNginxServiceIR struct{}

// PolicyIndex identifies a (rule, backend) pair within a merged HTTPRoute.
type PolicyIndex struct {
	Rule    int
	Backend int
}

// CorsPolicy defines a CORS policy that has been extracted from ingress-nginx annotations.
type CorsPolicy struct {
	// Enable corresponds to nginx.ingress.kubernetes.io/enable-cors and indicates whether CORS
	// is enabled.
	Enable bool

	// AllowOrigin corresponds to nginx.ingress.kubernetes.io/cors-allow-origin and controls what
	// is the accepted Origin for CORS.
	AllowOrigin []string

	// AllowCredentials corresponds to nginx.ingress.kubernetes.io/cors-allow-credentials and controls
	// if credentials can be passed during CORS operations. When nil, the provider has not specified a value.
	AllowCredentials *bool

	// AllowHeaders corresponds to nginx.ingress.kubernetes.io/cors-allow-headers and controls which
	// headers are accepted. Values are stored as raw header names; case-insensitivity is handled by consumers.
	AllowHeaders []string

	// ExposeHeaders corresponds to nginx.ingress.kubernetes.io/cors-expose-headers.
	// Values are header names as they appeared in the annotation, trimmed of
	// surrounding whitespace but otherwise case-preserving.
	ExposeHeaders []string

	// AllowMethods corresponds to nginx.ingress.kubernetes.io/cors-allow-methods and controls which methods
	// are accepted. Values are stored as raw method names; consumers can normalize/validate.
	AllowMethods []string

	// MaxAge corresponds to nginx.ingress.kubernetes.io/cors-max-age, in seconds and controls how long preflight
	// requests can be cached. When nil, the provider has not specified a value.
	MaxAge *int32
}

// ExtAuthPolicy defines an external authentication policy that has been extracted from ingress-nginx annotations.
type ExtAuthPolicy struct {
	// AuthURL defines the URL of an external authentication service.
	AuthURL string
	// ResponseHeaders defines the headers to pass to backend once authentication request completes.
	ResponseHeaders []string
}

// BasicAuthPolicy defines a basic authentication policy that has been extracted from ingress-nginx annotations.
type BasicAuthPolicy struct {
	// SecretName defines the name of the secret containing basic auth credentials.
	SecretName string
	// AuthType defines the format of the secret: "auth-file" (default) or "auth-map".
	// For "auth-file", the secret contains an htpasswd file in a specific key.
	// For "auth-map", the keys of the secret are usernames and values are hashed passwords.
	AuthType string
}

// SessionAffinityPolicy defines a session affinity policy that has been extracted from ingress-nginx annotations.
type SessionAffinityPolicy struct {
	// CookieName defines the name of the cookie used for session affinity.
	CookieName string
	// CookiePath defines the path that will be set on the cookie.
	CookiePath string
	// CookieDomain defines the Domain attribute of the sticky cookie.
	CookieDomain string
	// CookieSameSite defines the SameSite attribute of the sticky cookie (None, Lax, Strict).
	CookieSameSite string
	// CookieExpires defines the TTL/expiration time for the cookie.
	CookieExpires *metav1.Duration
	// CookieSecure defines whether the Secure flag is set on the cookie.
	CookieSecure *bool
}

// BackendTLSPolicy defines a backend TLS policy that has been extracted from ingress-nginx annotations.
type BackendTLSPolicy struct {
	// SecretName defines the name of the secret containing client certificate (tls.crt),
	// client key (tls.key), and CA certificate (ca.crt) in PEM format.
	// Format: "namespace/secretName"
	SecretName string
	// Verify enables or disables verification of the proxied HTTPS server certificate.
	// Default: false (off)
	Verify bool
	// Hostname allows overriding the server name used to verify the certificate of the proxied HTTPS server.
	// This value is also used for SNI when a connection is established.
	// In Gateway API, setting Hostname enables SNI automatically.
	Hostname string
}

// Policy describes all per-Ingress policy knobs that ingress-nginx projects into the
// IR (buffer, CORS, etc.).
type Policy struct {
	// ClientBodyBufferSize defines the size of the buffer used for client request bodies.
	ClientBodyBufferSize *resource.Quantity

	// ProxyBodySize defines the maximum allowed size of the client request body.
	ProxyBodySize *resource.Quantity

	// Cors defines the CORS policy derived from ingress-nginx annotations.
	Cors *CorsPolicy

	// RateLimit is a generic rate limit policy derived from ingress-nginx annotations.
	RateLimit *RateLimitPolicy

	// ProxySendTimeout defines the timeout for transmitting a request to the proxied server.
	ProxySendTimeout *metav1.Duration

	// ProxyReadTimeout defines the timeout for reading a response from a proxied server.
	ProxyReadTimeout *metav1.Duration

	// ProxySendTimeout defines the timeout for establishing a connection to a proxied server.
	ProxyConnectTimeout *metav1.Duration

	// EnableAccessLog defines whether access logging is enabled for the ingress.
	EnableAccessLog *bool

	// ExtAuth defines the external authentication policy.
	ExtAuth *ExtAuthPolicy

	// BasicAuth defines the basic authentication policy.
	BasicAuth *BasicAuthPolicy

	// SessionAffinity defines the session affinity policy.
	SessionAffinity *SessionAffinityPolicy

	// LoadBalancing controls the upstream load-balancing algorithm. Only round_robin is supported;
	// other values are ignored.
	LoadBalancing *BackendLoadBalancingPolicy

	// BackendTLS defines the backend TLS policy.
	BackendTLS *BackendTLSPolicy

	// SSLRedirect indicates whether SSL redirect is enabled, corresponding to
	// nginx.ingress.kubernetes.io/ssl-redirect. When true, requests should be
	// redirected to HTTPS.
	SSLRedirect *bool

	// RuleBackendSources lists the (rule, backend) pairs within a merged HTTPRoute
	// that this policy applies to.
	//
	// Each entry is a PolicyIndex struct identifying a (rule, backend) pair.
	//
	// This slice may contain duplicates; use AddRuleBackendSources to add entries
	// while ensuring uniqueness.
	RuleBackendSources []PolicyIndex

	// Backends holds all proxied backends that cannot be rendered as a standard k8s service, i.e. kgateway Backend.
	Backends map[types.NamespacedName]Backend

	// ruleBackendIndexSet is an internal helper used to deduplicate RuleBackendSources entries.
	ruleBackendIndexSet map[PolicyIndex]struct{}
}

// Backend defines a proxied backend that cannot be rendered as a standard k8s Service.
type Backend struct {
	// Namespace defines the namespace of the backend.
	Namespace string

	// Name defines the name of the backend.
	Name string

	// Port defines the port of the backend.
	Port int32

	// Host defines the host (IP or DNS name) of the backend.
	Host string
}

// RateLimitUnit defines the unit of rate limiting.
type RateLimitUnit string

const (
	// RateLimitUnitRPS defines rate limit in requests per second.
	RateLimitUnitRPS RateLimitUnit = "rps"
	// RateLimitUnitRPM defines rate limit in requests per minute.
	RateLimitUnitRPM RateLimitUnit = "rpm"
)

// RateLimitPolicy defines a rate limiting policy derived from ingress-nginx annotations.
type RateLimitPolicy struct {
	// Exactly one of RPS/RPM should be set by the provider.
	Limit int32         // normalized numeric limit
	Unit  RateLimitUnit // "rps" or "rpm"

	// BurstMultiplier is applied on top of the base limit to compute the bucket size.
	// If zero, treat as 1.
	BurstMultiplier int32
}

// LoadBalancingStrategy represents the upstream load-balancing mode requested by the Ingress NGINX annotations.
// Currently only round_robin is supported; other values are ignored.
type LoadBalancingStrategy string

const LoadBalancingStrategyRoundRobin LoadBalancingStrategy = "round_robin"

type BackendLoadBalancingPolicy struct {
	Strategy LoadBalancingStrategy
}

// AddRuleBackendSources returns a copy of p with idxs added to
// RuleBackendSources, ensuring each (Rule, Backend) pair is unique.
func (p Policy) AddRuleBackendSources(idxs []PolicyIndex) Policy {
	pCopy := p

	// Initialize the internal set from any existing slice contents.
	if len(pCopy.RuleBackendSources) > 0 && pCopy.ruleBackendIndexSet == nil {
		pCopy.ruleBackendIndexSet = make(map[PolicyIndex]struct{}, len(pCopy.RuleBackendSources))
		for _, existing := range pCopy.RuleBackendSources {
			pCopy.ruleBackendIndexSet[existing] = struct{}{}
		}
	}
	if pCopy.ruleBackendIndexSet == nil {
		pCopy.ruleBackendIndexSet = make(map[PolicyIndex]struct{})
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
