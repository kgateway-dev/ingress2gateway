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

package kgateway

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	"k8s.io/utils/ptr"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// parsedAuthURL contains the fields you can use to build a BackendObjectReference.
type parsedAuthURL struct {
	service   string
	namespace string
	port      int32
	path      string
	external  bool // true if host is not a Kubernetes service
}

// ParseAuthURL parses an nginx.ingress.kubernetes.io/auth-url value into a ParsedAuthURL.
// ingressNS = namespace of the Ingress (used when namespace is omitted).
func ParseAuthURL(raw string, ingressNS string) (*parsedAuthURL, error) {
	if raw == "" {
		return nil, fmt.Errorf("auth-url is empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid auth-url: %w", err)
	}

	// Default path
	path := u.Path
	if path == "" {
		path = "/"
	}

	host := u.Host

	// Split host and port
	var hostname, portStr string
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname = h
		portStr = p
	} else {
		hostname = host
	}

	// Detect external hostname (not a Kubernetes service)
	if !strings.Contains(hostname, ".svc") {
		return &parsedAuthURL{
			external: true,
			path:     path,
		}, nil
	}

	// Normalize cluster-local suffixes
	hostname = strings.TrimSuffix(hostname, ".cluster.local")
	hostname = strings.TrimSuffix(hostname, ".svc")

	parts := strings.Split(hostname, ".")
	if len(parts) < 1 {
		return nil, fmt.Errorf("unable to extract service from hostname %q", hostname)
	}

	service := parts[0]

	// Determine namespace
	namespace := ingressNS
	if len(parts) >= 2 {
		namespace = parts[1]
	}

	// Port
	var port int32
	if portStr != "" {
		var parsed int
		fmt.Sscanf(portStr, "%d", &parsed)
		port = int32(parsed)
	} else {
		switch u.Scheme {
		case "https":
			port = 443
		default:
			port = 80
		}
	}

	return &parsedAuthURL{
		service:   service,
		namespace: namespace,
		port:      port,
		path:      path,
		external:  false,
	}, nil
}

// applyExtAuthPolicy projects the ExtAuth IR policy into a GatewayExtension
// and ExtAuthPolicy in TrafficPolicy.
//
// Semantics:
//   - We create one GatewayExtension per unique auth-url.
//   - That GatewayExtension's Spec.ExtAuth.HttpService references an existing Service
//     (parsed from the auth URL).
//   - An ExtAuthPolicy is added to TrafficPolicy that references the GatewayExtension.
func applyExtAuthPolicy(
	pol intermediate.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
	gatewayExtensions map[string]*kgateway.GatewayExtension,
) bool {
	if pol.ExtAuth == nil || pol.ExtAuth.AuthURL == "" {
		return false
	}

	authURL := pol.ExtAuth.AuthURL

	// Parse the auth URL to extract service information.
	parsed, err := ParseAuthURL(authURL, namespace)
	if err != nil {
		// Invalid URL, skip it.
		return false
	}

	// Skip external URLs as we can only reference Kubernetes Services.
	if parsed.external {
		return false
	}

	// Use the URL as a key to deduplicate GatewayExtensions.
	if _, exists := gatewayExtensions[authURL]; !exists {
		// Create GatewayExtension with ExtAuth using HttpService.
		extHttpService := &kgateway.ExtHttpService{
			BackendRef: gwv1.BackendRef{
				BackendObjectReference: gwv1.BackendObjectReference{
					Name:      gwv1.ObjectName(parsed.service),
					Namespace: ptr.To(gwv1.Namespace(parsed.namespace)), // TODO: confirm that different namespace works
					Port:      ptr.To(gwv1.PortNumber(parsed.port)),
				},
			},
			PathPrefix: parsed.path,
		}

		// Set AuthorizationResponse if response headers are specified.
		if len(pol.ExtAuth.ResponseHeaders) > 0 {
			extHttpService.AuthorizationResponse = &kgateway.AuthorizationResponse{
				HeadersToBackend: pol.ExtAuth.ResponseHeaders,
			}
		}

		ge := &kgateway.GatewayExtension{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-extauth", parsed.service),
				Namespace: namespace,
			},
			Spec: kgateway.GatewayExtensionSpec{
				ExtAuth: &kgateway.ExtAuthProvider{
					HttpService: extHttpService,
				},
			},
		}
		ge.SetGroupVersionKind(GatewayExtensionGVK)
		gatewayExtensions[authURL] = ge
	}

	// Add ExtAuthPolicy to TrafficPolicy.
	t := ensureTrafficPolicy(tp, ingressName, namespace)
	ge := gatewayExtensions[authURL]

	t.Spec.ExtAuth = &kgateway.ExtAuthPolicy{
		ExtensionRef: &shared.NamespacedObjectReference{
			Name:      gwv1.ObjectName(ge.Name),
			Namespace: ptr.To(gwv1.Namespace(ge.Namespace)),
		},
	}

	return true
}
