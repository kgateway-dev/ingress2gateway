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

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// parsedAuthURL contains the fields you can use to build a BackendObjectReference.
type parsedAuthURL struct {
	service   string
	namespace string
	port      int32
	path      string
	external  bool // true if host is not a Kubernetes service
}

// parseAuthURL parses an nginx.ingress.kubernetes.io/auth-url value into a ParsedAuthURL.
func parseAuthURL(raw string, ingressNS string) (*parsedAuthURL, error) {
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
func applyExtAuthPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
	gatewayExtensions map[string]*kgateway.GatewayExtension,
) bool {
	if pol.ExtAuth == nil || pol.ExtAuth.AuthURL == "" {
		return false
	}

	authURL := pol.ExtAuth.AuthURL

	// Parse the auth URL to extract service information.
	parsed, err := parseAuthURL(authURL, namespace)
	if err != nil {
		// Invalid URL, skip it.
		return false
	}

	// Skip external URLs as we can only reference Kubernetes Services.
	if parsed.external {
		return false
	}

	// Create GatewayExtension with ExtAuth using HttpService.
	extHttpService := &kgateway.ExtHttpService{
		BackendRef: gatewayv1.BackendRef{
			BackendObjectReference: gatewayv1.BackendObjectReference{
				Name:      gatewayv1.ObjectName(parsed.service),
				Namespace: ptr.To(gatewayv1.Namespace(parsed.namespace)),
				Port:      ptr.To(gatewayv1.PortNumber(parsed.port)),
			},
		},
	}
	// Only set PathPrefix if it's not the default "/" to avoid redirect issues
	if parsed.path != "" && parsed.path != "/" {
		extHttpService.PathPrefix = parsed.path
	}

	// Set AuthorizationResponse if response headers are specified.
	if len(pol.ExtAuth.ResponseHeaders) > 0 {
		extHttpService.AuthorizationResponse = &kgateway.AuthorizationResponse{
			HeadersToBackend: pol.ExtAuth.ResponseHeaders,
		}
	}

	ge := &kgateway.GatewayExtension{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-extauth", ingressName),
			Namespace: namespace,
		},
		Spec: kgateway.GatewayExtensionSpec{
			ExtAuth: &kgateway.ExtAuthProvider{
				HttpService: extHttpService,
			},
		},
	}
	ge.SetGroupVersionKind(GatewayExtensionGVK)

	// Add ExtAuthPolicy to TrafficPolicy.
	t := ensureTrafficPolicy(tp, ingressName, namespace)

	t.Spec.ExtAuth = &kgateway.ExtAuthPolicy{
		ExtensionRef: &shared.NamespacedObjectReference{
			Name:      gatewayv1.ObjectName(ge.Name),
			Namespace: ptr.To(gatewayv1.Namespace(ge.Namespace)),
		},
	}

	gatewayExtensions[ingressName] = ge
	return true
}

// applyBasicAuthPolicy projects the BasicAuth IR policy into a Kgateway TrafficPolicy.
func applyBasicAuthPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
) bool {
	if pol.BasicAuth == nil || pol.BasicAuth.SecretName == "" {
		return false
	}

	t := ensureTrafficPolicy(tp, ingressName, namespace)
	secretRef := &kgateway.SecretReference{
		Name: gatewayv1.ObjectName(pol.BasicAuth.SecretName),
	}
	// Set Key field to "auth" when AuthType is "auth-file" (default format)
	if pol.BasicAuth.AuthType == "auth-file" {
		secretRef.Key = ptr.To("auth")
	}
	t.Spec.BasicAuth = &kgateway.BasicAuthPolicy{
		SecretRef: secretRef,
	}
	return true
}
