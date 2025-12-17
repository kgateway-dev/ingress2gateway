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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	gwtests "sigs.k8s.io/gateway-api/conformance/tests"
	gwconfig "sigs.k8s.io/gateway-api/conformance/utils/config"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	gwtls "sigs.k8s.io/gateway-api/conformance/utils/tls"
)

func waitForOutputReadiness(t *testing.T, ctx context.Context, objs []unstructured.Unstructured, timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	for _, gc := range filterKind(objs, "GatewayClass") {
		name := gc.GetName()
		for time.Now().Before(deadline) {
			u, err := getUnstructured(ctx, "gatewayclass", "", name)
			if err == nil && hasTopLevelCondition(u, "Accepted", "True") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		u, err := getUnstructured(ctx, "gatewayclass", "", name)
		if err != nil || !hasTopLevelCondition(u, "Accepted", "True") {
			t.Fatalf("GatewayClass/%s not Accepted=True (err=%v)", name, err)
		}
	}

	for _, gw := range filterKind(objs, "Gateway") {
		ns := gw.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		name := gw.GetName()

		for time.Now().Before(deadline) {
			u, err := getUnstructured(ctx, "gateway", ns, name)
			if err == nil && hasTopLevelCondition(u, "Accepted", "True") && hasTopLevelCondition(u, "Programmed", "True") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		u, err := getUnstructured(ctx, "gateway", ns, name)
		if err != nil {
			t.Fatalf("Gateway/%s get: %v", name, err)
		}
		if !hasTopLevelCondition(u, "Accepted", "True") || !hasTopLevelCondition(u, "Programmed", "True") {
			t.Fatalf("Gateway/%s not ready: need Accepted=True and Programmed=True", name)
		}
	}

	for _, hr := range filterKind(objs, "HTTPRoute") {
		ns := hr.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		name := hr.GetName()

		for time.Now().Before(deadline) {
			u, err := getUnstructured(ctx, "httproute", ns, name)
			if err == nil && hasRouteParentCondition(u, "Accepted", "True") && hasRouteParentCondition(u, "ResolvedRefs", "True") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		u, err := getUnstructured(ctx, "httproute", ns, name)
		if err != nil {
			t.Fatalf("HTTPRoute/%s get: %v", name, err)
		}
		if !hasRouteParentCondition(u, "Accepted", "True") || !hasRouteParentCondition(u, "ResolvedRefs", "True") {
			t.Fatalf("HTTPRoute/%s not ready: need parents[].conditions Accepted=True and ResolvedRefs=True", name)
		}
	}

	for _, tr := range filterKind(objs, "TLSRoute") {
		ns := tr.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		name := tr.GetName()

		for time.Now().Before(deadline) {
			u, err := getUnstructured(ctx, "tlsroute", ns, name)
			if err == nil && hasRouteParentCondition(u, "Accepted", "True") && hasRouteParentCondition(u, "ResolvedRefs", "True") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		u, err := getUnstructured(ctx, "tlsroute", ns, name)
		if err != nil {
			t.Fatalf("TLSRoute/%s get: %v", name, err)
		}
		if !hasRouteParentCondition(u, "Accepted", "True") || !hasRouteParentCondition(u, "ResolvedRefs", "True") {
			t.Fatalf("TLSRoute/%s not ready: need parents[].conditions Accepted=True and ResolvedRefs=True", name)
		}
	}
}

func waitForIngressAddress(t *testing.T, ctx context.Context, ns, name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ipOrHost, err := getIngressAddress(ctx, ns, name)
		if err == nil && ipOrHost != "" {
			return
		}
		time.Sleep(2 * time.Second)
	}
	ipOrHost, err := getIngressAddress(ctx, ns, name)
	t.Fatalf("Ingress/%s address not ready after %s (addr=%q err=%v)", name, timeout, ipOrHost, err)
}

// getRoundTripper creates a DefaultRoundTripper with appropriate timeout configuration.
func getRoundTripper() roundtripper.RoundTripper {
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second
	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
	}
}

func requireHTTP200Eventually(t *testing.T, ctx context.Context, hostHeader, scheme, address, port, path string, timeout time.Duration) {
	t.Helper()

	// Set defaults
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if path == "" {
		path = "/"
	}

	gwAddr := net.JoinHostPort(address, port)

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:   hostHeader,
			Method: "GET",
			Path:   path,
		},
		Response: gwhttp.Response{
			StatusCode: 200,
		},
	}

	rt := getRoundTripper()
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, expected)
}

// requireHTTPRedirectEventually waits for an HTTP redirect response with the expected status code
// and verifies the Location header contains https:// scheme.
// expectedCode should be "301" (Moved Permanently) or "308" (Permanent Redirect).
func requireHTTPRedirectEventually(t *testing.T, ctx context.Context, hostHeader, scheme, address, port, path string, expectedCode string, timeout time.Duration) {
	t.Helper()

	// Set defaults
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if path == "" {
		path = "/"
	}

	gwAddr := net.JoinHostPort(address, port)

	// Parse expected status code
	var statusCode int
	if expectedCode == "301" {
		statusCode = 301
	} else if expectedCode == "308" {
		statusCode = 308
	} else {
		t.Fatalf("unexpected redirect code: %s (expected 301 or 308)", expectedCode)
	}

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:             hostHeader,
			Method:           "GET",
			Path:             path,
			UnfollowRedirect: true,
		},
		Response: gwhttp.Response{
			StatusCodes: []int{statusCode},
		},
		RedirectRequest: &roundtripper.RedirectRequest{
			Scheme: "https",
			// Host and Path will be set by the gateway-api utility based on actual redirect
		},
	}

	rt := getRoundTripper()
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, expected)
}

// requireHTTP200OverHTTPSEventually waits for HTTP 200 status code over an HTTPS connection with TLS certificates.
// Uses Gateway API conformance TLS utilities with certificates from ssl-redirect-tls secret.
func requireHTTP200OverHTTPSEventually(t *testing.T, ctx context.Context, hostHeader, address, port, path string, timeout time.Duration) {
	t.Helper()

	// Set defaults
	if port == "" {
		port = "443"
	}
	if path == "" {
		path = "/"
	}

	// Load TLS certificates from ssl-redirect-tls secret
	cl, err := getKubernetesClient()
	if err != nil {
		t.Fatalf("failed to create Kubernetes client: %v", err)
	}
	certPem, keyPem, err := gwtests.GetTLSSecret(cl, types.NamespacedName{Namespace: "default", Name: "ssl-redirect-tls"})
	if err != nil {
		t.Fatalf("unexpected error finding TLS secret: %v", err)
	}

	gwAddr := net.JoinHostPort(address, port)

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:   hostHeader,
			Method: "GET",
			Path:   path,
		},
		Response: gwhttp.Response{
			StatusCode: 200,
		},
	}

	// Create roundtripper that connects to IP but uses hostname for SNI
	rt := getRoundTripperForIP(address, hostHeader)

	// Configure timeout config for the TLS request
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	// Use Gateway API TLS utilities to make the request with certificates
	gwtls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, certPem, keyPem, hostHeader, expected)
}

// getKubernetesClient creates a Kubernetes client using the kubeconfig context.
func getKubernetesClient() (client.Client, error) {
	cfg, err := ctrlconfig.GetConfigWithContext(kubeContext)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig: %w", err)
	}

	cl, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return cl, nil
}

// getRoundTripperForIP creates a roundtripper that connects to a specific IP address
// but uses the hostname for SNI. This is needed for TLS passthrough testing.
func getRoundTripperForIP(ip string, hostname string) roundtripper.RoundTripper {
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second

	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
		CustomDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
}

// requireHTTP200OverTLSEventually waits for HTTP 200 status code over an HTTPS connection with TLS certificates.
// Uses Gateway API conformance TLS utilities for proper TLS passthrough testing.
func requireHTTP200OverTLSEventually(t *testing.T, ctx context.Context, hostHeader, address, port, path string, certPem, keyPem []byte, timeout time.Duration) {
	t.Helper()

	// Set defaults
	if port == "" {
		port = "443"
	}
	if path == "" {
		path = "/"
	}

	gwAddr := net.JoinHostPort(address, port)

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:   hostHeader,
			Method: "GET",
			Path:   path,
		},
		Response: gwhttp.Response{
			StatusCode: 200,
		},
	}

	// Create roundtripper that connects to IP but uses hostname for SNI
	rt := getRoundTripperForIP(address, hostHeader)

	// Configure timeout config for the TLS request
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	// Use Gateway API TLS utilities to make the request with certificates
	gwtls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, certPem, keyPem, hostHeader, expected)
}

func waitForGatewayAddress(ctx context.Context, ns, gwName string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		u, err := getUnstructured(ctx, "gateway", ns, gwName)
		if err == nil {
			if addr := getGatewayStatusAddress(u); addr != "" {
				return addr, nil
			}
		}
		time.Sleep(2 * time.Second)
	}

	if _, err := getUnstructured(ctx, "gateway", ns, gwName); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no Gateway.status.addresses found for %s/%s", ns, gwName)
}

func waitForServiceAddress(ctx context.Context, ns, name string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		u, err := getUnstructured(ctx, "service", ns, name)
		if err == nil {
			ings, found, _ := unstructured.NestedSlice(u.Object, "status", "loadBalancer", "ingress")
			if found && len(ings) > 0 {
				m, ok := ings[0].(map[string]any)
				if ok {
					if ip, _ := m["ip"].(string); ip != "" {
						return ip, nil
					}
					if hn, _ := m["hostname"].(string); hn != "" {
						return hn, nil
					}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("service %s/%s has no external IP/hostname yet", ns, name)
}
