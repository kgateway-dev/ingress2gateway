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
	"encoding/base64"
	"fmt"
	"net"
	"strings"
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

// HTTPRequestConfig contains configuration for making HTTP requests in tests.
type HTTPRequestConfig struct {
	// HostHeader is the Host header value for the request
	HostHeader string
	// Scheme is "http" or "https"
	Scheme string
	// Address is the IP address or hostname to connect to
	Address string
	// Port is the port number (empty defaults to 80 for http, 443 for https)
	Port string
	// Path is the request path (empty defaults to "/")
	Path string
	// ExpectedStatusCode is the expected HTTP status code (used if ExpectedStatusCodes is empty)
	ExpectedStatusCode int
	// ExpectedStatusCodes is a list of acceptable status codes (takes precedence over ExpectedStatusCode)
	ExpectedStatusCodes []int
	// Timeout is the maximum time to wait for the request to succeed
	Timeout time.Duration
	// Username for Basic authentication
	Username string
	// Password for Basic authentication
	Password string
	// CertPem is the TLS certificate PEM data (for TLS passthrough)
	CertPem []byte
	// KeyPem is the TLS key PEM data (for TLS passthrough)
	KeyPem []byte
	// SecretName is the name of a Kubernetes secret containing TLS certificates
	SecretName string
	// RedirectRequest specifies expected redirect details
	RedirectRequest *roundtripper.RedirectRequest
	// UnfollowRedirect if true, don't follow redirects
	UnfollowRedirect bool
	// SNI is the Server Name Indication for TLS requests
	SNI string
}

// getRoundTripper creates a DefaultRoundTripper with appropriate timeout configuration.
func getRoundTripper() roundtripper.RoundTripper {
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second
	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
	}
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

// makeHTTPRequestEventually makes an HTTP request based on the provided configuration.
// It handles regular HTTP/HTTPS requests, TLS passthrough, Basic auth, and redirects.
func makeHTTPRequestEventually(t *testing.T, cfg HTTPRequestConfig) {
	t.Helper()

	// Load TLS certificates from secret if SecretName is specified
	if cfg.SecretName != "" {
		cl, err := getKubernetesClient()
		if err != nil {
			t.Fatalf("failed to create Kubernetes client: %v", err)
		}
		certPem, keyPem, err := gwtests.GetTLSSecret(cl, types.NamespacedName{Namespace: "default", Name: cfg.SecretName})
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}
		cfg.CertPem = certPem
		cfg.KeyPem = keyPem
	}

	gwAddr := net.JoinHostPort(cfg.Address, cfg.Port)

	// Build request headers
	headers := make(map[string]string)
	var expectedRequest *gwhttp.ExpectedRequest
	if cfg.Username != "" && cfg.Password != "" {
		// Add Authorization header for basic auth
		auth := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		headers["Authorization"] = "Basic " + auth
		// For basic auth, gateways strip Authorization header after validation,
		// so we expect it to be absent from the backend request
		expectedRequest = &gwhttp.ExpectedRequest{
			Request: gwhttp.Request{
				Host:   cfg.HostHeader,
				Method: "GET",
				Path:   cfg.Path,
			},
		}
	}

	// Build expected response
	expected := gwhttp.ExpectedResponse{
		Namespace:       "default",
		ExpectedRequest: expectedRequest,
		Request: gwhttp.Request{
			Host:             cfg.HostHeader,
			Method:           "GET",
			Path:             cfg.Path,
			Headers:          headers,
			UnfollowRedirect: cfg.UnfollowRedirect,
			SNI:              cfg.SNI,
		},
		RedirectRequest: cfg.RedirectRequest,
	}

	// Set expected status code(s)
	if len(cfg.ExpectedStatusCodes) > 0 {
		expected.Response.StatusCodes = cfg.ExpectedStatusCodes
	} else if cfg.ExpectedStatusCode != 0 {
		expected.Response.StatusCode = cfg.ExpectedStatusCode
	} else {
		// Default to 200 if not specified
		expected.Response.StatusCode = 200
	}

	rt := getRoundTripper()
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = cfg.Timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	// Use TLS utilities if certificates are provided
	if len(cfg.CertPem) > 0 && len(cfg.KeyPem) > 0 {
		sni := cfg.SNI
		if sni == "" {
			sni = cfg.HostHeader
		}
		gwtls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, cfg.CertPem, cfg.KeyPem, sni, expected)
	} else {
		gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, expected)
	}
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

// podAndCodeFromClient makes an HTTP request and returns the backend pod name and the status code.
func podAndCodeFromClient(t *testing.T, hostHeader, scheme, address, port, path string) (pod, code, out string, err error) {
	t.Helper()

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
		Response: gwhttp.Response{StatusCode: 200},
	}

	req := gwhttp.MakeRequest(t, &expected, gwAddr, strings.ToUpper(scheme), scheme)

	// Optional but helpful to avoid “same downstream connection == same upstream host” stickiness
	// in some implementations:
	if req.Headers == nil {
		req.Headers = map[string][]string{}
	}
	req.Headers["Connection"] = []string{"close"}
	req.Headers["X-E2E-Nonce"] = []string{fmt.Sprintf("%d", time.Now().UnixNano())}

	rt := getRoundTripper()
	cReq, cRes, err := rt.CaptureRoundTrip(req)
	if err != nil {
		return "", "000", fmt.Sprintf("request failed: %v", err), err
	}

	if cReq != nil {
		pod = cReq.Pod
	}
	code = fmt.Sprintf("%d", cRes.StatusCode)
	out = fmt.Sprintf("Status: %d, Protocol: %s, Pod: %s", cRes.StatusCode, cRes.Protocol, pod)
	return pod, code, out, nil
}

func requireLoadBalancedAcrossPodsEventually(
	t *testing.T,
	hostHeader, scheme, address, port, path string,
	wantDistinctPods int,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		seen := map[string]int{}
		var lastOut string
		var lastErr error
		var lastCode string

		// Enough samples that “3 replicas but I only saw 1–2 by chance” is very unlikely.
		for i := 0; i < 60; i++ {
			pod, code, out, err := podAndCodeFromClient(t, hostHeader, scheme, address, port, path)
			lastOut, lastErr, lastCode = out, err, code
			if err == nil && strings.TrimSpace(code) == "200" && pod != "" {
				seen[pod]++
			}
		}

		if len(seen) >= wantDistinctPods {
			t.Logf("load balancing OK (distinctPods=%d): %v", len(seen), seen)
			return
		}

		if attempt == 1 || attempt%5 == 0 {
			t.Logf("waiting for load balancing across %d pods (attempt=%d): seen=%v lastCode=%s lastErr=%v lastOut=%s",
				wantDistinctPods, attempt, seen, strings.TrimSpace(lastCode), lastErr, lastOut)
		}
		time.Sleep(interval)
	}

	t.Fatalf("timed out waiting to observe %d distinct backend pods", wantDistinctPods)
}
