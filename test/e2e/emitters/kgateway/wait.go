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

// getRoundTripper creates a DefaultRoundTripper with appropriate timeout configuration.
func getRoundTripper() roundtripper.RoundTripper {
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second
	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
	}
}

func requireHTTP200Eventually(t *testing.T, hostHeader, scheme, address, port, path string, timeout time.Duration) {
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
		Namespace: "default",
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

func requireStickySessionEventually(
	t *testing.T,
	hostHeader, scheme, address, port, path string,
	cookieName, cookieValue string,
	numRequests int,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		var basePod string
		ok := true

		for i := 0; i < numRequests; i++ {
			pod, code, _, err := podAndCodeFromClientWithCookie(t, hostHeader, scheme, address, port, path, cookieName, cookieValue)
			if err != nil || strings.TrimSpace(code) != "200" || pod == "" {
				ok = false
				break
			}
			if basePod == "" {
				basePod = pod
				continue
			}
			if pod != basePod {
				ok = false
				break
			}
		}

		if ok && basePod != "" {
			t.Logf("sticky session OK: cookie %s=%s consistently routed to pod %s", cookieName, cookieValue, basePod)
			return
		}

		if attempt == 1 || attempt%5 == 0 {
			t.Logf("waiting for sticky session to converge (attempt=%d cookie=%s=%s)", attempt, cookieName, cookieValue)
		}
		time.Sleep(interval)
	}

	t.Fatalf("timed out waiting for sticky session routing with cookie %s=%s", cookieName, cookieValue)
}

func requireDifferentSessionUsuallyDifferentPod(
	t *testing.T,
	hostHeader, scheme, address, port, path string,
	cookieName string,
	cookieValueA, cookieValueB string,
	numRequests int,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	for time.Now().Before(deadline) {
		podA, okA := stablePodForCookie(t, hostHeader, scheme, address, port, path, cookieName, cookieValueA, numRequests)
		podB, okB := stablePodForCookie(t, hostHeader, scheme, address, port, path, cookieName, cookieValueB, numRequests)

		if okA && okB && podA != "" && podB != "" && podA != podB {
			t.Logf("different cookies mapped to different pods: %q->%s, %q->%s", cookieValueA, podA, cookieValueB, podB)
			return
		}
		time.Sleep(interval)
	}

	// Don’t hard-fail if it never differs; environments can legitimately hash both cookies to same pod.
	t.Logf("note: different cookie values did not map to different pods within timeout; sticky routing still validated")
}

func stablePodForCookie(
	t *testing.T,
	hostHeader, scheme, address, port, path, cookieName, cookieValue string,
	numRequests int,
) (string, bool) {
	var basePod string
	for i := 0; i < numRequests; i++ {
		pod, code, _, err := podAndCodeFromClientWithCookie(t, hostHeader, scheme, address, port, path, cookieName, cookieValue)
		if err != nil || strings.TrimSpace(code) != "200" || pod == "" {
			return "", false
		}
		if basePod == "" {
			basePod = pod
			continue
		}
		if pod != basePod {
			return "", false
		}
	}
	return basePod, true
}

func podAndCodeFromClientWithCookie(
	t *testing.T,
	hostHeader, scheme, address, port, path string,
	cookieName, cookieValue string,
) (pod, code, out string, err error) {
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

	if req.Headers == nil {
		req.Headers = map[string][]string{}
	}
	// Keep same downstream connection behavior controlled (optional).
	req.Headers["Connection"] = []string{"close"}
	req.Headers["X-E2E-Nonce"] = []string{fmt.Sprintf("%d", time.Now().UnixNano())}

	// Set the cookie expected by the policy.
	// HTTP Cookie header format: "name=value"
	req.Headers["Cookie"] = []string{fmt.Sprintf("%s=%s", cookieName, cookieValue)}

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

// requireHTTPRedirectEventually waits for an HTTP redirect response with the expected status code
// and verifies the Location header contains https:// scheme.
// expectedCode should be "301" (Moved Permanently) or "308" (Permanent Redirect).
func requireHTTPRedirectEventually(t *testing.T, hostHeader, address, port, path string, expectedCode string, timeout time.Duration) {
	t.Helper()

	gwAddr := net.JoinHostPort(address, port)

	// Parse expected status code
	var statusCode int
	switch expectedCode {
	case "301":
		statusCode = 301
	case "308":
		statusCode = 308
	default:
		t.Fatalf("unexpected redirect code: %s (expected 301 or 308)", expectedCode)
	}

	expected := gwhttp.ExpectedResponse{
		Namespace: "default",
		Request: gwhttp.Request{
			Host:             hostHeader,
			Method:           "GET",
			Path:             path,
			UnfollowRedirect: true,
			SNI:              hostHeader,
		},
		Response: gwhttp.Response{
			StatusCodes: []int{statusCode},
		},
		RedirectRequest: &roundtripper.RedirectRequest{
			Scheme: "https",
			Port:   "",
			Path:   path,
		},
	}

	rt := getRoundTripper()
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, expected)
}

// requireHTTP200OverHTTPSEventually waits for HTTP 200 status code over an HTTPS connection with TLS certificates.
// Uses Gateway API conformance TLS utilities with certificates from the specified secret.
func requireHTTP200OverHTTPSEventually(t *testing.T, hostHeader, address, port, path, secretName string, timeout time.Duration) {
	t.Helper()

	// Load TLS certificates from the specified secret
	cl, err := getKubernetesClient()
	if err != nil {
		t.Fatalf("failed to create Kubernetes client: %v", err)
	}
	certPem, keyPem, err := gwtests.GetTLSSecret(cl, types.NamespacedName{Namespace: "default", Name: secretName})
	if err != nil {
		t.Fatalf("unexpected error finding TLS secret: %v", err)
	}

	requireHTTP200OverTLSEventually(t, hostHeader, address, port, path, certPem, keyPem, timeout)
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

// requireHTTP200OverTLSEventually waits for HTTP 200 status code over an HTTPS connection with TLS certificates.
// Uses Gateway API conformance TLS utilities for proper TLS passthrough testing.
func requireHTTP200OverTLSEventually(t *testing.T, host, address, port, path string, certPem, keyPem []byte, timeout time.Duration) {
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
		Namespace: "default",
		Request: gwhttp.Request{
			Host:   host,
			Method: "GET",
			Path:   path,
		},
		Response: gwhttp.Response{
			StatusCode: 200,
		},
	}

	// Create roundtripper that connects to IP but uses hostname for SNI
	rt := getRoundTripper()

	// Configure timeout config for the TLS request
	timeoutConfig := gwconfig.DefaultTimeoutConfig()
	timeoutConfig.MaxTimeToConsistency = timeout
	timeoutConfig.RequiredConsecutiveSuccesses = 1

	// Use Gateway API TLS utilities to make the request with certificates
	gwtls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, rt, timeoutConfig, gwAddr, certPem, keyPem, host, expected)
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

// pathAndCodeFromClient makes an HTTP request and returns the backend echoed path and status code.
// The echoed path comes from the conformance CapturedRequest (decoded from echo-backend JSON).
func pathAndCodeFromClient(t *testing.T, hostHeader, scheme, address, port, path string) (echoPath, code, out string, err error) {
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

	// Reduce chances of connection-based stickiness.
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
		echoPath = cReq.Path
	}
	code = fmt.Sprintf("%d", cRes.StatusCode)
	out = fmt.Sprintf("Status: %d, Protocol: %s, EchoPath: %s", cRes.StatusCode, cRes.Protocol, echoPath)
	return echoPath, code, out, nil
}

func requireEchoedPathEventually(
	t *testing.T,
	hostHeader, scheme, address, port, requestPath, expectedEchoPath string,
	timeout time.Duration,
) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastOut string
	var lastErr error
	var lastCode string
	var lastEchoPath string

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		echoPath, code, out, err := pathAndCodeFromClient(t, hostHeader, scheme, address, port, requestPath)
		lastEchoPath, lastCode, lastOut, lastErr = echoPath, code, out, err

		if err == nil && strings.TrimSpace(code) == "200" && echoPath == expectedEchoPath {
			return
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for echoed path %q (attempt=%d host=%s scheme=%s address=%s port=%s reqPath=%s): gotPath=%q code=%q err=%v out=%s",
				expectedEchoPath, attempt, hostHeader, scheme, address, port, requestPath, echoPath, strings.TrimSpace(code), err, out)
		}
		time.Sleep(interval)
	}

	t.Fatalf("timed out waiting for echoed path %q (request %q). lastEchoPath=%q lastCode=%q lastErr=%v lastOut=%s",
		expectedEchoPath, requestPath, lastEchoPath, strings.TrimSpace(lastCode), lastErr, lastOut)
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
