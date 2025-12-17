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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/gateway-api/conformance/utils/config"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
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
	timeoutConfig := config.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second
	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
	}
}

// getRoundTripperWithSNI creates a DefaultRoundTripper with custom dialer for SNI support.
// The dialer connects to the provided IP address but uses the hostname for SNI.
// If insecure is true, TLS verification is skipped.
func getRoundTripperWithSNI(ip string, hostname string, insecure bool) roundtripper.RoundTripper {
	timeoutConfig := config.DefaultTimeoutConfig()
	timeoutConfig.RequestTimeout = 5 * time.Second

	return &roundtripper.DefaultRoundTripper{
		TimeoutConfig: timeoutConfig,
		CustomDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Parse the address to extract port
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Connect to the IP address instead of resolving the hostname
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
}

func requireHTTP200Eventually(t *testing.T, ctx context.Context, hostHeader, scheme, address, port, path string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, out, err := httpCodeFromClient(t, hostHeader, scheme, address, port, path)
		lastCode, lastOut, lastErr = code, out, err

		if err == nil && strings.TrimSpace(code) == "200" {
			return
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP 200 (attempt=%d host=%s scheme=%s address=%s port=%s path=%s): code=%q err=%v",
				attempt, hostHeader, scheme, address, port, path, strings.TrimSpace(code), err)
		}
		time.Sleep(interval)
	}

	_ = debugHTTPVerbose(t, hostHeader, scheme, address, port, path)

	t.Fatalf("timed out waiting for HTTP 200 (host=%s scheme=%s address=%s port=%s path=%s timeout=%s). lastCode=%q lastErr=%v lastOut=%s",
		hostHeader, scheme, address, port, path, timeout, strings.TrimSpace(lastCode), lastErr, lastOut)
}

// httpCodeFromClient makes an HTTP request using Gateway API conformance utilities and returns the status code.
func httpCodeFromClient(t *testing.T, hostHeader, scheme, address, port, path string) (code string, out string, err error) {
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

	// gwhttp.MakeRequest expects gwAddr in format "host:port" or just "host" (it handles default ports)
	// But CalculateHost will strip default ports, so we need to pass address:port
	gwAddr := net.JoinHostPort(address, port)

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:   hostHeader,
			Method: "GET",
			Path:   path,
		},
		Response: gwhttp.Response{
			StatusCode: 200, // We'll check the actual status code from the response
		},
	}

	req := gwhttp.MakeRequest(t, &expected, gwAddr, strings.ToUpper(scheme), scheme)
	rt := getRoundTripper()

	cReq, cRes, err := rt.CaptureRoundTrip(req)
	if err != nil {
		return "000", fmt.Sprintf("request failed: %v", err), err
	}

	statusCode := fmt.Sprintf("%d", cRes.StatusCode)
	responseInfo := fmt.Sprintf("Status: %d, Protocol: %s", cRes.StatusCode, cRes.Protocol)
	if cReq != nil {
		responseInfo += fmt.Sprintf(", Path: %s, Host: %s", cReq.Path, cReq.Host)
	}

	return statusCode, responseInfo, nil
}

// httpCodeWithSNIFromClient makes an HTTPS request with SNI support using Gateway API conformance utilities.
// It connects to the IP address but uses the hostname for SNI.
// If insecure is true, TLS certificate verification is skipped.
func httpCodeWithSNIFromClient(t *testing.T, hostHeader, address, port, path string, insecure bool) (code string, out string, err error) {
	t.Helper()

	// Set defaults
	if port == "" {
		port = "443"
	}
	if path == "" {
		path = "/"
	}

	ip := address

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:   hostHeader,
			Method: "GET",
			Path:   path,
			SNI:    hostHeader, // Set SNI to the hostname
		},
		Response: gwhttp.Response{
			StatusCode: 200,
		},
	}

	req := gwhttp.MakeRequest(t, &expected, fmt.Sprintf("%s:%s", hostHeader, port), "HTTPS", "https")
	req.Server = hostHeader // Set Server for SNI

	// Create roundtripper with custom dialer for IP connection and SNI
	rt := getRoundTripperWithSNI(ip, hostHeader, insecure)

	// For insecure connections, we need to customize the TLS config
	// The roundtripper doesn't directly support InsecureSkipVerify via Request,
	// so we'll need to handle this in the custom dialer or create a custom transport
	if insecure {
		// We'll handle this by creating a custom transport wrapper
		timeoutConfig := config.DefaultTimeoutConfig()
		timeoutConfig.RequestTimeout = 5 * time.Second
		rt = &roundtripper.DefaultRoundTripper{
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
		// We need to set TLS config with InsecureSkipVerify
		// This requires accessing the transport, which we'll do via a custom implementation
		// For now, let's use a simpler approach with a custom HTTP client
		return httpCodeWithSNIInsecure(t, hostHeader, ip, port, path)
	}

	cReq, cRes, err := rt.CaptureRoundTrip(req)
	if err != nil {
		return "000", fmt.Sprintf("request failed: %v", err), err
	}

	statusCode := fmt.Sprintf("%d", cRes.StatusCode)
	responseInfo := fmt.Sprintf("Status: %d, Protocol: %s", cRes.StatusCode, cRes.Protocol)
	if cReq != nil {
		responseInfo += fmt.Sprintf(", Path: %s, Host: %s", cReq.Path, cReq.Host)
	}

	return statusCode, responseInfo, nil
}

// httpCodeWithSNIInsecure makes an HTTPS request with SNI and insecure TLS verification.
func httpCodeWithSNIInsecure(t *testing.T, hostname, ip, port, path string) (code string, out string, err error) {
	t.Helper()

	// Create a custom HTTP client with TLS config that skips verification
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         hostname,
				InsecureSkipVerify: true,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	urlStr := fmt.Sprintf("https://%s:%s%s", hostname, port, path)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "000", "", fmt.Errorf("create request: %w", err)
	}
	req.Host = hostname

	resp, err := client.Do(req)
	if err != nil {
		return "000", fmt.Sprintf("request failed: %v", err), err
	}
	defer resp.Body.Close()

	statusCode := fmt.Sprintf("%d", resp.StatusCode)
	responseInfo := fmt.Sprintf("Status: %d, Protocol: %s", resp.StatusCode, resp.Proto)

	return statusCode, responseInfo, nil
}

// httpRedirectFromClient makes an HTTP request and returns the status code and Location header.
// It does NOT follow redirects so we can see the redirect response.
// If insecure is true, TLS certificate verification is skipped (useful for HTTPS with self-signed certs).
func httpRedirectFromClient(t *testing.T, hostHeader, scheme, address, port, path string, insecure bool) (code string, location string, out string, err error) {
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

	// gwhttp.MakeRequest expects gwAddr in format "host:port" or just "host" (it handles default ports)
	// But CalculateHost will strip default ports, so we need to pass address:port
	gwAddr := net.JoinHostPort(address, port)

	expected := gwhttp.ExpectedResponse{
		Request: gwhttp.Request{
			Host:             hostHeader,
			Method:           "GET",
			Path:             path,
			UnfollowRedirect: true, // Don't follow redirects
		},
		Response: gwhttp.Response{
			StatusCode: 200, // We'll check the actual status code from the response
		},
	}

	req := gwhttp.MakeRequest(t, &expected, gwAddr, strings.ToUpper(scheme), scheme)
	req.UnfollowRedirect = true

	var rt roundtripper.RoundTripper
	if scheme == "https" && insecure {
		// For HTTPS with insecure, use custom client
		return httpRedirectInsecure(t, hostHeader, address, port, path)
	}

	rt = getRoundTripper()
	_, cRes, err := rt.CaptureRoundTrip(req)
	if err != nil {
		return "000", "", fmt.Sprintf("request failed: %v", err), err
	}

	statusCode := fmt.Sprintf("%d", cRes.StatusCode)
	locationHeader := ""
	if cRes.Headers != nil {
		for k, v := range cRes.Headers {
			if strings.ToLower(k) == "location" && len(v) > 0 {
				locationHeader = v[0]
				break
			}
		}
	}

	responseInfo := fmt.Sprintf("Status: %d, Protocol: %s", cRes.StatusCode, cRes.Protocol)
	if locationHeader != "" {
		responseInfo += fmt.Sprintf(", Location: %s", locationHeader)
	}

	return statusCode, locationHeader, responseInfo, nil
}

// httpRedirectInsecure makes an HTTP request with insecure TLS and returns redirect info.
func httpRedirectInsecure(t *testing.T, hostHeader, address, port, path string) (code string, location string, out string, err error) {
	t.Helper()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	urlStr := fmt.Sprintf("https://%s:%s%s", address, port, path)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "000", "", "", fmt.Errorf("create request: %w", err)
	}
	req.Host = hostHeader

	resp, err := client.Do(req)
	if err != nil {
		return "000", "", fmt.Sprintf("request failed: %v", err), err
	}
	defer resp.Body.Close()

	statusCode := fmt.Sprintf("%d", resp.StatusCode)
	locationHeader := resp.Header.Get("Location")

	responseInfo := fmt.Sprintf("Status: %d, Protocol: %s", resp.StatusCode, resp.Proto)
	if locationHeader != "" {
		responseInfo += fmt.Sprintf(", Location: %s", locationHeader)
	}

	return statusCode, locationHeader, responseInfo, nil
}

// debugHTTPVerbose logs detailed HTTP request/response information for debugging.
func debugHTTPVerbose(t *testing.T, hostHeader, scheme, address, port, path string) error {
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

	// gwhttp.MakeRequest expects gwAddr in format "host:port" or just "host" (it handles default ports)
	// But CalculateHost will strip default ports, so we need to pass address:port
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

	req := gwhttp.MakeRequest(t, &expected, gwAddr, strings.ToUpper(scheme), scheme)
	rt := getRoundTripper()

	cReq, cRes, err := rt.CaptureRoundTrip(req)
	if err != nil {
		t.Logf("debug: request failed: %v", err)
		return err
	}

	t.Logf("debug HTTP request details:")
	t.Logf("  Scheme: %s", scheme)
	t.Logf("  Address: %s", address)
	t.Logf("  Port: %s", port)
	t.Logf("  Path: %s", path)
	t.Logf("  Host header: %s", hostHeader)
	if cReq != nil {
		t.Logf("  Request Path: %s", cReq.Path)
		t.Logf("  Request Host: %s", cReq.Host)
		t.Logf("  Request Method: %s", cReq.Method)
		t.Logf("  Request Protocol: %s", cReq.Protocol)
	}
	if cRes != nil {
		t.Logf("  Response Status: %d", cRes.StatusCode)
		t.Logf("  Response Protocol: %s", cRes.Protocol)
		if cRes.Headers != nil {
			t.Logf("  Response Headers: %v", cRes.Headers)
		}
	}

	return nil
}

// requireHTTPRedirectEventually waits for an HTTP redirect response with the expected status code
// and verifies the Location header contains https:// scheme.
// expectedCode should be "301" (Moved Permanently) or "308" (Permanent Redirect).
func requireHTTPRedirectEventually(t *testing.T, ctx context.Context, hostHeader, scheme, address, port, path string, expectedCode string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastLocation string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, location, out, err := httpRedirectFromClient(t, hostHeader, scheme, address, port, path, false)
		lastCode, lastLocation, lastOut, lastErr = code, location, out, err

		codeTrimmed := strings.TrimSpace(code)
		if err == nil && codeTrimmed == expectedCode {
			// Verify Location header contains https://
			if strings.HasPrefix(strings.ToLower(location), "https://") {
				return
			}
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP %s redirect (attempt=%d host=%s scheme=%s address=%s port=%s path=%s): code=%q location=%q err=%v",
				expectedCode, attempt, hostHeader, scheme, address, port, path, codeTrimmed, location, err)
		}
		time.Sleep(interval)
	}

	_ = debugHTTPVerbose(t, hostHeader, scheme, address, port, path)

	t.Fatalf("timed out waiting for HTTP %s redirect (host=%s scheme=%s address=%s port=%s path=%s timeout=%s). lastCode=%q lastLocation=%q lastErr=%v lastOut=%s",
		expectedCode, hostHeader, scheme, address, port, path, timeout, strings.TrimSpace(lastCode), lastLocation, lastErr, lastOut)
}

// requireHTTP200OverHTTPSEventually waits for HTTP 200 status code over an HTTPS connection with insecure TLS verification.
func requireHTTP200OverHTTPSEventually(t *testing.T, ctx context.Context, hostHeader, address, port, path string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, out, err := httpCodeWithSNIFromClient(t, hostHeader, address, port, path, true)
		lastCode, lastOut, lastErr = code, out, err

		if err == nil && strings.TrimSpace(code) == "200" {
			return
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP 200 over HTTPS (attempt=%d host=%s address=%s port=%s path=%s): code=%q err=%v",
				attempt, hostHeader, address, port, path, strings.TrimSpace(code), err)
		}
		time.Sleep(interval)
	}

	// Debug with verbose HTTP
	_ = debugHTTPVerbose(t, hostHeader, "https", address, port, path)

	t.Fatalf("timed out waiting for HTTP 200 over HTTPS (host=%s address=%s port=%s path=%s timeout=%s). lastCode=%q lastErr=%v lastOut=%s",
		hostHeader, address, port, path, timeout, strings.TrimSpace(lastCode), lastErr, lastOut)
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
