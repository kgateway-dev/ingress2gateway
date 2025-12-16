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
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

func requireHTTP200Eventually(t *testing.T, ctx context.Context, host, url string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, out, err := curlHTTPCodeFromClient(ctx, host, url)
		lastCode, lastOut, lastErr = code, out, err

		if err == nil && strings.TrimSpace(code) == "200" {
			return
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP 200 (attempt=%d host=%s url=%s): code=%q err=%v",
				attempt, host, url, strings.TrimSpace(code), err)
		}
		time.Sleep(interval)
	}

	_ = debugCurlVerbose(t, ctx, host, url)

	t.Fatalf("timed out waiting for HTTP 200 (host=%s url=%s timeout=%s). lastCode=%q lastErr=%v lastOut=%s",
		host, url, timeout, strings.TrimSpace(lastCode), lastErr, lastOut)
}

func curlHTTPCodeFromClient(ctx context.Context, host, url string) (code string, out string, err error) {
	// Avoid interpolating host/url into the shell script; pass them as args to sh -c.
	// This prevents accidental quoting that turns the URL into "'http://...'" (invalid).
	script := `set -o pipefail; curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 5 -H "Host: $1" "$2" || echo 000`
	out, err = kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--",
		"sh", "-c", script, "_", host, url,
	)
	if err != nil {
		// kubectl exec itself failed (rare). Treat like transient failure.
		return "000", out, err
	}
	return strings.TrimSpace(out), out, nil
}

// curlHTTPCodeWithResolveFromClient executes curl with --resolve for SNI and returns the HTTP status code.
// If insecure is true, adds -k flag to skip certificate verification.
// Extracts port and IP from the URL and uses --resolve "$host:$port:$ip" for SNI.
func curlHTTPCodeWithResolveFromClient(ctx context.Context, host, url string, insecure bool) (code string, out string, err error) {
	// Extract port and IP from URL for --resolve
	urlParts := strings.Split(strings.TrimPrefix(url, "https://"), "/")
	hostPort := urlParts[0]
	port := "443"
	resolveIP := hostPort
	if strings.Contains(hostPort, ":") {
		parts := strings.Split(hostPort, ":")
		if len(parts) == 2 {
			port = parts[1]
			resolveIP = parts[0]
		}
	}

	// Build httpsURL using the hostname (not IP) for SNI
	httpsURL := fmt.Sprintf("https://%s/", host)
	if len(urlParts) > 1 && urlParts[1] != "" {
		httpsURL = fmt.Sprintf("https://%s/%s", host, strings.Join(urlParts[1:], "/"))
	}

	insecureFlag := ""
	if insecure {
		insecureFlag = "-k "
	}

	// Use --resolve for SNI: --resolve "$host:$port:$ip"
	script := fmt.Sprintf(`set -o pipefail; curl %s-sS -o /dev/null -w "%%{http_code}" --connect-timeout 2 --max-time 5 --resolve "$1:$2:$3" "$4" 2>/dev/null || echo 000`, insecureFlag)
	kubectlArgs := append([]string{"-n", "default", "exec", "deploy/curl", "--"},
		"sh", "-c", script, "_", host, port, resolveIP, httpsURL)
	out, err = kubectl(ctx, kubectlArgs...)
	if err != nil {
		// kubectl exec itself failed (rare). Treat like transient failure.
		return "000", out, err
	}
	return strings.TrimSpace(out), out, nil
}

// curlHTTPRedirectFromClient executes curl and returns the HTTP status code and Location header.
// It does NOT follow redirects (no -L flag) so we can see the redirect response.
// If insecure is true, adds -k flag to skip certificate verification (useful for HTTPS with self-signed certs).
func curlHTTPRedirectFromClient(ctx context.Context, host, url string, insecure bool) (code string, location string, out string, err error) {
	// Use -i to include headers, -s for silent, but keep stderr for errors
	// Extract status code and Location header
	insecureFlag := ""
	if insecure {
		insecureFlag = "-k "
	}
	script := fmt.Sprintf(`set -o pipefail; curl %s-sSi --connect-timeout 2 --max-time 5 -H "Host: $1" "$2" 2>&1 || echo "000"`, insecureFlag)
	out, err = kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--",
		"sh", "-c", script, "_", host, url,
	)
	if err != nil {
		return "000", "", out, err
	}

	// Parse status code from HTTP/1.1 308 Permanent Redirect
	lines := strings.Split(out, "\n")
	code = "000"
	location = ""
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		if strings.HasPrefix(line, "HTTP/") {
			// Extract status code from "HTTP/1.1 308 Permanent Redirect"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				code = parts[1]
			}
		}
		if strings.HasPrefix(lineLower, "location:") {
			// Extract Location header value (case-insensitive)
			// Handle both "Location: https://..." and "location: https://..."
			idx := strings.Index(lineLower, "location:")
			if idx != -1 {
				location = strings.TrimSpace(line[idx+9:])
			}
		}
	}

	return code, location, out, nil
}

func debugCurlVerbose(t *testing.T, ctx context.Context, host, url string) error {
	t.Helper()
	script := `curl -v --connect-timeout 2 --max-time 5 -H "Host: $1" "$2" || true`
	out, err := kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--",
		"sh", "-c", script, "_", host, url,
	)
	t.Logf("debug curl -v output:\n%s", out)
	return err
}

// requireHTTPRedirectEventually waits for an HTTP redirect response with the expected status code
// and verifies the Location header contains https:// scheme.
// expectedCode should be "301" (Moved Permanently) or "308" (Permanent Redirect).
func requireHTTPRedirectEventually(t *testing.T, ctx context.Context, host, url string, expectedCode string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastLocation string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, location, out, err := curlHTTPRedirectFromClient(ctx, host, url, false)
		lastCode, lastLocation, lastOut, lastErr = code, location, out, err

		codeTrimmed := strings.TrimSpace(code)
		if err == nil && codeTrimmed == expectedCode {
			// Verify Location header contains https://
			if strings.HasPrefix(strings.ToLower(location), "https://") {
				return
			}
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP %s redirect (attempt=%d host=%s url=%s): code=%q location=%q err=%v",
				expectedCode, attempt, host, url, codeTrimmed, location, err)
		}
		time.Sleep(interval)
	}

	_ = debugCurlVerbose(t, ctx, host, url)

	t.Fatalf("timed out waiting for HTTP %s redirect (host=%s url=%s timeout=%s). lastCode=%q lastLocation=%q lastErr=%v lastOut=%s",
		expectedCode, host, url, timeout, strings.TrimSpace(lastCode), lastLocation, lastErr, lastOut)
}

// requireHTTP200OverHTTPSEventually waits for HTTP 200 status code over an HTTPS connection using insecure curl (-k flag).
func requireHTTP200OverHTTPSEventually(t *testing.T, ctx context.Context, host, url string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 2 * time.Second

	var lastCode string
	var lastOut string
	var lastErr error

	for attempt := 1; time.Now().Before(deadline); attempt++ {
		code, out, err := curlHTTPCodeWithResolveFromClient(ctx, host, url, true)
		lastCode, lastOut, lastErr = code, out, err

		if err == nil && strings.TrimSpace(code) == "200" {
			return
		}

		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP 200 over HTTPS (attempt=%d host=%s url=%s): code=%q err=%v",
				attempt, host, url, strings.TrimSpace(code), err)
		}
		time.Sleep(interval)
	}

	// Debug with verbose curl using --resolve for SNI
	urlParts := strings.Split(strings.TrimPrefix(url, "https://"), "/")
	hostPort := urlParts[0]
	port := "443"
	if strings.Contains(hostPort, ":") {
		parts := strings.Split(hostPort, ":")
		if len(parts) == 2 {
			port = parts[1]
		}
		hostPort = parts[0]
	}
	httpsURL := fmt.Sprintf("https://%s/", host)
	if len(urlParts) > 1 && urlParts[1] != "" {
		httpsURL = fmt.Sprintf("https://%s/%s", host, strings.Join(urlParts[1:], "/"))
	}
	script := `curl -kv --connect-timeout 2 --max-time 5 --resolve "$1:$2:$3" "$4" || true`
	out, _ := kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--",
		"sh", "-c", script, "_", host, port, hostPort, httpsURL,
	)
	t.Logf("debug curl -kv output:\n%s", out)

	t.Fatalf("timed out waiting for HTTP 200 over HTTPS (host=%s url=%s timeout=%s). lastCode=%q lastErr=%v lastOut=%s",
		host, url, timeout, strings.TrimSpace(lastCode), lastErr, lastOut)
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
