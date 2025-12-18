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
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	gwtests "sigs.k8s.io/gateway-api/conformance/tests"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
)

func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	kindClusterName = envOrDefault("KIND_CLUSTER_NAME", defaultClusterName)
	kubeContext = "kind-" + kindClusterName
	keepCluster = envOrDefault("KEEP_KIND_CLUSTER", "false") == "true"

	mustHaveBin("docker")
	mustHaveBin("kind")
	mustHaveBin("kubectl")
	mustHaveBin("helm")
	mustHaveBin("go")
	mustHaveBin("openssl")

	ctx := context.Background()

	// If the cluster exists, reuse it. Otherwise, create a new one.
	if kindClusterExists(ctx, kindClusterName) {
		log.Printf("Reusing existing kind cluster %q", kindClusterName)
	} else {
		createArgs := []string{"create", "cluster", "--name", kindClusterName, "--wait", "3m"}
		if img := os.Getenv("KIND_NODE_IMAGE"); img != "" {
			createArgs = append(createArgs, "--image", img)
		}
		mustRun(ctx, "kind", createArgs...)
	}

	// Ensure kubectl uses the right context.
	mustRun(ctx, "kind", "export", "kubeconfig", "--name", kindClusterName)

	// MetalLB so LoadBalancer services get external IPs in kind.
	installMetalLB(ctx)

	// Gateway API CRDs (experimental install includes standard + experimental types).
	installGatewayAPICRDs(ctx)

	// Install ingress-nginx (from the provided manifest URL, with version variable).
	installIngressNginx(ctx)

	// Install kgateway (chart version defaults to the module version in go.mod).
	installKgateway(ctx)

	// Shared backend echo server (kept across subtests).
	// HTTP requests are made directly from test code using Gateway API conformance utilities.
	applyEchoBackend(ctx)

	// TLS-enabled backend for SSL passthrough tests.
	applyTLSBackend(ctx)

	// Create file-based secret for basic auth tests.
	createBasicAuthFileSecret(ctx, "basic-auth")

	e2eSetupComplete = true

	code := m.Run()

	// Give stdout/stderr a moment to flush in some CI environments.
	time.Sleep(100 * time.Millisecond)

	if !keepCluster {
		_ = run(ctx, "kind", "delete", "cluster", "--name", kindClusterName)
	} else {
		log.Printf("KEEP_KIND_CLUSTER=true; leaving kind cluster %q running", kindClusterName)
	}

	os.Exit(code)
}

// e2eTestSetup handles common setup for e2e tests and returns the context, gateway address, host, and ingress address.
// The caller is responsible for cleanup and test-specific validation.
func e2eTestSetup(t *testing.T, inputFile, outputFile string) (context.Context, string, string, string, string) {
	if !e2eSetupComplete {
		t.Fatalf("e2e setup did not complete")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	root, err := moduleRoot(ctx)
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}

	inputDir := filepath.Join(root, "test/e2e/emitters/kgateway/testdata/input")
	outputDir := filepath.Join(root, "test/e2e/emitters/kgateway/testdata/output")

	inPath := filepath.Join(inputDir, inputFile)
	outPath := filepath.Join(outputDir, outputFile)

	// Apply input Ingress YAML.
	mustKubectl(ctx, "apply", "-f", inPath)

	// Ensure cleanup of per-test resources (but keep curl + echo).
	t.Cleanup(func() {
		if _, delErr := kubectl(ctx, "delete", "-f", outPath, "--ignore-not-found=true", "--wait=true", "--timeout=2m"); delErr != nil {
			t.Logf("failed to delete output: %v", delErr)
		}
		if _, delErr := kubectl(ctx, "delete", "-f", inPath, "--ignore-not-found=true", "--wait=true", "--timeout=2m"); delErr != nil {
			t.Logf("failed to delete input: %v", delErr)
		}
	})

	ingObjs, err := decodeObjects(inPath)
	if err != nil {
		t.Fatalf("decode input objects: %v", err)
	}
	ingresses := filterKind(ingObjs, "Ingress")
	if len(ingresses) == 0 {
		t.Fatalf("input %s had no Ingress objects", inPath)
	}

	// Get ingress-nginx-controller Service IP
	ingressIP, err := getIngressNginxControllerAddress(ctx)
	if err != nil {
		t.Fatalf("get ingress-nginx-controller service address: %v", err)
	}

	// Extract host header from Ingress resources.
	var hostHeader string
	for _, ing := range ingresses {
		if h, _ := firstIngressHost(ing); h != "" {
			hostHeader = h
			break
		}
	}
	if hostHeader == "" {
		hostHeader = "demo.localdev.me"
	}

	// Apply the matching ingress2gateway output YAML.
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected output file missing: %s (%v)", outPath, err)
	}
	mustKubectl(ctx, "apply", "-f", outPath)

	outObjs, err := decodeObjects(outPath)
	if err != nil {
		t.Fatalf("decode output objects: %v", err)
	}

	// Check expected status conditions (GatewayClass, Gateway, HTTPRoute, etc.).
	waitForOutputReadiness(t, ctx, outObjs, 1*time.Minute)

	// Get Gateway address.
	gws := filterKind(outObjs, "Gateway")
	if len(gws) == 0 {
		t.Fatalf("output %s had no Gateway objects", outPath)
	}
	gw := gws[0]
	gwNS := gw.GetNamespace()
	if gwNS == "" {
		gwNS = "default"
	}
	gwName := gw.GetName()

	gwAddr, err := waitForGatewayAddress(ctx, gwNS, gwName, 1*time.Minute)
	if err != nil {
		t.Fatalf("gateway address: %v", err)
	}

	// Prefer HTTPRoute or TLSRoute hostnames if present.
	host := hostHeader
	if hr := firstRouteHost(outObjs); hr != "" {
		host = hr
	}

	return ctx, gwAddr, host, hostHeader, ingressIP
}

func TestBasic(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "basic.yaml", "basic.yaml")

	// Test HTTP connectivity via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})

	// Test HTTP connectivity via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})
}

func TestSSLRedirect(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "ssl_redirect.yaml", "ssl_redirect.yaml")

	// Test HTTP redirect (308) through Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:          ingressHostHeader,
		Address:             ingressIP,
		Port:                "",
		Path:                "",
		ExpectedStatusCodes: []int{308},
		Timeout:             5 * time.Second,
		UnfollowRedirect:    true,
		SNI:                 ingressHostHeader,
		RedirectRequest: &roundtripper.RedirectRequest{
			Scheme: "https",
			Port:   "",
			Path:   "",
		},
	})

	// Test HTTP redirect (301) through Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:          host,
		Address:             gwAddr,
		Port:                "",
		Path:                "/",
		ExpectedStatusCodes: []int{301},
		Timeout:             5 * time.Second,
		UnfollowRedirect:    true,
		SNI:                 host,
		RedirectRequest: &roundtripper.RedirectRequest{
			Scheme: "https",
			Port:   "",
			Path:   "/",
		},
	})

	// Test HTTPS connectivity (HTTP 200 status code)
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "https",
		Address:            gwAddr,
		Port:               "443",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            5 * time.Second,
		SecretName:         "ssl-redirect-tls",
	})
}

func TestLoadBalance(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "load_balance.yaml", "load_balance.yaml")

	// Test HTTP connectivity via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})

	// Test HTTP connectivity via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})

	// Assert we actually see all 3 backends.
	requireLoadBalancedAcrossPodsEventually(t, host, "http", gwAddr, "80", "/", 3, 1*time.Minute)
}

func TestCORS(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "cors.yaml", "cors.yaml")

	// Test HTTP connectivity via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})

	// Test HTTP connectivity via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
	})
}

func TestRewriteTarget(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "rewrite_target.yaml", "rewrite_target.yaml")

	// Must match "test/e2e/emitters/kgateway/testdata/output/rewrite_target.yaml".
	reqPath := "/before/rewrite"
	wantPath := "/after/rewrite"

	// Validate behavior through Ingress (ingress-nginx)
	requireEchoedPathEventually(t, ingressHostHeader, "http", ingressIP, "", reqPath, wantPath, 1*time.Minute)

	// Validate behavior through Gateway (kgateway + generated TrafficPolicy)
	requireEchoedPathEventually(t, host, "http", gwAddr, "80", reqPath, wantPath, 1*time.Minute)
}

func TestUseRegex(t *testing.T) {
	_, gwAddr, _, _, ingressIP := e2eTestSetup(t, "use_regex.yaml", "use_regex.yaml")

	// Test HTTP connectivity via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myservicea.foo.org",
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/path/one",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myservicea.foo.org",
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/path/two",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myserviceb.foo.org",
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})

	// Test HTTP connectivity via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myservicea.foo.org",
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/path/one",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myservicea.foo.org",
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/path/two",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         "myserviceb.foo.org",
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
}

func TestUseRegexRewriteTarget(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "rewrite_target_use_regex.yaml", "rewrite_target_use_regex.yaml")

	// Ingress should rewrite /before/rewrite -> /after/rewrite
	requireEchoedPathEventually(t, ingressHostHeader, "http", ingressIP, "", "/before/rewrite", "/after/rewrite", 1*time.Minute)

	// Gateway should also rewrite /before/rewrite -> /after/rewrite
	requireEchoedPathEventually(t, host, "http", gwAddr, "80", "/before/rewrite", "/after/rewrite", 1*time.Minute)
}

func TestSessionAffinityCookie(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "session_affinity.yaml", "session_affinity.yaml")

	// Test HTTP connectivity via Ingress and Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/session/affinity",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/session/affinity",
		Timeout:            1 * time.Minute,
		ExpectedStatusCode: 200,
	})

	// With the same cookie value, we should stick to one pod.
	requireStickySessionEventually(t, host, "http", gwAddr, "80", "/session/affinity",
		"session-id", "abc123",
		20, 1*time.Minute)

	// Different cookie value should usually map to a different pod (best-effort).
	requireDifferentSessionUsuallyDifferentPod(t, host, "http", gwAddr, "80", "/session/affinity",
		"session-id", "abc123", "xyz789",
		20, 1*time.Minute)
}

func TestSSLPassthrough(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "ssl_passthrough.yaml", "ssl_passthrough.yaml")

	// Load TLS certificates from secret for verification
	cl, err := getKubernetesClient()
	if err != nil {
		t.Fatalf("failed to create Kubernetes client: %v", err)
	}
	certPem, keyPem, err := gwtests.GetTLSSecret(cl, types.NamespacedName{Namespace: "default", Name: "tls-secret"})
	if err != nil {
		t.Fatalf("unexpected error finding TLS secret: %v", err)
	}

	// Test TLS passthrough connectivity via Ingress using TLS certificates
	// For TLS passthrough, the backend certificate is presented to the client through the gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "https",
		Address:            ingressIP,
		Port:               "443",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
		CertPem:            certPem,
		KeyPem:             keyPem,
	})

	// Test TLS passthrough connectivity via Gateway using TLS certificates
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "https",
		Address:            gwAddr,
		Port:               "443",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
		CertPem:            certPem,
		KeyPem:             keyPem,
	})
}

func TestBasicAuth(t *testing.T) {
	_, gwAddr, host, ingressHostHeader, ingressIP := e2eTestSetup(t, "basic_auth.yaml", "basic_auth.yaml")

	username := "user"
	password := "password"

	// Test unauthenticated request → expect 401 via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		ExpectedStatusCode: 401,
		Timeout:            1 * time.Minute,
	})

	// Test unauthenticated request → expect 401 via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 401,
		Timeout:            1 * time.Minute,
	})

	// Test authenticated request with valid credentials → expect 200 via Ingress
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         ingressHostHeader,
		Scheme:             "http",
		Address:            ingressIP,
		Port:               "",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
		Username:           username,
		Password:           password,
	})

	// Test authenticated request with valid credentials → expect 200 via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 200,
		Timeout:            1 * time.Minute,
		Username:           username,
		Password:           password,
	})

	// Test authenticated request with invalid credentials → expect 401 via Gateway
	makeHTTPRequestEventually(t, HTTPRequestConfig{
		HostHeader:         host,
		Scheme:             "http",
		Address:            gwAddr,
		Port:               "80",
		Path:               "/",
		ExpectedStatusCode: 401,
		Timeout:            1 * time.Minute,
		Username:           username,
		Password:           "wrongpassword",
	})
}
