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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	defaultClusterName         = "i2g-kgtw"
	defaultIngressNginxVersion = "v1.14.1"
	defaultGatewayAPIVersion   = "v1.4.0"
	defaultMetalLBVersion      = "v0.15.3"
	defaultCurlImage           = "curlimages/curl:8.6.0"

	defaultEchoImage = "gcr.io/k8s-staging-gateway-api/echo-basic:v20231214-v1.0.0-140-gf544a46e"
)

var (
	kubeContext      string
	kindClusterName  string
	keepCluster      bool
	e2eSetupComplete bool
)

func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	kindClusterName = envOrDefault("KIND_CLUSTER_NAME", defaultClusterName)
	kubeContext = "kind-" + kindClusterName
	keepCluster = envOrDefault("KEEP_KIND_CLUSTER", "") == "false"

	mustHaveBin("docker")
	mustHaveBin("kind")
	mustHaveBin("kubectl")
	mustHaveBin("helm")
	mustHaveBin("go")

	ctx := context.Background()

	// Recreate cluster for determinism.
	_ = run(ctx, "kind", "delete", "cluster", "--name", kindClusterName)

	createArgs := []string{"create", "cluster", "--name", kindClusterName, "--wait", "3m"}
	if img := os.Getenv("KIND_NODE_IMAGE"); img != "" {
		createArgs = append(createArgs, "--image", img)
	}
	mustRun(ctx, "kind", createArgs...)

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

	// Shared test client + backend echo server (kept across subtests).
	applyCurlClient(ctx)
	applyEchoBackend(ctx)

	e2eSetupComplete = true

	code := m.Run()

	if !keepCluster {
		_ = run(ctx, "kind", "delete", "cluster", "--name", kindClusterName)
	} else {
		log.Printf("KEEP_KIND_CLUSTER=true; leaving kind cluster %q running", kindClusterName)
	}

	os.Exit(code)
}

func TestIngress2GatewayE2E(t *testing.T) {
	if !e2eSetupComplete {
		t.Fatalf("e2e setup did not complete")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	root, err := moduleRoot(ctx)
	if err != nil {
		t.Fatalf("moduleRoot: %v", err)
	}

	inputDir := filepath.Join(root, "test/e2e/emitters/kgateway/testdata/input")
	outputDir := filepath.Join(root, "test/e2e/emitters/kgateway/testdata/output")

	inFiles, err := filepath.Glob(filepath.Join(inputDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob input: %v", err)
	}
	if len(inFiles) == 0 {
		t.Fatalf("no test cases found in %s", inputDir)
	}

	for _, inPath := range inFiles {
		name := strings.TrimSuffix(filepath.Base(inPath), filepath.Ext(inPath))
		outPath := filepath.Join(outputDir, name+".yaml")

		t.Run(name, func(t *testing.T) {
			// Apply input Ingress YAML.
			mustKubectl(ctx, "apply", "-f", inPath)

			// Ensure cleanup of per-test resources (but keep curl + echo).
			t.Cleanup(func() {
				if _, err = kubectl(ctx, "delete", "-f", outPath, "--ignore-not-found=true", "--wait=true", "--timeout=2m"); err != nil {
					t.Logf("failed to delete output: %v", err)
				}
				if _, err = kubectl(ctx, "delete", "-f", inPath, "--ignore-not-found=true", "--wait=true", "--timeout=2m"); err != nil {
					t.Logf("failed to delete input: %v", err)
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

			// Wait for Ingress status before proceeding.
			var ingressIP string
			var hostHeader string
			for _, ing := range ingresses {
				ns := ing.GetNamespace()
				if ns == "" {
					ns = "default"
				}
				waitForIngressAddress(t, ctx, ns, ing.GetName(), 1*time.Minute)
				ipOrHost, err := getIngressAddress(ctx, ns, ing.GetName())
				if err != nil {
					t.Fatalf("get ingress address: %v", err)
				}
				ingressIP = ipOrHost

				h, _ := firstIngressHost(ing)
				if h != "" {
					hostHeader = h
				}
			}
			if hostHeader == "" {
				// Fall back to something predictable if input doesn’t include a host
				hostHeader = "demo.localdev.me"
			}

			// Curl via Ingress (from the in-cluster curl client).
			requireHTTP200Eventually(t, ctx, hostHeader, fmt.Sprintf("http://%s/", ingressIP), 1*time.Minute)

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

			// Get Gateway IP of Gateway.
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

			// Prefer HTTPRoute hostnames if present.
			host := hostHeader
			if hr := firstHTTPRouteHost(outObjs); hr != "" {
				host = hr
			}

			// Curl via Gateway.
			requireHTTP200Eventually(t, ctx, host, fmt.Sprintf("http://%s:80/", gwAddr), 1*time.Minute)
		})
	}
}

func installMetalLB(ctx context.Context) {
	ver := envOrDefault("METALLB_VERSION", defaultMetalLBVersion)
	manifestURL := fmt.Sprintf("https://raw.githubusercontent.com/metallb/metallb/%s/config/manifests/metallb-native.yaml", ver)

	log.Printf("Installing MetalLB %s", ver)
	mustKubectl(ctx, "apply", "-f", manifestURL)

	// Wait for MetalLB controller + speaker.
	mustKubectl(ctx, "-n", "metallb-system", "rollout", "status", "deploy/controller", "--timeout=3m")
	// speaker is a DaemonSet in native manifest.
	mustKubectl(ctx, "-n", "metallb-system", "rollout", "status", "ds/speaker", "--timeout=3m")

	// Configure an address pool inside the kind Docker network.
	cidr := mustDockerKindSubnet(ctx)
	start, end, err := pickLBRange(cidr, 50)
	if err != nil {
		panic(fmt.Errorf("pick LB range from %s: %w", cidr, err))
	}
	poolYAML := fmt.Sprintf(`
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: kind-pool
  namespace: metallb-system
spec:
  addresses:
  - %s-%s
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: kind-adv
  namespace: metallb-system
spec:
  ipAddressPools:
  - kind-pool
`, start, end)

	log.Printf("Configuring MetalLB IPAddressPool %s-%s (from kind subnet %s)", start, end, cidr)
	mustKubectlApplyStdin(ctx, poolYAML)
}

func installGatewayAPICRDs(ctx context.Context) {
	ver := envOrDefault("GATEWAY_API_VERSION", defaultGatewayAPIVersion)
	url := fmt.Sprintf("https://github.com/kubernetes-sigs/gateway-api/releases/download/%s/experimental-install.yaml", ver)

	log.Printf("Installing Gateway API CRDs %s (experimental)", ver)
	mustKubectl(ctx, "apply", "--server-side=true", "-f", url)

	// Basic sanity: ensure CRDs exist.
	mustKubectl(ctx, "get", "crd", "gateways.gateway.networking.k8s.io")
	mustKubectl(ctx, "get", "crd", "httproutes.gateway.networking.k8s.io")
}

func installKgateway(ctx context.Context) {
	// Use the module version found in go.mod
	modVer, err := kgatewayVersionFromGoMod(ctx)
	if err != nil {
		panic(fmt.Errorf("read kgateway module version from go.mod: %w", err))
	}
	chartVer := envOrDefault("KGATEWAY_VERSION", modVer)
	ns := "kgateway-system"

	log.Printf("Installing kgateway chart version %s (module version: %s)", chartVer, modVer)

	// Install kgateway CRDs.
	mustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway-crds",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds",
		"--create-namespace", "--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
	)

	// Install kgateway.
	mustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway",
		"--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
		"--set", "controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true",
	)

	// Wait for control plane to be running.
	mustKubectl(ctx, "-n", ns, "rollout", "status", "deploy/kgateway", "--timeout=3m")

	// Verify the expected GatewayClass exists and is Accepted.
	if _, err := kubectl(ctx, "get", "gatewayclass", "kgateway"); err != nil {
		panic(fmt.Errorf("expected GatewayClass/kgateway not found: %w", err))
	}
	if _, err := kubectl(ctx, "wait", "--for=condition=Accepted", "gatewayclass/kgateway", "--timeout=1m"); err != nil {
		panic(fmt.Errorf("GatewayClass/kgateway not Accepted: %w", err))
	}
}

func installIngressNginx(ctx context.Context) {
	ver := envOrDefault("INGRESS_NGINX_VERSION", defaultIngressNginxVersion)
	url := fmt.Sprintf("https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-%s/deploy/static/provider/cloud/deploy.yaml", ver)

	log.Printf("Installing ingress-nginx %s from %s", ver, url)
	mustKubectl(ctx, "apply", "-f", url)

	// Wait for controller deployment.
	mustKubectl(ctx, "-n", "ingress-nginx", "rollout", "status", "deploy/ingress-nginx-controller", "--timeout=1m")

	// Wait for controller service to receive an external IP (MetalLB).
	_, err := waitForServiceAddress(ctx, "ingress-nginx", "ingress-nginx-controller", 1*time.Minute)
	if err != nil {
		panic(fmt.Errorf("ingress-nginx-controller external IP: %w", err))
	}
}

func applyCurlClient(ctx context.Context) {
	img := envOrDefault("CURL_IMAGE", defaultCurlImage)
	y := fmt.Sprintf(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: curl
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: curl
  template:
    metadata:
      labels:
        app: curl
    spec:
      containers:
      - name: curl
        image: %s
        command: ["sh","-c","sleep 365d"]
`, img)

	log.Printf("Deploying curl client (%s)", img)
	mustKubectlApplyStdin(ctx, y)
	mustKubectl(ctx, "-n", "default", "rollout", "status", "deploy/curl", "--timeout=5m")
}

func applyEchoBackend(ctx context.Context) {
	img := envOrDefault("ECHO_IMAGE", defaultEchoImage)
	y := fmt.Sprintf(`
apiVersion: v1
kind: Service
metadata:
  name: echo-backend
  namespace: default
spec:
  selector:
    app: echo-backend
  ports:
  - name: http
    port: 8080
    targetPort: 3000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-backend
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-backend
  template:
    metadata:
      labels:
        app: echo-backend
    spec:
      containers:
      - name: echo-backend
        image: %s
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        ports:
        - containerPort: 3000
        readinessProbe:
          httpGet:
            path: /
            port: 3000
          initialDelaySeconds: 2
          periodSeconds: 2
`, img)

	log.Printf("Deploying echo backend (%s)", img)
	mustKubectlApplyStdin(ctx, y)
	mustKubectl(ctx, "-n", "default", "rollout", "status", "deploy/echo-backend", "--timeout=5m")
}

func waitForOutputReadiness(t *testing.T, ctx context.Context, objs []unstructured.Unstructured, timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	// GatewayClass: Accepted=True
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

	// Gateway: Accepted=True and Programmed=True
	for _, gw := range filterKind(objs, "Gateway") {
		ns := gw.GetNamespace()
		if ns == "" {
			ns = "default"
		}
		name := gw.GetName()

		for time.Now().Before(deadline) {
			u, err := getUnstructured(ctx, "gateway", ns, name)
			if err == nil &&
				hasTopLevelCondition(u, "Accepted", "True") &&
				hasTopLevelCondition(u, "Programmed", "True") {
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

	// HTTPRoute: within status.parents[*].conditions, need Accepted=True and ResolvedRefs=True
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

		// Optional: log occasionally so you can see progress without flooding output.
		if attempt == 1 || attempt%10 == 0 {
			t.Logf("waiting for HTTP 200 (attempt=%d host=%s url=%s): code=%q err=%v",
				attempt, host, url, strings.TrimSpace(code), err)
		}

		time.Sleep(interval)
	}

	// One last verbose curl for debug (helps understand 503s quickly).
	_ = debugCurlVerbose(t, ctx, host, url)

	t.Fatalf("timed out waiting for HTTP 200 (host=%s url=%s timeout=%s). lastCode=%q lastErr=%v lastOut=%s",
		host, url, timeout, strings.TrimSpace(lastCode), lastErr, lastOut)
}

func curlHTTPCodeFromClient(ctx context.Context, host, url string) (code string, out string, err error) {
	// NOTE: If curl fails to connect, it may exit non-zero.
	// We translate that to an error and use code "000" to keep the retry loop simple.
	cmd := fmt.Sprintf(`
set -o pipefail
code=$(curl -sS -o /dev/null -w "%%{http_code}" --connect-timeout 2 --max-time 5 -H "Host: %s" "%s" 2>&1) || {
  echo "000"
  exit 0
}
echo "$code"
`, shellEscape(host), shellEscape(url))

	out, err = kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--", "sh", "-c", cmd)
	if err != nil {
		return "000", out, err
	}
	return strings.TrimSpace(out), out, nil
}

func debugCurlVerbose(t *testing.T, ctx context.Context, host, url string) error {
	t.Helper()
	out, err := kubectl(ctx, "-n", "default", "exec", "deploy/curl", "--",
		"sh", "-c",
		fmt.Sprintf(`curl -v --connect-timeout 2 --max-time 5 -H "Host: %s" "%s" || true`, shellEscape(host), shellEscape(url)),
	)
	t.Logf("debug curl -v output:\n%s", out)
	return err
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

func decodeObjects(path string) ([]unstructured.Unstructured, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := k8syaml.NewYAMLOrJSONDecoder(f, 4096)

	var objs []unstructured.Unstructured
	for {
		var raw map[string]any
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		u := unstructured.Unstructured{Object: raw}
		// Skip “List” wrapper objects.
		if u.GetKind() == "List" {
			items, found, _ := unstructured.NestedSlice(u.Object, "items")
			if found {
				for _, it := range items {
					m, ok := it.(map[string]any)
					if ok && len(m) > 0 {
						objs = append(objs, unstructured.Unstructured{Object: m})
					}
				}
			}
			continue
		}
		objs = append(objs, u)
	}
	return objs, nil
}

func filterKind(objs []unstructured.Unstructured, kind string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, o := range objs {
		if o.GetKind() == kind {
			out = append(out, o)
		}
	}
	return out
}

func firstIngressHost(ing unstructured.Unstructured) (string, bool) {
	rules, found, _ := unstructured.NestedSlice(ing.Object, "spec", "rules")
	if !found || len(rules) == 0 {
		return "", false
	}
	r0, ok := rules[0].(map[string]any)
	if !ok {
		return "", false
	}
	h, _ := r0["host"].(string)
	return h, h != ""
}

func firstHTTPRouteHost(objs []unstructured.Unstructured) string {
	for _, o := range objs {
		if o.GetKind() != "HTTPRoute" {
			continue
		}
		hosts, found, _ := unstructured.NestedStringSlice(o.Object, "spec", "hostnames")
		if found && len(hosts) > 0 && hosts[0] != "" {
			return hosts[0]
		}
	}
	return ""
}

func getIngressAddress(ctx context.Context, ns, name string) (string, error) {
	u, err := getUnstructured(ctx, "ingress", ns, name)
	if err != nil {
		return "", err
	}
	ings, found, _ := unstructured.NestedSlice(u.Object, "status", "loadBalancer", "ingress")
	if !found || len(ings) == 0 {
		return "", fmt.Errorf("no status.loadBalancer.ingress yet")
	}
	m, ok := ings[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected ingress status shape")
	}
	if ip, _ := m["ip"].(string); ip != "" {
		return ip, nil
	}
	if hn, _ := m["hostname"].(string); hn != "" {
		return hn, nil
	}
	return "", fmt.Errorf("no ip/hostname in status.loadBalancer.ingress[0]")
}

func hasTopLevelCondition(u unstructured.Unstructured, typ, status string) bool {
	conds, found, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	if !found {
		return false
	}
	return anyConditionEquals(conds, typ, status)
}

func hasRouteParentCondition(u unstructured.Unstructured, typ, status string) bool {
	parents, found, _ := unstructured.NestedSlice(u.Object, "status", "parents")
	if !found {
		return false
	}
	for _, p := range parents {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		conds, found, _ := unstructured.NestedSlice(pm, "conditions")
		if !found {
			continue
		}
		if anyConditionEquals(conds, typ, status) {
			return true
		}
	}
	return false
}

func anyConditionEquals(conds []any, typ, status string) bool {
	for _, c := range conds {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := cm["type"].(string)
		s, _ := cm["status"].(string)
		if t == typ && s == status {
			return true
		}
	}
	return false
}

func getGatewayStatusAddress(u unstructured.Unstructured) string {
	addrs, found, _ := unstructured.NestedSlice(u.Object, "status", "addresses")
	if !found || len(addrs) == 0 {
		return ""
	}
	m, ok := addrs[0].(map[string]any)
	if !ok {
		return ""
	}
	v, _ := m["value"].(string)
	return v
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

func mustHaveBin(name string) {
	if _, err := exec.LookPath(name); err != nil {
		panic(fmt.Errorf("required binary %q not found in PATH", name))
	}
}

func mustRun(ctx context.Context, bin string, args ...string) {
	if err := run(ctx, bin, args...); err != nil {
		panic(err)
	}
}

func run(ctx context.Context, bin string, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("RUN: %s %s", bin, strings.Join(args, " "))
	return cmd.Run()
}

func kubectl(ctx context.Context, args ...string) (string, error) {
	base := []string{"--context", kubeContext}
	base = append(base, args...)
	cmd := exec.CommandContext(ctx, "kubectl", base...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	log.Printf("KUBECTL: kubectl %s", strings.Join(base, " "))
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		if se := strings.TrimSpace(stderr.String()); se != "" {
			out = out + "\n" + se
		}
		return out, fmt.Errorf("kubectl %v: %w", args, err)
	}
	return out, nil
}

func mustKubectl(ctx context.Context, args ...string) {
	out, err := kubectl(ctx, args...)
	if err != nil {
		panic(fmt.Errorf("kubectl failed: %v\n%s", err, out))
	}
}

func mustKubectlApplyStdin(ctx context.Context, yaml string) {
	cmd := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("KUBECTL: kubectl --context %s apply -f -", kubeContext)
	if err := cmd.Run(); err != nil {
		panic(fmt.Errorf("kubectl apply -f - failed: %w", err))
	}
}

func getUnstructured(ctx context.Context, resource, ns, name string) (unstructured.Unstructured, error) {
	args := []string{"get", resource, name, "-o", "json"}
	if ns != "" {
		args = append([]string{"-n", ns}, args...)
	}
	out, err := kubectl(ctx, args...)
	if err != nil {
		return unstructured.Unstructured{}, err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		return unstructured.Unstructured{}, err
	}
	return unstructured.Unstructured{Object: obj}, nil
}

func kgatewayVersionFromGoMod(ctx context.Context) (string, error) {
	// Use go env GOMOD to locate the active go.mod.
	out, err := exec.CommandContext(ctx, "go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w: %s", err, string(out))
	}
	goModPath := strings.TrimSpace(string(out))
	if goModPath == "" || goModPath == os.DevNull {
		return "", fmt.Errorf("GOMOD not set (are you running in module mode?)")
	}
	b, err := os.ReadFile(goModPath)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`(?m)^\s*github\.com/kgateway-dev/kgateway/v2\s+([^\s]+)\s*$`)
	m := re.FindStringSubmatch(string(b))
	if len(m) != 2 {
		return "", fmt.Errorf("module github.com/kgateway-dev/kgateway/v2 not found in %s", goModPath)
	}

	modVer := m[1]

	// Trim Go pseudo-version suffix: .<timestamp>-<sha>
	modVer = regexp.MustCompile(`\.\d{14}-[0-9a-f]{7,}$`).ReplaceAllString(modVer, "")

	// If version ends with ".0" and looks like a beta (e.g. v2.2.0-beta.1.0),
	// drop the ".0" because release tags are "v2.2.0-beta.1".
	modVer = regexp.MustCompile(`(v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+)\.0$`).ReplaceAllString(modVer, `$1`)

	return modVer, nil
}

func envOrDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func shellEscape(s string) string {
	// minimal safe escape for sh -c contexts
	return strings.ReplaceAll(s, `"`, `\"`)
}

func mustDockerKindSubnet(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", "kind", "-f", "{{(index .IPAM.Config 0).Subnet}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Errorf("docker network inspect kind: %w: %s", err, string(out)))
	}
	cidr := strings.TrimSpace(string(out))
	if cidr == "" {
		panic("empty subnet from docker network inspect kind")
	}
	return cidr
}

func pickLBRange(cidr string, count uint32) (net.IP, net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("only IPv4 supported, got %s", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("unexpected mask bits: %d", bits)
	}
	total := uint32(1) << uint32(32-ones)
	if total < count+10 {
		return nil, nil, fmt.Errorf("subnet too small for lb range: %s", cidr)
	}

	base := binary.BigEndian.Uint32(ipnet.IP.To4())
	// last usable: base + total - 2 (skip broadcast)
	last := base + total - 2
	first := last - count

	start := make(net.IP, 4)
	end := make(net.IP, 4)
	binary.BigEndian.PutUint32(start, first)
	binary.BigEndian.PutUint32(end, last)

	if !ipnet.Contains(start) || !ipnet.Contains(end) {
		return nil, nil, fmt.Errorf("computed range not within subnet: %s-%s not in %s", start, end, cidr)
	}
	return start, end, nil
}

func moduleRoot(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go env GOMOD: %w: %s", err, string(out))
	}
	goMod := strings.TrimSpace(string(out))
	if goMod == "" || goMod == os.DevNull {
		return "", fmt.Errorf("GOMOD not set")
	}
	return filepath.Dir(goMod), nil
}
