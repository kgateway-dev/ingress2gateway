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
	"log"
	"os/exec"
	"strings"
	"time"
)

func kindClusterExists(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "kind", "get", "clusters").CombinedOutput()
	if err != nil {
		log.Printf("WARN: kind get clusters failed (%v): %s", err, strings.TrimSpace(string(out)))
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == name {
			return true
		}
	}
	return false
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

func installMetalLB(ctx context.Context) {
	ver := envOrDefault("METALLB_VERSION", defaultMetalLBVersion)
	manifestURL := fmt.Sprintf("https://raw.githubusercontent.com/metallb/metallb/%s/config/manifests/metallb-native.yaml", ver)

	log.Printf("Installing MetalLB %s", ver)
	mustKubectl(ctx, "apply", "-f", manifestURL)

	mustKubectl(ctx, "-n", "metallb-system", "rollout", "status", "deploy/controller", "--timeout=3m")
	mustKubectl(ctx, "-n", "metallb-system", "rollout", "status", "ds/speaker", "--timeout=3m")

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

	mustKubectl(ctx, "get", "crd", "gateways.gateway.networking.k8s.io")
	mustKubectl(ctx, "get", "crd", "httproutes.gateway.networking.k8s.io")
}

func installIngressNginx(ctx context.Context) {
	ver := envOrDefault("INGRESS_NGINX_VERSION", defaultIngressNginxVersion)
	url := fmt.Sprintf("https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-%s/deploy/static/provider/cloud/deploy.yaml", ver)

	log.Printf("Installing ingress-nginx %s from %s", ver, url)
	mustKubectl(ctx, "apply", "-f", url)

	mustKubectl(ctx, "-n", "ingress-nginx", "rollout", "status", "deploy/ingress-nginx-controller", "--timeout=1m")

	if _, err := waitForServiceAddress(ctx, "ingress-nginx", "ingress-nginx-controller", 1*time.Minute); err != nil {
		panic(fmt.Errorf("ingress-nginx-controller external IP: %w", err))
	}
}

func installKgateway(ctx context.Context) {
	modVer, err := kgatewayVersionFromGoMod(ctx)
	if err != nil {
		panic(fmt.Errorf("read kgateway module version from go.mod: %w", err))
	}
	chartVer := envOrDefault("KGATEWAY_VERSION", modVer)
	ns := "kgateway-system"

	log.Printf("Installing kgateway chart version %s (module version: %s)", chartVer, modVer)

	mustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway-crds",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds",
		"--create-namespace", "--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
	)

	mustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway",
		"--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
		"--set", "controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true",
	)

	mustKubectl(ctx, "-n", ns, "rollout", "status", "deploy/kgateway", "--timeout=3m")

	if _, err := kubectl(ctx, "get", "gatewayclass", "kgateway"); err != nil {
		panic(fmt.Errorf("expected GatewayClass/kgateway not found: %w", err))
	}
	if _, err := kubectl(ctx, "wait", "--for=condition=Accepted", "gatewayclass/kgateway", "--timeout=1m"); err != nil {
		panic(fmt.Errorf("GatewayClass/kgateway not Accepted: %w", err))
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
