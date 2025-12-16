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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// Shared test client + backend echo server (kept across subtests).
	applyCurlClient(ctx)
	applyEchoBackend(ctx)

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

				if h, _ := firstIngressHost(ing); h != "" {
					hostHeader = h
				}
			}
			if hostHeader == "" {
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
