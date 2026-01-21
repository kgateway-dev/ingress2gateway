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

package common

import (
	"context"
	"log"
	"os"

	testutils "github.com/kgateway-dev/ingress2gateway/test/e2e/utils"
)

// PrereqConfig captures versioned dependencies that both emitter suites install.
type PrereqConfig struct {
	MetalLBVersion      string
	GatewayAPIVersion   string
	IngressNginxVersion string
}

// MustHaveE2EBinaries validates the external tools needed by both suites.
func MustHaveE2EBinaries() {
	testutils.MustHaveBin("docker")
	testutils.MustHaveBin("kind")
	testutils.MustHaveBin("kubectl")
	testutils.MustHaveBin("helm")
	testutils.MustHaveBin("go")
	testutils.MustHaveBin("openssl")
}

// EnsureKindCluster ensures a kind cluster exists (reuse if present, otherwise create).
func EnsureKindCluster(ctx context.Context, kindClusterName string) {
	// If the cluster exists, reuse it. Otherwise, create a new one.
	if testutils.KindClusterExists(ctx, kindClusterName) {
		log.Printf("Reusing existing kind cluster %q", kindClusterName)
		return
	}

	createArgs := []string{"create", "cluster", "--name", kindClusterName, "--wait", "3m"}
	if img := os.Getenv("KIND_NODE_IMAGE"); img != "" {
		createArgs = append(createArgs, "--image", img)
	}
	testutils.MustRun(ctx, "kind", createArgs...)
}

// ExportKubeconfig ensures kubectl uses the right context for the cluster.
func ExportKubeconfig(ctx context.Context, kindClusterName string) {
	testutils.MustRun(ctx, "kind", "export", "kubeconfig", "--name", kindClusterName)
}

// InstallPrereqs installs common, non-implementation-specific components.
func InstallPrereqs(ctx context.Context, kubeContext string, cfg PrereqConfig) {
	// MetalLB so LoadBalancer services get external IPs in kind.
	testutils.InstallMetalLB(ctx, kubeContext, cfg.MetalLBVersion)

	// Gateway API CRDs (experimental install includes standard  experimental types).
	testutils.InstallGatewayAPICRDs(ctx, kubeContext, cfg.GatewayAPIVersion)

	// Install ingress-nginx (from the provided manifest URL, with version variable).
	testutils.InstallIngressNginx(ctx, kubeContext, cfg.IngressNginxVersion)
}

// InstallSharedBackends installs the common test backends used by both suites.
func InstallSharedBackends(ctx context.Context, kubeContext string, echoImage string) {
	// Shared backend echo server (kept across subtests).
	// HTTP requests are made directly from test code using Gateway API conformance utilities.
	testutils.ApplyEchoBackend(ctx, kubeContext, echoImage)

	// TLS-enabled backend for SSL passthrough tests.
	testutils.ApplyTLSBackend(ctx, kubeContext, echoImage)

	// External auth service for external auth tests.
	testutils.ApplyExternalAuthService(ctx, kubeContext)

	// Create file-based secret for basic auth tests.
	testutils.CreateBasicAuthFileSecret(ctx, kubeContext, "basic-auth")
}

// CleanupKindCluster deletes the kind cluster unless KEEP_KIND_CLUSTER=true.
func CleanupKindCluster(ctx context.Context, kindClusterName string, keepCluster bool) {
	if keepCluster {
		log.Printf("KEEP_KIND_CLUSTER=true; leaving kind cluster %q running", kindClusterName)
		return
	}
	_ = testutils.Run(ctx, "kind", "delete", "cluster", "--name", kindClusterName)
}
