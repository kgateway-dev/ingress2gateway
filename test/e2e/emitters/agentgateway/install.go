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

package agentgateway

import (
	"context"
	"fmt"
	"log"

	"github.com/kgateway-dev/ingress2gateway/test/e2e/emitters/common"
	testutils "github.com/kgateway-dev/ingress2gateway/test/e2e/utils"
)

func installAgentgateway(ctx context.Context, kubeContext string) {
	modVer, err := common.KgatewayVersionFromGoMod(ctx)
	if err != nil {
		panic(fmt.Errorf("read kgateway module version from go.mod: %w", err))
	}
	chartVer := testutils.EnvOrDefault("AGENTGATEWAY_VERSION", modVer)
	ns := "agentgateway-system"

	log.Printf("Installing agentgateway chart version %s (module version: %s)", chartVer, modVer)

	testutils.MustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "agentgateway-crds",
		"oci://ghcr.io/kgateway-dev/charts/agentgateway-crds",
		"--create-namespace", "--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
	)

	testutils.MustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "agentgateway",
		"oci://ghcr.io/kgateway-dev/charts/agentgateway",
		"--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
		"--set", "controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true",
	)

	testutils.MustKubectl(ctx, kubeContext, "-n", ns, "rollout", "status", "deploy/agentgateway", "--timeout=3m")

	if _, err := testutils.Kubectl(ctx, kubeContext, "get", "gatewayclass", "agentgateway"); err != nil {
		panic(fmt.Errorf("expected GatewayClass/agentgateway not found: %w", err))
	}
	if _, err := testutils.Kubectl(ctx, kubeContext, "wait", "--for=condition=Accepted", "gatewayclass/agentgateway", "--timeout=1m"); err != nil {
		panic(fmt.Errorf("GatewayClass/agentgateway not Accepted: %w", err))
	}
}
