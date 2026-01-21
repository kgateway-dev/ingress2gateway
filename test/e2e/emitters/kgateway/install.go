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

	testutils "github.com/kgateway-dev/ingress2gateway/test/e2e/utils"
)

func installKgateway(ctx context.Context) {
	modVer, err := kgatewayVersionFromGoMod(ctx)
	if err != nil {
		panic(fmt.Errorf("read kgateway module version from go.mod: %w", err))
	}
	chartVer := testutils.EnvOrDefault("KGATEWAY_VERSION", modVer)
	ns := "kgateway-system"

	log.Printf("Installing kgateway chart version %s (module version: %s)", chartVer, modVer)

	testutils.MustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway-crds",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway-crds",
		"--create-namespace", "--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
	)

	testutils.MustRun(ctx, "helm",
		"--kube-context", kubeContext,
		"upgrade", "-i", "kgateway",
		"oci://cr.kgateway.dev/kgateway-dev/charts/kgateway",
		"--namespace", ns,
		"--version", chartVer,
		"--set", "controller.image.pullPolicy=Always",
		"--set", "controller.extraEnv.KGW_ENABLE_GATEWAY_API_EXPERIMENTAL_FEATURES=true",
	)

	testutils.MustKubectl(ctx, kubeContext, "-n", ns, "rollout", "status", "deploy/kgateway", "--timeout=3m")

	if _, err := testutils.Kubectl(ctx, kubeContext, "get", "gatewayclass", "kgateway"); err != nil {
		panic(fmt.Errorf("expected GatewayClass/kgateway not found: %w", err))
	}
	if _, err := testutils.Kubectl(ctx, kubeContext, "wait", "--for=condition=Accepted", "gatewayclass/kgateway", "--timeout=1m"); err != nil {
		panic(fmt.Errorf("GatewayClass/kgateway not Accepted: %w", err))
	}
}
