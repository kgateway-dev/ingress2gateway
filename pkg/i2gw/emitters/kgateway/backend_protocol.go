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
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyBackendProtocol projects backend protocol metadata on IR Backends into
// typed Kgateway Backend CRs and rewrites HTTPRoute backendRefs to reference
// those Backends.
//
// Semantics:
//   - For each Policy.Backends entry produced by the ingress-nginx provider,
//     we ensure there is a Static Backend CR with the correct host / port and
//     (if set) appProtocol (currently only gRPC).
//   - HTTPRoute backendRefs that were originally core Services and are covered
//     by this Policy are rewritten to:
//     group: gateway.kgateway.dev
//     kind:  Backend
//     name:  <svc>-service-upstream
//   - This works regardless of whether service-upstream was also used.
func applyBackendProtocol(
	pol emitterir.Policy,
	ingressName string,
	httpRouteKey types.NamespacedName,
	httpRouteCtx *emitterir.HTTPRouteContext,
	backends map[types.NamespacedName]*kgateway.Backend,
) {
	if len(pol.Backends) == 0 || len(pol.RuleBackendSources) == 0 {
		return
	}

	for _, idx := range pol.RuleBackendSources {
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := &httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := &rule.BackendRefs[idx.Backend]

		// Only core Service backends.
		if br.BackendRef.Group != nil && *br.BackendRef.Group != "" {
			continue
		}
		if br.BackendRef.Kind != nil && *br.BackendRef.Kind != "Service" {
			continue
		}
		if br.BackendRef.Name == "" {
			continue
		}

		svcName := string(br.BackendRef.Name)
		if svcName == "" {
			continue
		}

		backendKey := backendKeyForService(httpRouteKey.Namespace, svcName)

		be, ok := pol.Backends[backendKey]
		if !ok {
			// Provider did not produce metadata for this Service backend.
			continue
		}

		// Ensure / create the typed Backend CR (host, port, protocol).
		kb := ensureStaticBackendForService(
			ingressName,
			httpRouteKey,
			svcName,
			be.Host,
			be.Port,
			be.Protocol,
			backends,
		)

		// Rewrite BackendRef to point to this Backend.
		group := gatewayv1.Group(BackendGVK.Group)
		kind := gatewayv1.Kind(BackendGVK.Kind)

		br.BackendRef.Group = &group
		br.BackendRef.Kind = &kind
		br.BackendRef.Name = gatewayv1.ObjectName(kb.Name)
		// Backend controls the port.
		br.BackendRef.Port = nil
	}
}
