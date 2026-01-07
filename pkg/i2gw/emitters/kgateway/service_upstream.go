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
	kgtwir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate/kgateway"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyServiceUpstream projects provider-specific static backend mappings into typed
// Kgateway Backend CRs and rewrites HTTPRoute backendRefs to reference those Backends.
//
// Semantics:
//   - One Backend CR per (namespace, svcName-service-upstream).
//   - Backend.Spec.Static.Hosts contains a single host+port from the IR Backend.
//   - HTTPRoute backendRefs for those services are rewritten to:
//     group: gateway.kgateway.dev
//     kind:  Backend
//     name:  <svc>-service-upstream
//
// This function is driven by the IR Policy.Backends and RuleBackendSources
// populated by the ingress-nginx provider (service-upstream feature).
func applyServiceUpstream(
	pol kgtwir.Policy,
	ingressName string,
	httpRouteKey types.NamespacedName,
	httpRouteCtx *emitterir.HTTPRouteContext,
	backends map[types.NamespacedName]*kgateway.Backend,
) {
	if len(pol.Backends) == 0 || len(pol.RuleBackendSources) == 0 {
		return
	}

	for _, idx := range pol.RuleBackendSources {
		// Validate indices.
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := &httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := &rule.BackendRefs[idx.Backend]

		// Only core Services.
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

		backendName := svcName + "-service-upstream"
		backendKey := types.NamespacedName{
			Namespace: httpRouteKey.Namespace,
			Name:      backendName,
		}

		// Find provider-produced backend metadata (host/port).
		be, ok := pol.Backends[backendKey]
		if !ok {
			continue
		}

		// service-upstream IR Backends don't currently carry protocol; backend-protocol
		// is stored on the Policy. Prefer the per-backend protocol if present, otherwise
		// fall back to the Policy-level protocol.
		proto := be.Protocol
		if proto == nil {
			proto = pol.BackendProtocol
		}

		// Ensure a Kgateway Backend exists with the correct host/port.
		kb := ensureStaticBackendForService(
			ingressName,
			httpRouteKey,
			svcName,
			be.Host,
			be.Port,
			proto,
			backends,
		)

		// Rewrite BackendRef to point to this Backend.
		group := gatewayv1.Group(BackendGVK.Group)
		kind := gatewayv1.Kind(BackendGVK.Kind)

		br.BackendRef.Group = &group
		br.BackendRef.Kind = &kind
		br.BackendRef.Name = gatewayv1.ObjectName(kb.Name)
		// When using a static Backend, the Backend controls the port.
		br.BackendRef.Port = nil
	}
}
