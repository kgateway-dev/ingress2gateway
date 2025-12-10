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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	kgw "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyServiceUpstreamBackend projects provider-specific static backend mappings
// into typed Kgateway Backend CRs and rewrites HTTPRoute backendRefs to reference
// those Backends.
//
// Semantics:
//   - One Backend CR per (namespace, svcName-service-upstream)
//   - Backend.Spec.Static.Hosts contains a single host+port
//   - HTTPRoute backendRefs for those services are rewritten to:
//     group: gateway.kgateway.dev
//     kind:  Backend
//     name:  <svc>-service-upstream
//
// Returns true if it mutated the HTTPRouteContext or produced a Backend CR.
func applyServiceUpstreamBackend(
	pol intermediate.Policy,
	ingressName string,
	httpRouteKey types.NamespacedName,
	httpRouteCtx *intermediate.HTTPRouteContext,
	backends map[types.NamespacedName]*kgw.Backend,
) {
	if len(pol.Backends) == 0 || len(pol.RuleBackendSources) == 0 {
		return
	}

	for _, idx := range pol.RuleBackendSources {
		// Validate indices
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := &httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := &rule.BackendRefs[idx.Backend]

		// Only core Services
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

		// Find provider-produced backend metadata
		be, ok := pol.Backends[backendKey]
		if !ok {
			continue
		}

		// Create or reuse typed Backend CR
		kb, exists := backends[backendKey]
		if !exists {
			kb = &kgw.Backend{
				TypeMeta: metav1.TypeMeta{
					Kind:       BackendGVK.Kind,
					APIVersion: BackendGVK.GroupVersion().String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      backendKey.Name,
					Namespace: backendKey.Namespace,
					Labels: map[string]string{
						"ingress2gateway.kubernetes.io/source-ingress": ingressName,
					},
				},
				Spec: kgw.BackendSpec{
					Type: kgw.BackendTypeStatic,
					Static: &kgw.StaticBackend{
						Hosts: []kgw.Host{
							{
								Host: be.Host,
								Port: gwv1.PortNumber(be.Port),
							},
						},
					},
				},
			}
			backends[backendKey] = kb
		}

		// Rewrite BackendRef to point to this Backend
		group := gwv1.Group(BackendGVK.Group)
		kind := gwv1.Kind(BackendGVK.Kind)

		br.BackendRef.Group = &group
		br.BackendRef.Kind = &kind
		br.BackendRef.Name = gwv1.ObjectName(backendKey.Name)
		br.BackendRef.Port = nil // backend controls port
	}
}
