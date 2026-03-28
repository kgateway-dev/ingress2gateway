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

package ingressnginx

import (
	"fmt"
	"strings"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func serviceUpstreamFeature(
	_ notifications.NotifyFunc,
	_ []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	_ *providerir.ProviderIR,
) field.ErrorList {
	return nil
}

// applyServiceUpstreamToEmitterIR projects service-upstream backend metadata into
// emitter-neutral per-route policy state so custom emitters can materialize
// backend CRs and rewrite covered HTTPRoute backendRefs.
func (p *Provider) applyServiceUpstreamToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
	for key, pRouteCtx := range pIR.HTTPRoutes {
		eRouteCtx, ok := eIR.HTTPRoutes[key]
		if !ok {
			continue
		}

		for ruleIdx := range eRouteCtx.Spec.Rules {
			if ruleIdx >= len(pRouteCtx.RuleBackendSources) || ruleIdx >= len(eRouteCtx.Spec.Rules) {
				continue
			}

			sources := pRouteCtx.RuleBackendSources[ruleIdx]
			rule := eRouteCtx.Spec.Rules[ruleIdx]
			for backendIdx := range rule.BackendRefs {
				if backendIdx >= len(sources) {
					continue
				}

				source := sources[backendIdx]
				if !serviceUpstreamEnabled(source.Ingress) {
					continue
				}

				backendRef := rule.BackendRefs[backendIdx].BackendRef
				if backendRef.Group != nil && *backendRef.Group != "" {
					continue
				}
				if backendRef.Kind != nil && *backendRef.Kind != "Service" {
					continue
				}
				if backendRef.Name == "" || backendRef.Port == nil {
					continue
				}

				if eRouteCtx.PoliciesBySourceIngressName == nil {
					eRouteCtx.PoliciesBySourceIngressName = make(map[string]emitterir.Policy)
				}

				ingressName := source.Ingress.Name
				policy := eRouteCtx.PoliciesBySourceIngressName[ingressName]
				if policy.Backends == nil {
					policy.Backends = make(map[types.NamespacedName]emitterir.Backend)
				}

				backendKey := types.NamespacedName{
					Namespace: key.Namespace,
					Name:      string(backendRef.Name) + "-service-upstream",
				}
				backend := policy.Backends[backendKey]
				backend.Namespace = backendKey.Namespace
				backend.Name = backendKey.Name
				backend.Host = fmt.Sprintf("%s.%s.svc.cluster.local", backendRef.Name, key.Namespace)
				backend.Port = int32(*backendRef.Port)
				policy.Backends[backendKey] = backend

				policy = policy.AddRuleBackendSources([]emitterir.PolicyIndex{{
					Rule:    ruleIdx,
					Backend: backendIdx,
				}})
				eRouteCtx.PoliciesBySourceIngressName[ingressName] = policy
			}
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func serviceUpstreamEnabled(ing *networkingv1.Ingress) bool {
	if ing == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(ing.Annotations[ServiceUpstreamAnnotation]), "true")
}
