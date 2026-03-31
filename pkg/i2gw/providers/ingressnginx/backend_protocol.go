/*
Copyright 2025 The Kubernetes Authors.

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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// createBackendTLSPolicies inspects ingresses for backend-protocol annotations
// and creates BackendTLSPolicies if HTTPS or GRPCS is specified.
func createBackendTLSPolicies(_ notifications.NotifyFunc, ingresses []networkingv1.Ingress, servicePorts map[types.NamespacedName]map[string]int32, _ *providerir.ProviderIR) field.ErrorList {
	ruleGroups := common.GetRuleGroups(ingresses)
	var errList field.ErrorList

	for _, rg := range ruleGroups {
		// Determine protocol for this rule group (host).
		var protocolType string

		for _, rule := range rg.Rules {
			if val, ok := rule.Ingress.Annotations[BackendProtocolAnnotation]; ok {
				if val != "" {
					protocolType = strings.ToUpper(val)
					break
				}
			}
		}

		// Handle HTTPS and GRPCS (TLS Policy)
		if protocolType == "HTTPS" || protocolType == "GRPCS" {
			// We iterate the Rules in the Group to find backends
			for _, rule := range rg.Rules {
				for _, path := range rule.IngressRule.HTTP.Paths {
					backendRef, err := common.ToBackendRef(rg.Namespace, path.Backend, servicePorts, field.NewPath("backend"))
					if err != nil {
						errList = append(errList, err)
						continue
					}
					serviceName := string(backendRef.Name)
					if serviceName == "" {
						continue
					}
				}
			}
		}
	}
	return errList
}

// applyBackendProtocolToEmitterIR projects ingress-nginx backend-protocol intent into
// the emitter-neutral policy map used by custom emitters like kgateway and agentgateway.
//
// We intentionally keep GRPC upstreams as HTTPRoutes and let emitters decide how to
// project the upstream protocol. When service-upstream is also enabled, we populate
// per-backend host/port metadata so emitters can generate implementation-specific
// Backend resources and rewrite backendRefs.
func (p *Provider) applyBackendProtocolToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
	for key, pRouteCtx := range pIR.HTTPRoutes {
		eRouteCtx, ok := eIR.HTTPRoutes[key]
		if !ok {
			continue
		}

		for ruleIdx := range eRouteCtx.Spec.Rules {
			if ruleIdx >= len(pRouteCtx.RuleBackendSources) {
				continue
			}
			if ruleIdx >= len(eRouteCtx.Spec.Rules) {
				continue
			}

			rule := eRouteCtx.Spec.Rules[ruleIdx]
			sources := pRouteCtx.RuleBackendSources[ruleIdx]

			for backendIdx := range rule.BackendRefs {
				if backendIdx >= len(sources) {
					continue
				}
				source := sources[backendIdx]
				if source.Ingress == nil {
					continue
				}

				rawProtocol, ok := source.Ingress.Annotations[BackendProtocolAnnotation]
				if !ok {
					continue
				}

				protocol, supported := parseBackendProtocol(strings.TrimSpace(rawProtocol))
				if !supported {
					continue
				}

				if eRouteCtx.PoliciesBySourceIngressName == nil {
					eRouteCtx.PoliciesBySourceIngressName = make(map[string]emitterir.Policy)
				}

				ingressName := source.Ingress.Name
				policy := eRouteCtx.PoliciesBySourceIngressName[ingressName]
				policy.BackendProtocol = protocol
				policy = policy.AddRuleBackendSources([]emitterir.PolicyIndex{{
					Rule:    ruleIdx,
					Backend: backendIdx,
				}})

				if serviceUpstreamEnabled(source.Ingress) {
					backendRef := rule.BackendRefs[backendIdx].BackendRef
					if backendRef.Name != "" && backendRef.Port != nil {
						if policy.Backends == nil {
							policy.Backends = make(map[types.NamespacedName]emitterir.Backend)
						}

						svcName := string(backendRef.Name)
						backendKey := types.NamespacedName{
							Namespace: key.Namespace,
							Name:      svcName + "-service-upstream",
						}
						policy.Backends[backendKey] = emitterir.Backend{
							Namespace: key.Namespace,
							Name:      backendKey.Name,
							Host:      fmt.Sprintf("%s.%s.svc.cluster.local", svcName, key.Namespace),
							Port:      int32(*backendRef.Port),
							Protocol:  protocol,
						}
					}
				}

				eRouteCtx.PoliciesBySourceIngressName[ingressName] = policy
			}
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func parseBackendProtocol(raw string) (*emitterir.BackendProtocol, bool) {
	switch strings.ToUpper(raw) {
	case string(emitterir.BackendProtocolGRPC):
		protocol := emitterir.BackendProtocolGRPC
		return &protocol, true
	default:
		return nil, false
	}
}
