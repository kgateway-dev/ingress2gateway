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

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// applyLoadBalancingToEmitterIR reads ingress-nginx load balancing annotations from ProviderIR sources and stores
// provider-neutral load balancing intent into EmitterIR, which will later be converted by each custom emitter.
//
// Currently supported annotations are:
// - nginx.ingress.kubernetes.io/load-balance
func (p *Provider) applyLoadBalancingToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
	for key, pRouteCtx := range pIR.HTTPRoutes {
		eRouteCtx, ok := eIR.HTTPRoutes[key]
		if !ok {
			continue
		}

		for ruleIdx := range eRouteCtx.Spec.Rules {
			if ruleIdx >= len(pRouteCtx.RuleBackendSources) {
				continue
			}
			ing := getNonCanaryIngress(pRouteCtx.RuleBackendSources[ruleIdx])
			if ing == nil {
				continue
			}

			loadBalancing, parsedAnnotations := p.parseIngressNginxLoadBalancing(ing)
			if loadBalancing == nil {
				continue
			}

			if eRouteCtx.LoadBalancingByRuleIdx == nil {
				eRouteCtx.LoadBalancingByRuleIdx = make(map[int]*emitterir.BackendLoadBalancingPolicy)
			}

			source := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)
			message := "Load balancing behavior is implementation-specific and may require provider-specific configuration"
			paths := make([]*field.Path, len(parsedAnnotations))
			for i, ann := range parsedAnnotations {
				paths[i] = field.NewPath(ing.Namespace, ing.Name, "metadata", "annotations", fmt.Sprintf("%q", ann))
			}
			loadBalancing.Metadata = emitterir.NewExtensionFeatureMetadata(
				source,
				paths,
				message,
			)

			eRouteCtx.LoadBalancingByRuleIdx[ruleIdx] = loadBalancing
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func (p *Provider) parseIngressNginxLoadBalancing(ing *networkingv1.Ingress) (*emitterir.BackendLoadBalancingPolicy, []string) {
	if ing.Annotations == nil {
		return nil, nil
	}

	raw, ok := ing.Annotations[LoadBalanceAnnotation]
	if !ok {
		return nil, nil
	}

	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return nil, nil
	}

	switch value {
	case string(emitterir.LoadBalancingStrategyRoundRobin):
		return &emitterir.BackendLoadBalancingPolicy{
			Strategy: emitterir.LoadBalancingStrategyRoundRobin,
		}, []string{LoadBalanceAnnotation}
	default:
		p.notify(
			notifications.WarningNotification,
			fmt.Sprintf(`Unsupported load-balance annotation %q: only "round_robin" is supported, skipping load balancing`, raw),
			ing,
		)
		return nil, nil
	}
}
