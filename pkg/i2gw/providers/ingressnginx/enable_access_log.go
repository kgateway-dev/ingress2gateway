/*
Copyright 2024 The Kubernetes Authors.

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
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// applyAccessLogToEmitterIR reads ingress-nginx access log annotations from ProviderIR sources and stores
// provider-neutral access log intent into EmitterIR, which will later be converted by each custom emitter.
//
// Currently supported annotations are:
// - nginx.ingress.kubernetes.io/enable-access-log
func (p *Provider) applyAccessLogToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
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

			accessLog, parsedAnnotations := p.parseIngressNginxAccessLog(ing)
			if accessLog == nil {
				continue
			}

			if eRouteCtx.EnableAccessLogByRuleIdx == nil {
				eRouteCtx.EnableAccessLogByRuleIdx = make(map[int]*emitterir.AccessLog)
			}

			source := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)
			message := "Access log configuration is implementation-specific and may not map exactly across Gateway API implementations"
			paths := make([]*field.Path, len(parsedAnnotations))
			for i, ann := range parsedAnnotations {
				paths[i] = field.NewPath(ing.Namespace, ing.Name, "metadata", "annotations", fmt.Sprintf("%q", ann))
			}
			accessLog.Metadata = emitterir.NewExtensionFeatureMetadata(
				source,
				paths,
				message,
			)

			eRouteCtx.EnableAccessLogByRuleIdx[ruleIdx] = accessLog
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func (p *Provider) parseIngressNginxAccessLog(ing *networkingv1.Ingress) (*emitterir.AccessLog, []string) {
	raw := strings.TrimSpace(ing.Annotations[EnableAccessLogAnnotation])
	if raw == "" {
		return nil, nil
	}

	// ingress-nginx defaults access logs on; only an explicit "true" should enable
	// and any other non-empty value is treated as false to preserve prior behavior.
	return &emitterir.AccessLog{
		Enabled: raw == "true",
	}, []string{EnableAccessLogAnnotation}
}
