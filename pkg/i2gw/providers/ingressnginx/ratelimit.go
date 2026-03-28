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
	"strconv"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// applyRateLimitToEmitterIR reads ingress-nginx rate limit annotations from ProviderIR sources and stores
// provider-neutral rate limit intent into EmitterIR, which will later be converted by each custom emitter.
//
// Currently supported annotations are:
// - nginx.ingress.kubernetes.io/limit-rps
// - nginx.ingress.kubernetes.io/limit-rpm
// - nginx.ingress.kubernetes.io/limit-burst-multiplier
func (p *Provider) applyRateLimitToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
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

			limitPolicy, parsedAnnotations := p.parseIngressNginxRateLimit(ing)
			if limitPolicy == nil {
				continue
			}

			if eRouteCtx.RateLimitByRuleIdx == nil {
				eRouteCtx.RateLimitByRuleIdx = make(map[int]*emitterir.RateLimitPolicy)
			}

			source := fmt.Sprintf("%s/%s", ing.Namespace, ing.Name)
			message := "Rate limiting usually requires implementation-specific policy configuration"
			paths := make([]*field.Path, len(parsedAnnotations))
			for i, ann := range parsedAnnotations {
				paths[i] = field.NewPath(ing.Namespace, ing.Name, "metadata", "annotations", fmt.Sprintf("%q", ann))
			}
			limitPolicy.Metadata = emitterir.NewExtensionFeatureMetadata(
				source,
				paths,
				message,
			)

			eRouteCtx.RateLimitByRuleIdx[ruleIdx] = limitPolicy
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func (p *Provider) parseIngressNginxRateLimit(ing *networkingv1.Ingress) (*emitterir.RateLimitPolicy, []string) {
	var (
		limit             int32
		unit              emitterir.RateLimitUnit
		hasLimit          bool
		burstMultiplier   int32 = 1
		parsedAnnotations       = make([]string, 0, 2)
	)

	if val, ok := ing.Annotations[LimitRPSAnnotation]; ok && val != "" {
		parsedAnnotations = append(parsedAnnotations, LimitRPSAnnotation)
		parsed, err := strconv.Atoi(val)
		if err != nil || parsed <= 0 {
			p.notify(
				notifications.WarningNotification,
				fmt.Sprintf("Invalid limit-rps annotation %q: must be a positive integer, skipping rate limit", val),
				ing,
			)
			return nil, nil
		}
		limit = int32(parsed)
		unit = emitterir.RateLimitUnitRPS
		hasLimit = true
	}

	if !hasLimit {
		if val, ok := ing.Annotations[LimitRPMAnnotation]; ok && val != "" {
			parsedAnnotations = append(parsedAnnotations, LimitRPMAnnotation)
			parsed, err := strconv.Atoi(val)
			if err != nil || parsed <= 0 {
				p.notify(
					notifications.WarningNotification,
					fmt.Sprintf("Invalid limit-rpm annotation %q: must be a positive integer, skipping rate limit", val),
					ing,
				)
				return nil, nil
			}
			limit = int32(parsed)
			unit = emitterir.RateLimitUnitRPM
			hasLimit = true
		}
	}

	if !hasLimit {
		return nil, nil
	}

	if val, ok := ing.Annotations[LimitBurstMultiplierAnnotation]; ok && val != "" {
		parsedAnnotations = append(parsedAnnotations, LimitBurstMultiplierAnnotation)
		parsed, err := strconv.Atoi(val)
		if err != nil || parsed <= 0 {
			p.notify(
				notifications.WarningNotification,
				fmt.Sprintf("Invalid limit-burst-multiplier annotation %q: must be a positive integer, using default burst multiplier 1", val),
				ing,
			)
		} else {
			burstMultiplier = int32(parsed)
		}
	}

	return &emitterir.RateLimitPolicy{
		Limit:           limit,
		Unit:            unit,
		BurstMultiplier: burstMultiplier,
	}, parsedAnnotations
}
