/*
Copyright The Kubernetes Authors.

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
	"strings"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func sessionAffinityFeature(notify notifications.NotifyFunc, _ []networkingv1.Ingress, _ map[types.NamespacedName]map[string]int32, ir *providerir.ProviderIR) field.ErrorList {
	// Iterate over all HTTPRoutes to find backend services and apply generic SessionAffinity
	for _, httpRouteCtx := range ir.HTTPRoutes {
		for ruleIdx := range httpRouteCtx.Spec.Rules {
			if ruleIdx >= len(httpRouteCtx.RuleBackendSources) {
				continue
			}
			sources := httpRouteCtx.RuleBackendSources[ruleIdx]
			if len(sources) == 0 {
				continue
			}

			// We need to find the backend service for this rule to attach the policy.
			// Currently, we just look at the BackendRefs.
			// Note: This logic assumes we can map back to the service.
			// Ingress-Nginx usually maps path -> backend service.
			// We check the Ingress sources for the annotation.

			var affinityType string
			var cookieTTL *int64
			var sourceIngress *networkingv1.Ingress

			for _, source := range sources {
				if val, ok := source.Ingress.Annotations[AffinityAnnotation]; ok && val == "cookie" {
					affinityType = "Cookie"
					sourceIngress = source.Ingress

					// Check for Max Age (Expires)
					if ttlVal, ok := source.Ingress.Annotations[SessionCookieExpiresAnnotation]; ok {
						if ttl, err := strconv.ParseInt(ttlVal, 10, 64); err == nil {
							cookieTTL = &ttl
						}
					}

					break
				}
			}

			if affinityType == "" {
				continue
			}

			// Build metadata following the same pattern as IPRangeControl:
			// source is namespace/name, paths list all parsed annotations.
			source := fmt.Sprintf("%s/%s", sourceIngress.Namespace, sourceIngress.Name)
			message := "Session affinity is not supported"
			paths := []*field.Path{
				field.NewPath(sourceIngress.Namespace, sourceIngress.Name, "metadata", "annotations", fmt.Sprintf("%q", AffinityAnnotation)),
			}
			if cookieTTL != nil {
				paths = append(paths, field.NewPath(sourceIngress.Namespace, sourceIngress.Name, "metadata", "annotations", fmt.Sprintf("%q", SessionCookieExpiresAnnotation)))
			}
			metadata := emitterir.NewExtensionFeatureMetadata(source, paths, message)

			// Apply to all backend refs in this rule?
			// Session Affinity is per Backend Service.
			// We need to update the ServiceIR for the referenced services.

			for _, backendRef := range httpRouteCtx.Spec.Rules[ruleIdx].BackendRefs {
				refName := string(backendRef.Name)

				svcKey := types.NamespacedName{
					Namespace: httpRouteCtx.HTTPRoute.Namespace, // assumption: same namespace
					Name:      refName,
				}

				if svc, ok := ir.Services[svcKey]; ok {
					if svc.SessionAffinity == nil {
						svc.SessionAffinity = &emitterir.SessionAffinity{}
					}

					svc.SessionAffinity.Type = affinityType
					svc.SessionAffinity.CookieTTLSec = cookieTTL
					svc.SessionAffinity.Metadata = metadata

					// Update the map
					ir.Services[svcKey] = svc
				} else {
					// Service doesn't exist yet, create it
					svc = providerir.ProviderSpecificServiceIR{
						SessionAffinity: &emitterir.SessionAffinity{
							Metadata:     metadata,
							Type:         affinityType,
							CookieTTLSec: cookieTTL,
						},
					}
					ir.Services[svcKey] = svc
				}
			}
		}
	}
	return nil
}

// applySessionAffinityToEmitterIR projects ingress-nginx cookie affinity annotations into
// emitter-neutral per-route policy intent for emitters like kgateway.
func (p *Provider) applySessionAffinityToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
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

			sources := pRouteCtx.RuleBackendSources[ruleIdx]
			rule := eRouteCtx.Spec.Rules[ruleIdx]

			for backendIdx := range rule.BackendRefs {
				if backendIdx >= len(sources) {
					continue
				}

				source := sources[backendIdx]
				if source.Ingress == nil {
					continue
				}

				sessionAffinity, parsedAnnotations := parseIngressNginxSessionAffinity(source.Ingress)
				if sessionAffinity == nil {
					continue
				}

				if eRouteCtx.PoliciesBySourceIngressName == nil {
					eRouteCtx.PoliciesBySourceIngressName = make(map[string]emitterir.Policy)
				}

				ingressName := source.Ingress.Name
				policy := eRouteCtx.PoliciesBySourceIngressName[ingressName]
				policy.SessionAffinity = sessionAffinity
				policy = policy.AddRuleBackendSources([]emitterir.PolicyIndex{{
					Rule:    ruleIdx,
					Backend: backendIdx,
				}})
				eRouteCtx.PoliciesBySourceIngressName[ingressName] = policy

				_ = parsedAnnotations
			}
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}

func parseIngressNginxSessionAffinity(ing *networkingv1.Ingress) (*emitterir.SessionAffinityPolicy, []string) {
	if ing == nil {
		return nil, nil
	}
	if !strings.EqualFold(strings.TrimSpace(ing.Annotations[AffinityAnnotation]), "cookie") {
		return nil, nil
	}

	parsedAnnotations := []string{AffinityAnnotation}
	policy := &emitterir.SessionAffinityPolicy{
		CookieName: "INGRESSCOOKIE",
	}

	if v := strings.TrimSpace(ing.Annotations[SessionCookieNameAnnotation]); v != "" {
		policy.CookieName = v
		parsedAnnotations = append(parsedAnnotations, SessionCookieNameAnnotation)
	}
	if v := strings.TrimSpace(ing.Annotations[SessionCookiePathAnnotation]); v != "" {
		policy.CookiePath = v
		parsedAnnotations = append(parsedAnnotations, SessionCookiePathAnnotation)
	}
	if v := strings.TrimSpace(ing.Annotations[SessionCookieDomainAnnotation]); v != "" {
		policy.CookieDomain = v
		parsedAnnotations = append(parsedAnnotations, SessionCookieDomainAnnotation)
	}
	if v := strings.TrimSpace(ing.Annotations[SessionCookieSameSiteAnnotation]); v != "" {
		policy.CookieSameSite = v
		parsedAnnotations = append(parsedAnnotations, SessionCookieSameSiteAnnotation)
	}
	if v := strings.TrimSpace(ing.Annotations[SessionCookieSecureAnnotation]); v != "" {
		if secure, err := strconv.ParseBool(v); err == nil {
			policy.CookieSecure = &secure
			parsedAnnotations = append(parsedAnnotations, SessionCookieSecureAnnotation)
		}
	}

	ttlRaw := strings.TrimSpace(ing.Annotations[SessionCookieMaxAgeAnnotation])
	ttlAnnotation := SessionCookieMaxAgeAnnotation
	if ttlRaw == "" {
		ttlRaw = strings.TrimSpace(ing.Annotations[SessionCookieExpiresAnnotation])
		ttlAnnotation = SessionCookieExpiresAnnotation
	}
	if ttlRaw != "" {
		if ttl, err := strconv.ParseInt(ttlRaw, 10, 64); err == nil {
			policy.CookieExpires = &ttl
			parsedAnnotations = append(parsedAnnotations, ttlAnnotation)
		}
	}

	return policy, parsedAnnotations
}
