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
	"strings"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
)

const (
	authURLAnnotation             = "nginx.ingress.kubernetes.io/auth-url"
	authResponseHeadersAnnotation = "nginx.ingress.kubernetes.io/auth-response-headers"
	authTypeAnnotation            = "nginx.ingress.kubernetes.io/auth-type"
	authSecretAnnotation          = "nginx.ingress.kubernetes.io/auth-secret"      //nolint:gosec // G101: annotation key, not a credential
	authSecretTypeAnnotation      = "nginx.ingress.kubernetes.io/auth-secret-type" //nolint:gosec // G101: annotation key, not a credential
)

type extAuthConfig struct {
	authURL         string
	responseHeaders []string
}

type basicAuthConfig struct {
	secretName string
	authType   string
}

func parseExtAuthConfig(ing *networkingv1.Ingress) *extAuthConfig {
	authURL := strings.TrimSpace(ing.Annotations[authURLAnnotation])
	responseHeaders := splitAndTrimCSV(ing.Annotations[authResponseHeadersAnnotation])
	if authURL == "" && len(responseHeaders) == 0 {
		return nil
	}
	return &extAuthConfig{
		authURL:         authURL,
		responseHeaders: responseHeaders,
	}
}

func parseBasicAuthConfig(ing *networkingv1.Ingress) *basicAuthConfig {
	authType := strings.TrimSpace(ing.Annotations[authTypeAnnotation])
	authSecret := strings.TrimSpace(ing.Annotations[authSecretAnnotation])
	if authType != "basic" || authSecret == "" {
		return nil
	}

	secretName := authSecret
	if strings.Contains(authSecret, "/") {
		parts := strings.SplitN(authSecret, "/", 2)
		if len(parts) == 2 {
			secretName = parts[1]
		}
	}

	secretType := strings.TrimSpace(ing.Annotations[authSecretTypeAnnotation])
	if secretType == "" {
		secretType = "auth-file"
	}

	return &basicAuthConfig{
		secretName: secretName,
		authType:   secretType,
	}
}

func splitAndTrimCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	rawValues := strings.Split(value, ",")
	values := make([]string, 0, len(rawValues))
	for _, rawValue := range rawValues {
		value := strings.TrimSpace(rawValue)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

// applyAuthToEmitterIR projects ingress-nginx auth annotations into the
// emitter-neutral per-ingress policy map used by custom emitters.
func (p *Provider) applyAuthToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
	for key, pRouteCtx := range pIR.HTTPRoutes {
		eRouteCtx, ok := eIR.HTTPRoutes[key]
		if !ok {
			continue
		}

		for ruleIdx := range pRouteCtx.HTTPRoute.Spec.Rules {
			if ruleIdx >= len(pRouteCtx.RuleBackendSources) {
				continue
			}
			if ruleIdx >= len(eRouteCtx.Spec.Rules) {
				continue
			}

			ing := getNonCanaryIngress(pRouteCtx.RuleBackendSources[ruleIdx])
			if ing == nil {
				continue
			}

			extAuth := parseExtAuthConfig(ing)
			basicAuth := parseBasicAuthConfig(ing)
			if extAuth == nil && basicAuth == nil {
				continue
			}

			if eRouteCtx.PoliciesBySourceIngressName == nil {
				eRouteCtx.PoliciesBySourceIngressName = make(map[string]emitterir.Policy)
			}

			policy := eRouteCtx.PoliciesBySourceIngressName[ing.Name]
			if extAuth != nil {
				policy.ExtAuth = &emitterir.ExtAuthPolicy{
					AuthURL:         extAuth.authURL,
					ResponseHeaders: append([]string(nil), extAuth.responseHeaders...),
				}
			}
			if basicAuth != nil {
				policy.BasicAuth = &emitterir.BasicAuthPolicy{
					SecretName: basicAuth.secretName,
					AuthType:   basicAuth.authType,
				}
			}

			for backendIdx := range eRouteCtx.Spec.Rules[ruleIdx].BackendRefs {
				policy = policy.AddRuleBackendSources([]emitterir.PolicyIndex{{
					Rule:    ruleIdx,
					Backend: backendIdx,
				}})
			}

			eRouteCtx.PoliciesBySourceIngressName[ing.Name] = policy
		}

		eIR.HTTPRoutes[key] = eRouteCtx
	}
}
