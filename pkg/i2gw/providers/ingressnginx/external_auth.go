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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	authURLAnnotation             = "nginx.ingress.kubernetes.io/auth-url"
	authResponseHeadersAnnotation = "nginx.ingress.kubernetes.io/auth-response-headers"
	authTypeAnnotation            = "nginx.ingress.kubernetes.io/auth-type"
	authSecretAnnotation          = "nginx.ingress.kubernetes.io/auth-secret"
	authSecretTypeAnnotation      = "nginx.ingress.kubernetes.io/auth-secret-type"
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

// applyAuthToEmitterIR keeps auth annotation parsing aligned with the newer ingress-nginx
// EmitterIR bridge helpers. The legacy provider-specific auth policy wiring no longer matches
// the current refactor, so until dedicated EmitterIR auth fields are added we surface a warning
// once per source Ingress instead of leaving broken dead code in place.
func (p *Provider) applyAuthToEmitterIR(pIR providerir.ProviderIR, eIR *emitterir.EmitterIR) {
	warnedIngresses := make(map[types.NamespacedName]struct{})

	for key, pRouteCtx := range pIR.HTTPRoutes {
		if _, ok := eIR.HTTPRoutes[key]; !ok {
			continue
		}

		for ruleIdx := range pRouteCtx.HTTPRoute.Spec.Rules {
			if ruleIdx >= len(pRouteCtx.RuleBackendSources) {
				continue
			}

			ing := getNonCanaryIngress(pRouteCtx.RuleBackendSources[ruleIdx])
			if ing == nil {
				continue
			}

			if parseExtAuthConfig(ing) == nil && parseBasicAuthConfig(ing) == nil {
				continue
			}

			ingKey := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}
			if _, warned := warnedIngresses[ingKey]; warned {
				continue
			}

			p.notify(
				notifications.WarningNotification,
				"Ingress-NGINX auth annotations were detected, but the refactored EmitterIR bridge does not yet project external-auth/basic-auth configuration. Please verify the generated output manually.",
				ing,
			)
			warnedIngresses[ingKey] = struct{}{}
		}
	}
}
