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
	"testing"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestApplyAuthToEmitterIR_ProjectsExtAuth(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		authURLAnnotation:             "http://auth.default.svc.cluster.local",
		authResponseHeadersAnnotation: "X-Auth-Token, X-User-ID",
	}
	pIR, eIR := setupAuthTest(key, "ing-auth", annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyAuthToEmitterIR(pIR, &eIR)

	policy := eIR.HTTPRoutes[key].PoliciesBySourceIngressName["ing-auth"]
	if policy.ExtAuth == nil {
		t.Fatalf("expected ext auth policy to be projected")
	}
	if got, want := policy.ExtAuth.AuthURL, annotations[authURLAnnotation]; got != want {
		t.Fatalf("expected auth URL %q, got %q", want, got)
	}
	if len(policy.ExtAuth.ResponseHeaders) != 2 {
		t.Fatalf("expected 2 auth response headers, got %d", len(policy.ExtAuth.ResponseHeaders))
	}
	if len(policy.RuleBackendSources) != 1 || policy.RuleBackendSources[0] != (emitterir.PolicyIndex{Rule: 0, Backend: 0}) {
		t.Fatalf("expected full backend coverage for ext auth, got %#v", policy.RuleBackendSources)
	}
}

func TestApplyAuthToEmitterIR_ProjectsBasicAuth(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		authTypeAnnotation:   "basic",
		authSecretAnnotation: "default/basic-auth-secret",
	}
	pIR, eIR := setupAuthTest(key, "ing-basic", annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyAuthToEmitterIR(pIR, &eIR)

	policy := eIR.HTTPRoutes[key].PoliciesBySourceIngressName["ing-basic"]
	if policy.BasicAuth == nil {
		t.Fatalf("expected basic auth policy to be projected")
	}
	if got, want := policy.BasicAuth.SecretName, "basic-auth-secret"; got != want {
		t.Fatalf("expected secret name %q, got %q", want, got)
	}
	if got, want := policy.BasicAuth.AuthType, "auth-file"; got != want {
		t.Fatalf("expected auth type %q, got %q", want, got)
	}
	if len(policy.RuleBackendSources) != 1 || policy.RuleBackendSources[0] != (emitterir.PolicyIndex{Rule: 0, Backend: 0}) {
		t.Fatalf("expected full backend coverage for basic auth, got %#v", policy.RuleBackendSources)
	}
}

func setupAuthTest(
	httpRouteKey types.NamespacedName,
	ingressName string,
	annotations map[string]string,
) (providerir.ProviderIR, emitterir.EmitterIR) {
	ing := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   httpRouteKey.Namespace,
			Name:        ingressName,
			Annotations: annotations,
		},
	}

	route := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: httpRouteKey.Namespace,
			Name:      httpRouteKey.Name,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: "app",
							Port: func() *gatewayv1.PortNumber {
								port := gatewayv1.PortNumber(80)
								return &port
							}(),
						},
					},
				}},
			}},
		},
	}

	pIR := providerir.ProviderIR{
		HTTPRoutes: map[types.NamespacedName]providerir.HTTPRouteContext{
			httpRouteKey: {
				HTTPRoute: route,
				RuleBackendSources: [][]providerir.BackendSource{{
					{Ingress: &ing},
				}},
			},
		},
	}
	eIR := emitterir.EmitterIR{
		HTTPRoutes: map[types.NamespacedName]emitterir.HTTPRouteContext{
			httpRouteKey: {HTTPRoute: route},
		},
	}

	return pIR, eIR
}
