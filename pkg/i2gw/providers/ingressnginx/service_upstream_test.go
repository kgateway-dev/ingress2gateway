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
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestApplyServiceUpstreamToEmitterIR(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}

	serviceUpstreamIngress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-service-upstream",
			Namespace: key.Namespace,
			Annotations: map[string]string{
				ServiceUpstreamAnnotation: "true",
			},
		},
	}
	plainIngress := networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ing-plain",
			Namespace: key.Namespace,
		},
	}

	serviceKind := gatewayv1.Kind("Service")
	route := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("myservice"),
									Kind: &serviceKind,
									Port: portPtr(80),
								},
							},
						},
					},
				},
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: gatewayv1.ObjectName("myservice"),
									Kind: &serviceKind,
									Port: portPtr(80),
								},
							},
						},
					},
				},
			},
		},
	}

	pIR := providerir.ProviderIR{
		HTTPRoutes: map[types.NamespacedName]providerir.HTTPRouteContext{
			key: {
				HTTPRoute: route,
				RuleBackendSources: [][]providerir.BackendSource{
					{{Ingress: &serviceUpstreamIngress}},
					{{Ingress: &plainIngress}},
				},
			},
		},
	}
	eIR := emitterir.EmitterIR{
		HTTPRoutes: map[types.NamespacedName]emitterir.HTTPRouteContext{
			key: {HTTPRoute: route},
		},
	}

	(&Provider{}).applyServiceUpstreamToEmitterIR(pIR, &eIR)

	policy, ok := eIR.HTTPRoutes[key].PoliciesBySourceIngressName[serviceUpstreamIngress.Name]
	if !ok {
		t.Fatalf("expected service-upstream policy for ingress %q", serviceUpstreamIngress.Name)
	}
	if len(policy.RuleBackendSources) != 1 || policy.RuleBackendSources[0] != (emitterir.PolicyIndex{Rule: 0, Backend: 0}) {
		t.Fatalf("expected only rule 0/backend 0 coverage, got %#v", policy.RuleBackendSources)
	}

	backendKey := types.NamespacedName{
		Namespace: key.Namespace,
		Name:      "myservice-service-upstream",
	}
	backend, ok := policy.Backends[backendKey]
	if !ok {
		t.Fatalf("expected backend %v to be projected", backendKey)
	}
	if backend.Host != "myservice.default.svc.cluster.local" {
		t.Fatalf("expected host %q, got %q", "myservice.default.svc.cluster.local", backend.Host)
	}
	if backend.Port != 80 {
		t.Fatalf("expected port 80, got %d", backend.Port)
	}

	if _, ok := eIR.HTTPRoutes[key].PoliciesBySourceIngressName[plainIngress.Name]; ok {
		t.Fatalf("did not expect policy for ingress without service-upstream annotation")
	}
}

func portPtr(p gatewayv1.PortNumber) *gatewayv1.PortNumber {
	return &p
}
