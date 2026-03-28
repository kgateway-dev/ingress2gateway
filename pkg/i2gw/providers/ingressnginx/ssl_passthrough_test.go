/*
Copyright 2026 The Kubernetes Authors.

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

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestConvert_WiresSSLPassthroughFeature(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tls-passthrough",
			Namespace: "default",
			Annotations: map[string]string{
				SSLPassthroughAnnotation: "true",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptrTo("nginx"),
			Rules: []networkingv1.IngressRule{{
				Host: "nginx.example.com",
				IngressRuleValue: networkingv1.IngressRuleValue{
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []networkingv1.HTTPIngressPath{{
							Path:     "/",
							PathType: ptrTo(networkingv1.PathTypePrefix),
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: "my-nginx",
									Port: networkingv1.ServiceBackendPort{Number: 443},
								},
							},
						}},
					},
				},
			}},
		},
	}

	storage := newResourcesStorage()
	key := types.NamespacedName{Namespace: ingress.Namespace, Name: ingress.Name}
	storage.Ingresses.FromMap(map[types.NamespacedName]*networkingv1.Ingress{key: ingress})

	noopNotify := notifications.NotifyFunc(func(notifications.MessageType, string, ...client.Object) {})
	ir, errs := newResourcesToIRConverter(noopNotify).convert(noopNotify, storage)
	if len(errs) > 0 {
		t.Fatalf("convert returned errors: %v", errs)
	}

	routeKey := types.NamespacedName{Namespace: "default", Name: "tls-passthrough-nginx-example-com"}
	if _, ok := ir.HTTPRoutes[routeKey]; ok {
		t.Fatalf("expected HTTPRoute %s to be replaced by TLSRoute", routeKey)
	}

	tlsRoute, ok := ir.TLSRoutes[routeKey]
	if !ok {
		t.Fatalf("expected TLSRoute %s to be created", routeKey)
	}

	if got, want := len(tlsRoute.Spec.Rules), 1; got != want {
		t.Fatalf("expected %d TLSRoute rule, got %d", want, got)
	}
	if got, want := len(tlsRoute.Spec.Rules[0].BackendRefs), 1; got != want {
		t.Fatalf("expected %d backend ref, got %d", want, got)
	}
	if tlsRoute.Spec.Rules[0].BackendRefs[0].Port == nil || *tlsRoute.Spec.Rules[0].BackendRefs[0].Port != 443 {
		t.Fatalf("expected backend port 443, got %#v", tlsRoute.Spec.Rules[0].BackendRefs[0].Port)
	}

	gatewayKey := types.NamespacedName{Namespace: "default", Name: "nginx"}
	gatewayCtx, ok := ir.Gateways[gatewayKey]
	if !ok {
		t.Fatalf("expected Gateway %s to be present", gatewayKey)
	}
	if got, want := len(gatewayCtx.Spec.Listeners), 1; got != want {
		t.Fatalf("expected %d listener, got %d", want, got)
	}

	listener := gatewayCtx.Spec.Listeners[0]
	if got, want := listener.Name, gatewayv1.SectionName("nginx-example-com-tls-passthrough"); got != want {
		t.Fatalf("expected listener name %q, got %q", want, got)
	}
	if got, want := listener.Protocol, gatewayv1.TLSProtocolType; got != want {
		t.Fatalf("expected listener protocol %q, got %q", want, got)
	}
	if got, want := listener.Port, gatewayv1.PortNumber(443); got != want {
		t.Fatalf("expected listener port %d, got %d", want, got)
	}
	if listener.TLS == nil || listener.TLS.Mode == nil || *listener.TLS.Mode != gatewayv1.TLSModePassthrough {
		t.Fatalf("expected listener TLS mode Passthrough, got %#v", listener.TLS)
	}
	if listener.Hostname == nil || *listener.Hostname != gatewayv1.Hostname("nginx.example.com") {
		t.Fatalf("expected listener hostname nginx.example.com, got %#v", listener.Hostname)
	}

	if got, want := len(tlsRoute.Spec.ParentRefs), 1; got != want {
		t.Fatalf("expected %d parent ref, got %d", want, got)
	}
	if tlsRoute.Spec.ParentRefs[0].SectionName == nil || *tlsRoute.Spec.ParentRefs[0].SectionName != listener.Name {
		t.Fatalf("expected TLSRoute parent ref sectionName %q, got %#v", listener.Name, tlsRoute.Spec.ParentRefs[0].SectionName)
	}
}
