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

package utils

import (
	"testing"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"

	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestDedupeGatewayListenerCertificateRefs(t *testing.T) {
	gw := gatewayv1.Gateway{}
	gw.Namespace = "default"
	gw.Name = "nginx"

	hostname := gatewayv1.Hostname("redirect.example")
	gw.Spec.Listeners = []gatewayv1.Listener{
		{
			Name:     "redirect-example-https",
			Hostname: &hostname,
			Port:     443,
			Protocol: gatewayv1.HTTPSProtocolType,
			TLS: &gatewayv1.ListenerTLSConfig{
				CertificateRefs: []gatewayv1.SecretObjectReference{
					{Name: "redirect-tls"},
					{Name: "redirect-tls"}, // duplicate
				},
			},
		},
	}

	gr := i2gw.GatewayResources{
		Gateways: map[types.NamespacedName]gatewayv1.Gateway{
			{Namespace: "default", Name: "nginx"}: gw,
		},
	}

	dedupeGatewayListenerCertificateRefs(&gr)

	got := gr.Gateways[types.NamespacedName{Namespace: "default", Name: "nginx"}]
	if got.Spec.Listeners[0].TLS == nil {
		t.Fatalf("expected TLS config to be present")
	}
	if len(got.Spec.Listeners[0].TLS.CertificateRefs) != 1 {
		t.Fatalf("expected 1 certificateRef after dedupe, got %d", len(got.Spec.Listeners[0].TLS.CertificateRefs))
	}
	if string(got.Spec.Listeners[0].TLS.CertificateRefs[0].Name) != "redirect-tls" {
		t.Fatalf("expected remaining certificateRef name 'redirect-tls', got %q", got.Spec.Listeners[0].TLS.CertificateRefs[0].Name)
	}
}
