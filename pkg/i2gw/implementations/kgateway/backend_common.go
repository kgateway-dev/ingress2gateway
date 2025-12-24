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

package kgateway

import (
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	kgw "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// sourceIngressAnnotation is used to label Backend CRs with the source Ingress name.
const sourceIngressAnnotation = "ingress2gateway.kubernetes.io/source-ingress"

func backendNameForService(svcName string) string {
	return svcName + "-service-upstream"
}

func backendKeyForService(ns, svcName string) types.NamespacedName {
	return types.NamespacedName{
		Namespace: ns,
		Name:      backendNameForService(svcName),
	}
}

// ensureStaticBackendForService ensures there is a Static kgateway.Backend for the given
// service in the provided map. If it already exists, it is reused and optionally
// updated with the given protocol. If not, a new Backend is created.
//
// ingressName is only used for the source-ingress label.
func ensureStaticBackendForService(
	ingressName string,
	httpRouteKey types.NamespacedName,
	svcName string,
	host string,
	port int32,
	protocol *providerir.BackendProtocol,
	backends map[types.NamespacedName]*kgw.Backend,
) *kgw.Backend {
	backendKey := backendKeyForService(httpRouteKey.Namespace, svcName)

	// Reuse existing Backend CR if present.
	if kb, ok := backends[backendKey]; ok {
		if protocol != nil && kb.Spec.Static != nil && kb.Spec.Static.AppProtocol == nil {
			switch *protocol {
			case providerir.BackendProtocolGRPC:
				ap := kgw.AppProtocolGrpc
				kb.Spec.Static.AppProtocol = &ap
			}
		}
		return kb
	}

	kb := &kgw.Backend{
		TypeMeta: metav1.TypeMeta{
			Kind:       BackendGVK.Kind,
			APIVersion: BackendGVK.GroupVersion().String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      backendKey.Name,
			Namespace: backendKey.Namespace,
			Labels: map[string]string{
				sourceIngressAnnotation: ingressName,
			},
		},
		Spec: kgw.BackendSpec{
			Type: kgw.BackendTypeStatic,
			Static: &kgw.StaticBackend{
				Hosts: []kgw.Host{
					{
						Host: host,
						Port: gwv1.PortNumber(port),
					},
				},
			},
		},
	}

	if protocol != nil {
		switch *protocol {
		case providerir.BackendProtocolGRPC:
			ap := kgw.AppProtocolGrpc
			kb.Spec.Static.AppProtocol = &ap
		}
	}

	backends[backendKey] = kb
	return kb
}
