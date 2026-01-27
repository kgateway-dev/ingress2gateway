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

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBufferPolicyFeature(t *testing.T) {
	testCases := []struct {
		name                  string
		ingress               networkingv1.Ingress
		expectBufferSizeSet   bool
		expectedBufferSizeVal string
	}{
		{
			name: "buffer size with proxy-buffering enabled",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-buffer-enabled",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/client-body-buffer-size": "8k",
						"nginx.ingress.kubernetes.io/proxy-buffering":         "on",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectBufferSizeSet:   true,
			expectedBufferSizeVal: "8k",
		},
		{
			name: "buffer size ignored when proxy-buffering is off",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-buffer-off",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/client-body-buffer-size": "8k",
						"nginx.ingress.kubernetes.io/proxy-buffering":         "off",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectBufferSizeSet: false,
		},
		{
			name: "buffer size ignored when proxy-buffering is unset",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-buffer-unset",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/client-body-buffer-size": "8k",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectBufferSizeSet: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ir := providerir.ProviderIR{
				HTTPRoutes: make(map[types.NamespacedName]providerir.HTTPRouteContext),
			}

			// Setup initial HTTPRoute in IR
			routeKey := types.NamespacedName{
				Namespace: tc.ingress.Namespace,
				Name:      common.RouteName(tc.ingress.Name, "example.com"),
			}
			ir.HTTPRoutes[routeKey] = providerir.HTTPRouteContext{
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: tc.ingress.Namespace,
						Name:      routeKey.Name,
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "test-service",
												Port: ptr.To(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]providerir.BackendSource{
					{
						{Ingress: &tc.ingress},
					},
				},
				ProviderSpecificIR: providerir.ProviderSpecificHTTPRouteIR{},
			}

			// Run the feature parser
			errs := bufferPolicyFeature([]networkingv1.Ingress{tc.ingress}, nil, &ir)
			if len(errs) > 0 {
				t.Fatalf("Unexpected errors: %v", errs)
			}

			// Verify results
			httpCtx := ir.HTTPRoutes[routeKey]
			if tc.expectBufferSizeSet {
				if httpCtx.ProviderSpecificIR.IngressNginx == nil {
					t.Fatal("Expected IngressNginx IR to be set")
				}
				policy, ok := httpCtx.ProviderSpecificIR.IngressNginx.Policies[tc.ingress.Name]
				if !ok {
					t.Fatal("Expected policy to be set")
				}
				if policy.ClientBodyBufferSize == nil {
					t.Fatal("Expected ClientBodyBufferSize to be set")
				}

				expectedQuantity := resource.MustParse(tc.expectedBufferSizeVal)
				if !policy.ClientBodyBufferSize.Equal(expectedQuantity) {
					t.Errorf("Expected buffer size %v, got %v", expectedQuantity, policy.ClientBodyBufferSize)
				}
			} else {
				// Verify buffer size was NOT set
				if httpCtx.ProviderSpecificIR.IngressNginx != nil {
					if policy, ok := httpCtx.ProviderSpecificIR.IngressNginx.Policies[tc.ingress.Name]; ok {
						if policy.ClientBodyBufferSize != nil {
							t.Errorf("Expected ClientBodyBufferSize to NOT be set, but it was: %v", policy.ClientBodyBufferSize)
						}
					}
				}
			}
		})
	}
}

func TestProxyBodySizeFeature(t *testing.T) {
	testCases := []struct {
		name                    string
		ingress                 networkingv1.Ingress
		expectProxyBodySizeSet  bool
		expectedProxyBodySizeVal string
	}{
		{
			name: "proxy-body-size with proxy-buffering enabled",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-proxy-enabled",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/proxy-body-size":  "10m",
						"nginx.ingress.kubernetes.io/proxy-buffering": "on",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectProxyBodySizeSet:  true,
			expectedProxyBodySizeVal: "10m",
		},
		{
			name: "proxy-body-size ignored when proxy-buffering is off",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-proxy-off",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/proxy-body-size":  "10m",
						"nginx.ingress.kubernetes.io/proxy-buffering": "off",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectProxyBodySizeSet: false,
		},
		{
			name: "proxy-body-size ignored when proxy-buffering is unset",
			ingress: networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-proxy-unset",
					Namespace: "default",
					Annotations: map[string]string{
						"nginx.ingress.kubernetes.io/proxy-body-size": "10m",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr.To(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "test-service",
													Port: networkingv1.ServiceBackendPort{
														Number: 80,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectProxyBodySizeSet: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ir := providerir.ProviderIR{
				HTTPRoutes: make(map[types.NamespacedName]providerir.HTTPRouteContext),
			}

			// Setup initial HTTPRoute in IR
			routeKey := types.NamespacedName{
				Namespace: tc.ingress.Namespace,
				Name:      common.RouteName(tc.ingress.Name, "example.com"),
			}
			ir.HTTPRoutes[routeKey] = providerir.HTTPRouteContext{
				HTTPRoute: gatewayv1.HTTPRoute{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: tc.ingress.Namespace,
						Name:      routeKey.Name,
					},
					Spec: gatewayv1.HTTPRouteSpec{
						Rules: []gatewayv1.HTTPRouteRule{
							{
								BackendRefs: []gatewayv1.HTTPBackendRef{
									{
										BackendRef: gatewayv1.BackendRef{
											BackendObjectReference: gatewayv1.BackendObjectReference{
												Name: "test-service",
												Port: ptr.To(gatewayv1.PortNumber(80)),
											},
										},
									},
								},
							},
						},
					},
				},
				RuleBackendSources: [][]providerir.BackendSource{
					{
						{Ingress: &tc.ingress},
					},
				},
				ProviderSpecificIR: providerir.ProviderSpecificHTTPRouteIR{},
			}

			// Run the feature parser
			errs := proxyBodySizeFeature([]networkingv1.Ingress{tc.ingress}, nil, &ir)
			if len(errs) > 0 {
				t.Fatalf("Unexpected errors: %v", errs)
			}

			// Verify results
			httpCtx := ir.HTTPRoutes[routeKey]
			if tc.expectProxyBodySizeSet {
				if httpCtx.ProviderSpecificIR.IngressNginx == nil {
					t.Fatal("Expected IngressNginx IR to be set")
				}
				policy, ok := httpCtx.ProviderSpecificIR.IngressNginx.Policies[tc.ingress.Name]
				if !ok {
					t.Fatal("Expected policy to be set")
				}
				if policy.ProxyBodySize == nil {
					t.Fatal("Expected ProxyBodySize to be set")
				}

				expectedQuantity := resource.MustParse(tc.expectedProxyBodySizeVal)
				if !policy.ProxyBodySize.Equal(expectedQuantity) {
					t.Errorf("Expected proxy body size %v, got %v", expectedQuantity, policy.ProxyBodySize)
				}
			} else {
				// Verify proxy body size was NOT set
				if httpCtx.ProviderSpecificIR.IngressNginx != nil {
					if policy, ok := httpCtx.ProviderSpecificIR.IngressNginx.Policies[tc.ingress.Name]; ok {
						if policy.ProxyBodySize != nil {
							t.Errorf("Expected ProxyBodySize to NOT be set, but it was: %v", policy.ProxyBodySize)
						}
					}
				}
			}
		})
	}
}
