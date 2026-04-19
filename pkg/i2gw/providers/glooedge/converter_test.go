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

package glooedge

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_ToIR(t *testing.T) {
	gPathPrefix := gatewayv1.PathMatchPathPrefix

	testCases := []struct {
		name           string
		virtualService *VirtualService
		expectedIR     providerir.ProviderIR
		expectedErrors field.ErrorList
	}{
		{
			name: "basic single upstream conversion",
			virtualService: &VirtualService{
				Name:      "example-vs",
				Namespace: "default",
				Spec: VirtualServiceSpec{
					Hosts: []string{"example.com"},
					VirtualHost: VirtualHost{
						Routes: []Route{
							{
								Matchers: []Matcher{
									{Prefix: "/api"},
								},
								RouteAction: RouteAction{
									Single: SingleUpstream{
										Upstream: Upstream{
											Name:      "my-service",
											Namespace: "default",
										},
									},
								},
							},
						},
					},
				},
			},
			expectedIR: providerir.ProviderIR{
				Gateways: map[types.NamespacedName]providerir.GatewayContext{
					{Namespace: "default", Name: "gloo-edge"}: {
						Gateway: gatewayv1.Gateway{
							ObjectMeta: metav1.ObjectMeta{Name: "gloo-edge", Namespace: "default"},
							Spec: gatewayv1.GatewaySpec{
								GatewayClassName: "gloo-edge",
								Listeners: []gatewayv1.Listener{{
									Name:     "example-com-http",
									Port:     80,
									Protocol: gatewayv1.HTTPProtocolType,
									Hostname: ptr.To(gatewayv1.Hostname("example.com")),
								}},
							},
						},
					},
				},
				HTTPRoutes: map[types.NamespacedName]providerir.HTTPRouteContext{
					{Namespace: "default", Name: "example-vs-example-com"}: {
						HTTPRoute: gatewayv1.HTTPRoute{
							ObjectMeta: metav1.ObjectMeta{Name: "example-vs-example-com", Namespace: "default"},
							Spec: gatewayv1.HTTPRouteSpec{
								CommonRouteSpec: gatewayv1.CommonRouteSpec{
									ParentRefs: []gatewayv1.ParentReference{{
										Name: "gloo-edge",
									}},
								},
								Hostnames: []gatewayv1.Hostname{"example.com"},
								Rules: []gatewayv1.HTTPRouteRule{{
									Matches: []gatewayv1.HTTPRouteMatch{{
										Path: &gatewayv1.HTTPPathMatch{
											Type:  &gPathPrefix,
											Value: ptr.To("/api"),
										},
									}},
									BackendRefs: []gatewayv1.HTTPBackendRef{
										{
											BackendRef: gatewayv1.BackendRef{
												BackendObjectReference: gatewayv1.BackendObjectReference{
													Name: "my-service",
												},
											},
										},
									},
								}},
							},
						},
					},
				},
			},
			expectedErrors: field.ErrorList{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := NewProvider(&i2gw.ProviderConf{})

			geProvider := provider.(*Provider)
			// Create storage and add the VirtualService
			geProvider.storage.addVirtualService(tc.virtualService)

			ir, errs := provider.ToIR()

			// Validate error count
			if len(errs) != len(tc.expectedErrors) {
				t.Errorf("Expected %d errors, got %d: %+v", len(tc.expectedErrors), len(errs), errs)
			} else {
				for i, e := range errs {
					if errors.Is(e, tc.expectedErrors[i]) {
						t.Errorf("Unexpected error message at %d index. Got %s, want: %s", i, e, tc.expectedErrors[i])
					}
				}
			}

			// Validate HTTPRoutes
			if len(ir.HTTPRoutes) != len(tc.expectedIR.HTTPRoutes) {
				t.Errorf("Expected %d HTTPRoutes, got %d: %+v",
					len(tc.expectedIR.HTTPRoutes), len(ir.HTTPRoutes), ir.HTTPRoutes)
			} else {
				for _, gotHTTPRouteContext := range ir.HTTPRoutes {
					key := types.NamespacedName{Namespace: gotHTTPRouteContext.HTTPRoute.Namespace, Name: gotHTTPRouteContext.HTTPRoute.Name}
					wantHTTPRouteContext := tc.expectedIR.HTTPRoutes[key]
					wantHTTPRouteContext.HTTPRoute.SetGroupVersionKind(common.HTTPRouteGVK)
					if !apiequality.Semantic.DeepEqual(gotHTTPRouteContext.HTTPRoute, wantHTTPRouteContext.HTTPRoute) {
						t.Errorf("Expected HTTPRoute %s to be %+v\n Got: %+v\n Diff: %s", key.Name, wantHTTPRouteContext.HTTPRoute, gotHTTPRouteContext.HTTPRoute, cmp.Diff(wantHTTPRouteContext.HTTPRoute, gotHTTPRouteContext.HTTPRoute))
					}
				}
			}

			// Validate Gateways
			if len(ir.Gateways) != len(tc.expectedIR.Gateways) {
				t.Errorf("Expected %d Gateways, got %d: %+v",
					len(tc.expectedIR.Gateways), len(ir.Gateways), ir.Gateways)
			} else {
				for _, gotGatewayContext := range ir.Gateways {
					key := types.NamespacedName{Namespace: gotGatewayContext.Gateway.Namespace, Name: gotGatewayContext.Gateway.Name}
					wantGatewayContext := tc.expectedIR.Gateways[key]
					wantGatewayContext.Gateway.SetGroupVersionKind(common.GatewayGVK)
					if !apiequality.Semantic.DeepEqual(gotGatewayContext.Gateway, wantGatewayContext.Gateway) {
						t.Errorf("Expected Gateway %s to be %+v\n Got: %+v\n Diff: %s", key.Name, wantGatewayContext.Gateway, gotGatewayContext.Gateway, cmp.Diff(wantGatewayContext.Gateway, gotGatewayContext.Gateway))
					}
				}
			}
		})
	}
}
