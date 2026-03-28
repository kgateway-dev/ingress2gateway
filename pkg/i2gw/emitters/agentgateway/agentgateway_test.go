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

package agentgateway

import (
	"testing"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestEmit_Gateway(t *testing.T) {
	e := &Emitter{notify: notifications.NoopNotify}
	nn := types.NamespacedName{Namespace: "default", Name: "test-gateway"}

	gr, errs := e.Emit(emitterir.EmitterIR{
		Gateways: map[types.NamespacedName]emitterir.GatewayContext{
			nn: {
				Gateway: gatewayv1.Gateway{
					Spec: gatewayv1.GatewaySpec{
						Listeners: []gatewayv1.Listener{{
							Name:     "http",
							Port:     80,
							Protocol: gatewayv1.HTTPProtocolType,
							Hostname: common.PtrTo(gatewayv1.Hostname("example.com")),
						}},
					},
				},
			},
		},
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}

	if gw, ok := gr.Gateways[nn]; !ok {
		t.Fatalf("missing gateway %s", nn)
	} else if gw.Spec.GatewayClassName != emitterName {
		t.Errorf("unexpected GatewayClassName %q", gw.Spec.GatewayClassName)
	}
}

func TestEmit_BodySizeFromRuleIR(t *testing.T) {
	nn := types.NamespacedName{Namespace: "default", Name: "test-http-route"}

	testHTTPRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-http-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name: gatewayv1.ObjectName("test-gateway"),
				}},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  common.PtrTo(gatewayv1.PathMatchPathPrefix),
							Value: common.PtrTo("/"),
						},
					}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: gatewayv1.ObjectName("test-service"),
								Port: common.PtrTo(gatewayv1.PortNumber(80)),
							},
						},
					}},
				},
			},
		},
	}

	e := &Emitter{notify: notifications.NoopNotify}
	got, errs := e.Emit(emitterir.EmitterIR{
		HTTPRoutes: map[types.NamespacedName]emitterir.HTTPRouteContext{
			nn: {
				HTTPRoute: testHTTPRoute,
				BodySizeByRuleIdx: map[int]*emitterir.BodySize{
					0: {
						Metadata:   emitterir.NewExtensionFeatureMetadata("default/ing-body-size", nil, ""),
						BufferSize: common.PtrTo(resource.MustParse("1Mi")),
						MaxSize:    common.PtrTo(resource.MustParse("2Mi")),
					},
				},
			},
		},
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got.GatewayExtensions) != 1 {
		t.Fatalf("want 1 GatewayExtension, got %d", len(got.GatewayExtensions))
	}

	ext := got.GatewayExtensions[0]
	if ext.GetKind() != AgentgatewayPolicyGVK.Kind {
		t.Fatalf("want kind %q, got %q", AgentgatewayPolicyGVK.Kind, ext.GetKind())
	}
	if ext.GetName() != "ing-body-size" {
		t.Fatalf("want policy name %q, got %q", "ing-body-size", ext.GetName())
	}

	targetRefs, found, err := unstructured.NestedSlice(ext.Object, "spec", "targetRefs")
	if err != nil || !found || len(targetRefs) != 1 {
		t.Fatalf("expected one targetRef, found=%v err=%v targetRefs=%#v", found, err, targetRefs)
	}
	targetRef, ok := targetRefs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected targetRef map, got %#v", targetRefs[0])
	}
	if targetRef["name"] != "test-http-route" {
		t.Fatalf("want targetRef name %q, got %#v", "test-http-route", targetRef["name"])
	}

	maxBufferSize, found, err := unstructured.NestedInt64(ext.Object, "spec", "frontend", "http", "maxBufferSize")
	if err != nil || !found {
		t.Fatalf("expected frontend.http.maxBufferSize, found=%v err=%v", found, err)
	}
	if maxBufferSize != 2*1024*1024 {
		t.Fatalf("want maxBufferSize %d, got %d", 2*1024*1024, maxBufferSize)
	}
}

func TestEmit_RateLimitFromRuleIR(t *testing.T) {
	nn := types.NamespacedName{Namespace: "default", Name: "test-http-route"}

	testHTTPRoute := gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-http-route"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name: gatewayv1.ObjectName("test-gateway"),
				}},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: gatewayv1.ObjectName("test-service"),
								Port: common.PtrTo(gatewayv1.PortNumber(80)),
							},
						},
					}},
				},
			},
		},
	}

	e := &Emitter{notify: notifications.NoopNotify}
	got, errs := e.Emit(emitterir.EmitterIR{
		HTTPRoutes: map[types.NamespacedName]emitterir.HTTPRouteContext{
			nn: {
				HTTPRoute: testHTTPRoute,
				RateLimitByRuleIdx: map[int]*emitterir.RateLimitPolicy{
					0: {
						Metadata: emitterir.NewExtensionFeatureMetadata("default/ing-ratelimit", nil, ""),
						Limit:    10,
						Unit:     emitterir.RateLimitUnitRPS,
					},
				},
			},
		},
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(got.GatewayExtensions) != 1 {
		t.Fatalf("want 1 GatewayExtension, got %d", len(got.GatewayExtensions))
	}

	ext := got.GatewayExtensions[0]
	if ext.GetKind() != AgentgatewayPolicyGVK.Kind {
		t.Fatalf("want kind %q, got %q", AgentgatewayPolicyGVK.Kind, ext.GetKind())
	}
	if ext.GetName() != "ing-ratelimit" {
		t.Fatalf("want policy name %q, got %q", "ing-ratelimit", ext.GetName())
	}

	targetRefs, found, err := unstructured.NestedSlice(ext.Object, "spec", "targetRefs")
	if err != nil || !found || len(targetRefs) != 1 {
		t.Fatalf("expected one targetRef, found=%v err=%v targetRefs=%#v", found, err, targetRefs)
	}
	targetRef, ok := targetRefs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected targetRef map, got %#v", targetRefs[0])
	}
	if targetRef["name"] != "test-http-route" {
		t.Fatalf("want targetRef name %q, got %#v", "test-http-route", targetRef["name"])
	}

	localLimits, found, err := unstructured.NestedSlice(ext.Object, "spec", "traffic", "rateLimit", "local")
	if err != nil || !found || len(localLimits) != 1 {
		t.Fatalf("expected one local rate limit, found=%v err=%v local=%#v", found, err, localLimits)
	}
	localLimit, ok := localLimits[0].(map[string]any)
	if !ok {
		t.Fatalf("expected local rate limit map, got %#v", localLimits[0])
	}
	if localLimit["requests"] != int64(10) {
		t.Fatalf("want requests %d, got %#v", 10, localLimit["requests"])
	}
	if localLimit["unit"] != string("Seconds") {
		t.Fatalf("want unit %q, got %#v", "Seconds", localLimit["unit"])
	}
}

func TestEmit_AccessLogFromRuleIR(t *testing.T) {
	tests := []struct {
		name       string
		ingress    string
		enabled    bool
		wantFilter any
	}{
		{
			name:       "enabled access log emits empty config",
			ingress:    "ing-access-log-on",
			enabled:    true,
			wantFilter: nil,
		},
		{
			name:       "disabled access log emits false filter",
			ingress:    "ing-access-log-off",
			enabled:    false,
			wantFilter: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nn := types.NamespacedName{Namespace: "default", Name: "test-http-route"}
			testHTTPRoute := gatewayv1.HTTPRoute{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "test-http-route"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{
							Name: gatewayv1.ObjectName("test-gateway"),
						}},
					},
					Hostnames: []gatewayv1.Hostname{"example.com"},
					Rules: []gatewayv1.HTTPRouteRule{
						{
							BackendRefs: []gatewayv1.HTTPBackendRef{{
								BackendRef: gatewayv1.BackendRef{
									BackendObjectReference: gatewayv1.BackendObjectReference{
										Name: gatewayv1.ObjectName("test-service"),
										Port: common.PtrTo(gatewayv1.PortNumber(80)),
									},
								},
							}},
						},
					},
				},
			}

			e := &Emitter{notify: notifications.NoopNotify}
			got, errs := e.Emit(emitterir.EmitterIR{
				HTTPRoutes: map[types.NamespacedName]emitterir.HTTPRouteContext{
					nn: {
						HTTPRoute: testHTTPRoute,
						EnableAccessLogByRuleIdx: map[int]*emitterir.AccessLog{
							0: {
								Metadata: emitterir.NewExtensionFeatureMetadata("default/"+tt.ingress, nil, ""),
								Enabled:  tt.enabled,
							},
						},
					},
				},
			})
			if len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if len(got.GatewayExtensions) != 1 {
				t.Fatalf("want 1 GatewayExtension, got %d", len(got.GatewayExtensions))
			}

			ext := got.GatewayExtensions[0]
			if ext.GetKind() != AgentgatewayPolicyGVK.Kind {
				t.Fatalf("want kind %q, got %q", AgentgatewayPolicyGVK.Kind, ext.GetKind())
			}
			if ext.GetName() != tt.ingress {
				t.Fatalf("want policy name %q, got %q", tt.ingress, ext.GetName())
			}

			targetRefs, found, err := unstructured.NestedSlice(ext.Object, "spec", "targetRefs")
			if err != nil || !found || len(targetRefs) != 1 {
				t.Fatalf("expected one targetRef, found=%v err=%v targetRefs=%#v", found, err, targetRefs)
			}

			accessLog, found, err := unstructured.NestedMap(ext.Object, "spec", "frontend", "accessLog")
			if err != nil || !found {
				t.Fatalf("expected accessLog config, found=%v err=%v", found, err)
			}
			filter, found, err := unstructured.NestedString(accessLog, "filter")
			if err != nil {
				t.Fatalf("unexpected filter error: %v", err)
			}
			if tt.wantFilter == nil {
				if found {
					t.Fatalf("expected no filter, got %q", filter)
				}
			} else {
				if !found || filter != tt.wantFilter {
					t.Fatalf("want filter %q, got found=%v value=%q", tt.wantFilter, found, filter)
				}
			}
		})
	}
}
