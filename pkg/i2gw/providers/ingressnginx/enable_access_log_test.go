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
	"k8s.io/apimachinery/pkg/types"
)

func TestApplyAccessLogToEmitterIR_Enabled(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		EnableAccessLogAnnotation: "true",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyAccessLogToEmitterIR(pIR, &eIR)

	accessLogIR := eIR.HTTPRoutes[key].EnableAccessLogByRuleIdx[0]
	if accessLogIR == nil {
		t.Fatalf("expected access log IR to be set for rule index 0")
	}
	if !accessLogIR.Enabled {
		t.Fatalf("expected access log to be enabled")
	}
}

func TestApplyAccessLogToEmitterIR_Disabled(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		EnableAccessLogAnnotation: "false",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyAccessLogToEmitterIR(pIR, &eIR)

	accessLogIR := eIR.HTTPRoutes[key].EnableAccessLogByRuleIdx[0]
	if accessLogIR == nil {
		t.Fatalf("expected access log IR to be set for rule index 0")
	}
	if accessLogIR.Enabled {
		t.Fatalf("expected access log to be disabled")
	}
}
