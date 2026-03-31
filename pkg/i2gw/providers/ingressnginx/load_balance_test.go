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
	"k8s.io/apimachinery/pkg/types"
)

func TestApplyLoadBalancingToEmitterIR_SetRoundRobin(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		LoadBalanceAnnotation: "round_robin",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyLoadBalancingToEmitterIR(pIR, &eIR)

	loadBalancingIR := eIR.HTTPRoutes[key].LoadBalancingByRuleIdx[0]
	if loadBalancingIR == nil {
		t.Fatalf("expected load balancing IR to be set for rule index 0")
	}
	if loadBalancingIR.Strategy != emitterir.LoadBalancingStrategyRoundRobin {
		t.Fatalf("expected strategy %q, got %q", emitterir.LoadBalancingStrategyRoundRobin, loadBalancingIR.Strategy)
	}
}

func TestApplyLoadBalancingToEmitterIR_SkipsUnsupportedStrategy(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		LoadBalanceAnnotation: "ewma",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyLoadBalancingToEmitterIR(pIR, &eIR)

	if got := eIR.HTTPRoutes[key].LoadBalancingByRuleIdx; got != nil {
		t.Fatalf("expected no load balancing IR for unsupported annotation, got %#v", got)
	}
}
