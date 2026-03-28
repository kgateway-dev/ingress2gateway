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

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/notifications"
	"k8s.io/apimachinery/pkg/types"
)

func TestApplyRateLimitToEmitterIR_PrefersRPS(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		LimitRPSAnnotation:             "10",
		LimitRPMAnnotation:             "600",
		LimitBurstMultiplierAnnotation: "3",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyRateLimitToEmitterIR(pIR, &eIR)

	rateLimitIR := eIR.HTTPRoutes[key].RateLimitByRuleIdx[0]
	if rateLimitIR == nil {
		t.Fatalf("expected rate limit IR to be set for rule index 0")
	}
	if rateLimitIR.Limit != 10 {
		t.Fatalf("expected limit 10, got %d", rateLimitIR.Limit)
	}
	if rateLimitIR.Unit != emitterir.RateLimitUnitRPS {
		t.Fatalf("expected unit %q, got %q", emitterir.RateLimitUnitRPS, rateLimitIR.Unit)
	}
	if rateLimitIR.BurstMultiplier != 3 {
		t.Fatalf("expected burst multiplier 3, got %d", rateLimitIR.BurstMultiplier)
	}
}

func TestApplyRateLimitToEmitterIR_UsesRPMWhenRPSMissing(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		LimitRPMAnnotation: "120",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyRateLimitToEmitterIR(pIR, &eIR)

	rateLimitIR := eIR.HTTPRoutes[key].RateLimitByRuleIdx[0]
	if rateLimitIR == nil {
		t.Fatalf("expected rate limit IR to be set for rule index 0")
	}
	if rateLimitIR.Limit != 120 {
		t.Fatalf("expected limit 120, got %d", rateLimitIR.Limit)
	}
	if rateLimitIR.Unit != emitterir.RateLimitUnitRPM {
		t.Fatalf("expected unit %q, got %q", emitterir.RateLimitUnitRPM, rateLimitIR.Unit)
	}
	if rateLimitIR.BurstMultiplier != 1 {
		t.Fatalf("expected default burst multiplier 1, got %d", rateLimitIR.BurstMultiplier)
	}
}

func TestApplyRateLimitToEmitterIR_SkipsInvalidLimit(t *testing.T) {
	key := types.NamespacedName{Namespace: "default", Name: "route"}
	annotations := map[string]string{
		LimitRPSAnnotation: "nope",
	}
	pIR, eIR := setupBodySizeTest(key, annotations)

	p := &Provider{notify: notifications.NoopNotify}
	p.applyRateLimitToEmitterIR(pIR, &eIR)

	if got := eIR.HTTPRoutes[key].RateLimitByRuleIdx; got != nil {
		t.Fatalf("expected no rate limit IR for invalid annotation, got %#v", got)
	}
}
