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

package kgateway

import (
	"time"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EmitRateLimit projects provider-neutral per-rule rate limit intent into
// section-scoped Kgateway TrafficPolicies.
func (e *Emitter) EmitRateLimit(ir emitterir.EmitterIR) {
	for _, ctx := range ir.HTTPRoutes {
		for idx, rl := range ctx.RateLimitByRuleIdx {
			if rl == nil || idx < 0 || idx >= len(ctx.Spec.Rules) || rl.Limit <= 0 {
				continue
			}

			var (
				maxTokens     int32
				tokensPerFill int32
				fillInterval  metav1.Duration
			)

			burstMult := rl.BurstMultiplier
			if burstMult <= 0 {
				burstMult = 1
			}

			switch rl.Unit {
			case emitterir.RateLimitUnitRPS:
				tokensPerFill = rl.Limit
				maxTokens = rl.Limit * burstMult
				fillInterval = metav1.Duration{Duration: time.Second}
			case emitterir.RateLimitUnitRPM:
				tokensPerFill = rl.Limit
				maxTokens = rl.Limit * burstMult
				fillInterval = metav1.Duration{Duration: time.Minute}
			default:
				continue
			}

			sectionName := e.getSectionName(ctx, idx)
			trafficPolicy := e.getOrBuildTrafficPolicy(ctx, sectionName, idx)
			if trafficPolicy.Spec.RateLimit == nil {
				trafficPolicy.Spec.RateLimit = &kgateway.RateLimit{}
			}
			if trafficPolicy.Spec.RateLimit.Local == nil {
				trafficPolicy.Spec.RateLimit.Local = &kgateway.LocalRateLimitPolicy{}
			}
			trafficPolicy.Spec.RateLimit.Local.TokenBucket = &kgateway.TokenBucket{
				MaxTokens:     maxTokens,
				TokensPerFill: int32Ptr(tokensPerFill),
				FillInterval:  fillInterval,
			}
		}
	}
}

func int32Ptr(v int32) *int32 { return &v }
