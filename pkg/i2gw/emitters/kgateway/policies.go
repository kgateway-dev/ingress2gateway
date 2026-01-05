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

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// applyBufferPolicy projects the buffer-related policy IR into a Kgateway TrafficPolicy,
// returning true if it modified/created a TrafficPolicy for this ingress.
//
// Semantics are as follows:
//   - If the "nginx.ingress.kubernetes.io/proxy-body-size" annotation is present, that value
//     is used as the effective max request size.
//   - Otherwise, if the "nginx.ingress.kubernetes.io/client-body-buffer-size" annotation is present,
//     that value is used.
//   - If neither is set, no Kgateway Buffer policy is emitted.
//
// Note: Kgateway's Buffer.MaxRequestSize has "max body size" semantics (413 on exceed),
// which matches NGINX's proxy-body-size more directly. client-body-buffer-size is
// treated as a fallback when proxy-body-size is not configured.
func applyBufferPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
) bool {
	if pol.ClientBodyBufferSize == nil && pol.ProxyBodySize == nil {
		return false
	}

	// Prefer proxy-body-size if present; otherwise fall back to client-body-buffer-size.
	size := pol.ProxyBodySize
	if size == nil {
		size = pol.ClientBodyBufferSize
	}
	if size == nil {
		return false
	}

	t := ensureTrafficPolicy(tp, ingressName, namespace)
	t.Spec.Buffer = &kgateway.Buffer{
		MaxRequestSize: size,
	}
	return true
}

// applyRateLimitPolicy projects the rate limit policy IR into a Kgateway TrafficPolicy.
func applyRateLimitPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
) bool {
	if pol.RateLimit == nil {
		return false
	}

	rl := pol.RateLimit
	if rl.Limit <= 0 {
		return false
	}

	// Default burst multiplier to 1 if unset/zero.
	burstMult := rl.BurstMultiplier
	if burstMult <= 0 {
		burstMult = 1
	}

	var (
		maxTokens     int32
		tokensPerFill int32
		fillInterval  metav1.Duration
	)

	switch rl.Unit {
	case providerir.RateLimitUnitRPS:
		// Requests per second.
		tokensPerFill = rl.Limit
		maxTokens = rl.Limit * burstMult
		fillInterval = metav1.Duration{Duration: time.Second}
	case providerir.RateLimitUnitRPM:
		// Requests per minute.
		tokensPerFill = rl.Limit
		maxTokens = rl.Limit * burstMult
		fillInterval = metav1.Duration{Duration: time.Minute}
	default:
		// Unknown unit; ignore for now.
		return false
	}

	t := ensureTrafficPolicy(tp, ingressName, namespace)

	if t.Spec.RateLimit == nil {
		t.Spec.RateLimit = &kgateway.RateLimit{}
	}
	if t.Spec.RateLimit.Local == nil {
		t.Spec.RateLimit.Local = &kgateway.LocalRateLimitPolicy{}
	}

	// Helper to create *int32 without extra imports.
	int32Ptr := func(v int32) *int32 { return &v }

	t.Spec.RateLimit.Local.TokenBucket = &kgateway.TokenBucket{
		MaxTokens:     maxTokens,
		TokensPerFill: int32Ptr(tokensPerFill),
		FillInterval:  fillInterval,
	}

	return true
}

// applyTimeoutPolicy projects the timeout-related policy IR into a Kgateway TrafficPolicy,
// returning true if it modified/created a TrafficPolicy for this ingress.
//
// Semantics:
//   - If ProxySendTimeout is set, it is mapped to the Request timeout in Kgateway.
//   - If ProxyReadTimeout is set, it is mapped to the StreamIdle timeout in Kgateway.
func applyTimeoutPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	tp map[string]*kgateway.TrafficPolicy,
) bool {
	if pol.ProxySendTimeout == nil && pol.ProxyReadTimeout == nil {
		return false
	}

	t := ensureTrafficPolicy(tp, ingressName, namespace)

	if t.Spec.Timeouts == nil {
		t.Spec.Timeouts = &shared.Timeouts{}
	}

	// Map proxy-send-timeout → Timeouts.Request
	if pol.ProxySendTimeout != nil {
		t.Spec.Timeouts.Request = pol.ProxySendTimeout
	}

	// Map proxy-read-timeout → Timeouts.StreamIdle
	if pol.ProxyReadTimeout != nil {
		t.Spec.Timeouts.StreamIdle = pol.ProxyReadTimeout
	}

	return true
}
