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

package agentgateway

import (
	agentgatewayv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/agentgateway"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
)

// applyTimeoutPolicy projects timeout-related Policy IR into an AgentgatewayPolicy,
// returning true if it modified/created an AgentgatewayPolicy for this ingress.
//
// AgentgatewayPolicy exposes a single request timeout at traffic.timeouts.request.
// NGINX has separate proxy-send-timeout and proxy-read-timeout knobs; we conservatively
// choose the larger of the two when both are set.
func applyTimeoutPolicy(
	pol providerir.Policy,
	ingressName, namespace string,
	ap map[string]*agentgatewayv1alpha1.AgentgatewayPolicy,
) bool {
	if pol.ProxyReadTimeout == nil && pol.ProxySendTimeout == nil {
		return false
	}

	agp := ensureAgentgatewayPolicy(ap, ingressName, namespace)
	if agp.Spec.Traffic == nil {
		agp.Spec.Traffic = &agentgatewayv1alpha1.Traffic{}
	}
	if agp.Spec.Traffic.Timeouts == nil {
		agp.Spec.Traffic.Timeouts = &agentgatewayv1alpha1.Timeouts{}
	}

	// Pick the most permissive timeout to avoid unexpectedly truncating requests.
	timeout := pol.ProxySendTimeout
	if timeout == nil || (pol.ProxyReadTimeout != nil && pol.ProxyReadTimeout.Duration > timeout.Duration) {
		timeout = pol.ProxyReadTimeout
	}

	agp.Spec.Traffic.Timeouts.Request = timeout
	ap[ingressName] = agp
	return true
}
