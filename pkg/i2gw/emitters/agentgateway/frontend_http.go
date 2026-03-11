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

package agentgateway

import (
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	agentgatewayv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/agentgateway"
)

// applyFrontendHTTPPolicy projects frontend HTTP listener settings into
// AgentgatewayPolicy.spec.frontend.http.
func applyFrontendHTTPPolicy(
	pol emitterir.Policy,
	ingressName, namespace string,
	ap map[string]*agentgatewayv1alpha1.AgentgatewayPolicy,
) bool {
	if pol.FrontendHTTP == nil {
		return false
	}

	http := pol.FrontendHTTP
	if http.HTTP1MaxHeaders == nil &&
		http.HTTP1IdleTimeout == nil &&
		http.HTTP2WindowSize == nil &&
		http.HTTP2ConnectionWindowSize == nil &&
		http.HTTP2FrameSize == nil &&
		http.HTTP2KeepaliveInterval == nil &&
		http.HTTP2KeepaliveTimeout == nil {
		return false
	}

	agp := ensureAgentgatewayPolicy(ap, ingressName, namespace)
	if agp.Spec.Frontend == nil {
		agp.Spec.Frontend = &agentgatewayv1alpha1.Frontend{}
	}
	if agp.Spec.Frontend.HTTP == nil {
		agp.Spec.Frontend.HTTP = &agentgatewayv1alpha1.FrontendHTTP{}
	}

	agp.Spec.Frontend.HTTP.HTTP1MaxHeaders = http.HTTP1MaxHeaders
	agp.Spec.Frontend.HTTP.HTTP1IdleTimeout = http.HTTP1IdleTimeout
	agp.Spec.Frontend.HTTP.HTTP2WindowSize = http.HTTP2WindowSize
	agp.Spec.Frontend.HTTP.HTTP2ConnectionWindowSize = http.HTTP2ConnectionWindowSize
	agp.Spec.Frontend.HTTP.HTTP2FrameSize = http.HTTP2FrameSize
	agp.Spec.Frontend.HTTP.HTTP2KeepaliveInterval = http.HTTP2KeepaliveInterval
	agp.Spec.Frontend.HTTP.HTTP2KeepaliveTimeout = http.HTTP2KeepaliveTimeout

	ap[ingressName] = agp
	return true
}
