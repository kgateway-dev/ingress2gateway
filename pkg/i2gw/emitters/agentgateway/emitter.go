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
	"sort"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitters/utils"
	agentgatewayv1alpha1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/agentgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func init() {
	i2gw.EmitterConstructorByName["agentgateway"] = NewEmitter
}

type Emitter struct{}

// NewEmitter returns a new instance of AgentgatewayEmitter.
func NewEmitter(_ *i2gw.EmitterConf) i2gw.Emitter {
	return &Emitter{}
}

// Emit converts EmitterIR to Gateway API resources plus agentgateway-specific extensions.
func (e *Emitter) Emit(ir emitterir.EmitterIR) (i2gw.GatewayResources, field.ErrorList) {
	gatewayResources, errs := utils.ToGatewayResources(ir)
	if len(errs) > 0 {
		return gatewayResources, errs
	}

	// Set GatewayClassName to "agentgateway" for all Gateways
	for key := range gatewayResources.Gateways {
		gateway := gatewayResources.Gateways[key]
		gateway.Spec.GatewayClassName = "agentgateway"
		gatewayResources.Gateways[key] = gateway
	}

	// Track agentgateway-specific resources
	var agentgatewayObjs []client.Object

	// Track AgentgatewayPolicies per ingress name
	agentgatewayPolicies := map[string]*agentgatewayv1alpha1.AgentgatewayPolicy{}

	for httpRouteKey, httpRouteContext := range ir.HTTPRoutes {
		ingx := httpRouteContext.IngressNginx
		if ingx == nil {
			continue
		}

		// Apply host-wide regex enforcement first (so rule path regex is finalized)
		// TODO: implement regex path matching if needed

		// deterministic policy iteration
		policyNames := make([]string, 0, len(ingx.Policies))
		for name := range ingx.Policies {
			policyNames = append(policyNames, name)
		}
		sort.Strings(policyNames)

		for polSourceIngressName, pol := range ingx.Policies {
			// Normalize (rule, backend) coverage to unique pairs to avoid
			// generating duplicate filters on the same backendRef.
			coverage := uniquePolicyIndices(pol.RuleBackendSources)

			// Apply rate limit policy
			if applyRateLimitPolicy(pol, polSourceIngressName, httpRouteKey.Namespace, agentgatewayPolicies) {
				// Set targetRefs for the policy
				agp := agentgatewayPolicies[polSourceIngressName]
				if agp != nil {
					// If this policy covers all route backends, attach via targetRefs.
					// Otherwise, attach via ExtensionRef filters on the covered backendRefs.
					if len(coverage) == numRules(httpRouteContext.HTTPRoute) {
						// Full coverage via targetRefs.
						agp.Spec.TargetRefs = []shared.LocalPolicyTargetReferenceWithSectionName{{
							LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
								Group: gatewayv1.Group("gateway.networking.k8s.io"),
								Kind:  gatewayv1.Kind("HTTPRoute"),
								Name:  gatewayv1.ObjectName(httpRouteKey.Name),
							},
						}}
					} else {
						// Partial coverage via ExtensionRef filters on backendRefs.
						for _, idx := range coverage {
							if idx.Rule >= len(httpRouteContext.Spec.Rules) {
								continue
							}
							rule := &httpRouteContext.Spec.Rules[idx.Rule]
							if idx.Backend >= len(rule.BackendRefs) {
								continue
							}

							rule.BackendRefs[idx.Backend].Filters = append(
								rule.BackendRefs[idx.Backend].Filters,
								gatewayv1.HTTPRouteFilter{
									Type: gatewayv1.HTTPRouteFilterExtensionRef,
									ExtensionRef: &gatewayv1.LocalObjectReference{
										Group: gatewayv1.Group(AgentgatewayPolicyGVK.Group),
										Kind:  gatewayv1.Kind(AgentgatewayPolicyGVK.Kind),
										Name:  gatewayv1.ObjectName(agp.Name),
									},
								},
							)
						}
					}
				}
			}
		}

		// Write back the mutated HTTPRouteContext into the IR.
		ir.HTTPRoutes[httpRouteKey] = httpRouteContext

		// Update gatewayResources with modified HTTPRoute
		gatewayResources.HTTPRoutes[httpRouteKey] = httpRouteContext.HTTPRoute
	}

	// Collect AgentgatewayPolicies
	for _, ap := range agentgatewayPolicies {
		agentgatewayObjs = append(agentgatewayObjs, ap)
	}

	// Sort by Kind, then Namespace, then Name to make output deterministic for testing.
	sort.SliceStable(agentgatewayObjs, func(i, j int) bool {
		oi, oj := agentgatewayObjs[i], agentgatewayObjs[j]

		gvki := oi.GetObjectKind().GroupVersionKind()
		gvkj := oj.GetObjectKind().GroupVersionKind()

		ki, kj := gvki.Kind, gvkj.Kind
		if ki != kj {
			return ki < kj
		}

		nsi, nsj := oi.GetNamespace(), oj.GetNamespace()
		if nsi != nsj {
			return nsi < nsj
		}

		return oi.GetName() < oj.GetName()
	})

	// Convert agentgateway objects to unstructured and add to GatewayExtensions
	for _, obj := range agentgatewayObjs {
		u, err := toUnstructured(obj)
		if err != nil {
			errs = append(errs, field.InternalError(field.NewPath("agentgateway"), err))
			continue
		}
		gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *u)
	}

	return gatewayResources, errs
}
