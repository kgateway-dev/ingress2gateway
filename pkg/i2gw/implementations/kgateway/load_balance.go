/*
Copyright 2023 The Kubernetes Authors.

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
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyLoadBalancingPolicy projects the LoadBalancing IR policy into one or more
// Kgateway BackendConfigPolicies.
//
// Semantics:
//   - We create at most one BackendConfigPolicy per Service.
//   - If SessionAffinity is configured for a Service, it takes precedence and
//     this function will not override the ring-hash configuration.
//   - If there is no SessionAffinity for a Service and LoadBalancing.Strategy is
//     "round_robin", we configure LoadBalancer.RoundRobin on the BackendConfigPolicy.
//   - TargetRefs are populated with all core Service backends that this Policy covers
//     (based on RuleBackendSources).
func applyLoadBalancingPolicy(
	pol providerir.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteCtx providerir.HTTPRouteContext,
	backendCfg map[types.NamespacedName]*kgateway.BackendConfigPolicy,
) bool {
	// Only care about explicit round_robin strategies.
	if pol.LoadBalancing == nil || pol.LoadBalancing.Strategy != providerir.LoadBalancingStrategyRoundRobin {
		return false
	}

	touched := false

	for _, idx := range pol.RuleBackendSources {
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := rule.BackendRefs[idx.Backend]

		// Only core Service backends.
		if br.BackendRef.Group != nil && *br.BackendRef.Group != "" {
			continue
		}
		if br.BackendRef.Kind != nil && *br.BackendRef.Kind != "Service" {
			continue
		}

		svcName := string(br.BackendRef.Name)
		if svcName == "" {
			continue
		}

		svcKey := types.NamespacedName{
			Namespace: httpRouteKey.Namespace,
			Name:      svcName,
		}

		// Create or reuse BackendConfigPolicy per Service.
		bcp, exists := backendCfg[svcKey]
		if !exists {
			policyName := svcName + "-backend-config"
			bcp = &kgateway.BackendConfigPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      policyName,
					Namespace: httpRouteKey.Namespace,
				},
				Spec: kgateway.BackendConfigPolicySpec{
					TargetRefs: []shared.LocalPolicyTargetReference{
						{
							Group: "",
							Kind:  "Service",
							Name:  gwv1.ObjectName(svcName),
						},
					},
				},
			}
			bcp.SetGroupVersionKind(BackendConfigPolicyGVK)
			backendCfg[svcKey] = bcp
		}

		// Respect session affinity precedence:
		// If RingHash is already set (via applySessionAffinityPolicy), do not override.
		if bcp.Spec.LoadBalancer != nil && bcp.Spec.LoadBalancer.RingHash != nil {
			// TODO [danehans] add a notification that we are skipping due to session affinity.
			continue
		}

		if bcp.Spec.LoadBalancer == nil {
			bcp.Spec.LoadBalancer = &kgateway.LoadBalancer{}
		}

		// Set explicit round_robin.
		bcp.Spec.LoadBalancer.RoundRobin = &kgateway.LoadBalancerRoundRobinConfig{}

		touched = true
	}

	return touched
}
