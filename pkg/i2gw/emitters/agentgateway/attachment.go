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
	"fmt"
	"sort"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type trafficPolicyAttachment struct {
	TargetRefs      []shared.LocalPolicyTargetReferenceWithSectionName
	CoveredRuleIdxs map[int]struct{}
}

func buildTrafficPolicyAttachment(
	httpRouteKey types.NamespacedName,
	httpRouteCtx emitterir.HTTPRouteContext,
	coverage []emitterir.PolicyIndex,
	policyName string,
) (trafficPolicyAttachment, *field.Error) {
	attachment := trafficPolicyAttachment{
		CoveredRuleIdxs: map[int]struct{}{},
	}

	if len(httpRouteCtx.Spec.Rules) == 0 || len(coverage) == 0 {
		attachment.TargetRefs = []shared.LocalPolicyTargetReferenceWithSectionName{
			httpRouteTargetRef(httpRouteKey.Name, nil),
		}
		return attachment, nil
	}

	coveredByRule := make(map[int]map[int]struct{}, len(httpRouteCtx.Spec.Rules))
	for _, idx := range coverage {
		if idx.Rule < 0 || idx.Rule >= len(httpRouteCtx.Spec.Rules) || idx.Backend < 0 {
			continue
		}
		if _, ok := coveredByRule[idx.Rule]; !ok {
			coveredByRule[idx.Rule] = map[int]struct{}{}
		}
		coveredByRule[idx.Rule][idx.Backend] = struct{}{}
	}

	for ruleIdx, rule := range httpRouteCtx.Spec.Rules {
		backendCount := len(rule.BackendRefs)
		if backendCount == 0 {
			continue
		}

		validCoveredBackends := 0
		if backends, ok := coveredByRule[ruleIdx]; ok {
			for backendIdx := range backends {
				if backendIdx >= backendCount {
					continue
				}
				validCoveredBackends++
			}
		}

		switch {
		case validCoveredBackends == 0:
			continue
		case validCoveredBackends == backendCount:
			attachment.CoveredRuleIdxs[ruleIdx] = struct{}{}
		default:
			ruleName := ruleSectionName(rule, ruleIdx)
			return trafficPolicyAttachment{}, field.Invalid(
				field.NewPath("emitter", "agentgateway", "AgentgatewayPolicy"),
				policyName,
				fmt.Sprintf(
					"policy only applies to a subset of backendRefs within HTTPRoute rule %q (%d/%d); agentgateway can target whole HTTPRoute rules via targetRefs.sectionName, but cannot attach traffic policy to only some backendRefs within a rule",
					ruleName,
					validCoveredBackends,
					backendCount,
				),
			)
		}
	}

	if len(attachment.CoveredRuleIdxs) == 0 {
		return trafficPolicyAttachment{}, field.Invalid(
			field.NewPath("emitter", "agentgateway", "AgentgatewayPolicy"),
			policyName,
			"policy did not resolve to any covered HTTPRoute rules",
		)
	}

	if len(attachment.CoveredRuleIdxs) == len(httpRouteCtx.Spec.Rules) {
		attachment.TargetRefs = []shared.LocalPolicyTargetReferenceWithSectionName{
			httpRouteTargetRef(httpRouteKey.Name, nil),
		}
		return attachment, nil
	}

	ruleIdxs := make([]int, 0, len(attachment.CoveredRuleIdxs))
	for ruleIdx := range attachment.CoveredRuleIdxs {
		ruleIdxs = append(ruleIdxs, ruleIdx)
	}
	sort.Ints(ruleIdxs)

	attachment.TargetRefs = make([]shared.LocalPolicyTargetReferenceWithSectionName, 0, len(ruleIdxs))
	for _, ruleIdx := range ruleIdxs {
		sectionName := ruleSectionName(httpRouteCtx.Spec.Rules[ruleIdx], ruleIdx)
		attachment.TargetRefs = append(
			attachment.TargetRefs,
			httpRouteTargetRef(httpRouteKey.Name, &sectionName),
		)
	}

	return attachment, nil
}

func hasFullBackendCoverage(httpRoute gatewayv1.HTTPRoute, coverage []emitterir.PolicyIndex) bool {
	total := numRules(httpRoute)
	if total == 0 || len(coverage) == 0 {
		return true
	}

	validCovered := 0
	for _, idx := range coverage {
		if idx.Rule < 0 || idx.Rule >= len(httpRoute.Spec.Rules) {
			continue
		}
		if idx.Backend < 0 || idx.Backend >= len(httpRoute.Spec.Rules[idx.Rule].BackendRefs) {
			continue
		}
		validCovered++
	}

	return validCovered == total
}

func httpRouteTargetRef(
	routeName string,
	sectionName *gatewayv1.SectionName,
) shared.LocalPolicyTargetReferenceWithSectionName {
	return shared.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
			Group: gatewayv1.Group("gateway.networking.k8s.io"),
			Kind:  gatewayv1.Kind("HTTPRoute"),
			Name:  gatewayv1.ObjectName(routeName),
		},
		SectionName: sectionName,
	}
}

func ruleSectionName(rule gatewayv1.HTTPRouteRule, ruleIdx int) gatewayv1.SectionName {
	if rule.Name != nil && *rule.Name != "" {
		return *rule.Name
	}
	return gatewayv1.SectionName(fmt.Sprintf("rule-%d", ruleIdx))
}
