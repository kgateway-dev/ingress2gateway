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

package ingressnginx

import (
	"strings"

	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
)

const nginxRewriteTargetAnnotation = "nginx.ingress.kubernetes.io/rewrite-target"

// rewriteTargetFeature parses the nginx.ingress.kubernetes.io/rewrite-target annotation.
//
// Semantics:
//   - Per ingress, if rewrite-target is present and non-empty, store it in Policy.RewriteTarget.
//   - Coverage is tracked via RuleBackendSources in the normal way.
//   - For a host-group (merged HTTPRoute), RegexForcedByRewrite is true if ANY ingress has rewrite-target present,
//     and RegexLocationForHost is OR'd to true.
func rewriteTargetFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Per-Ingress rewrite target value.
	perIngress := map[types.NamespacedName]string{}

	for i := range ingresses {
		ing := &ingresses[i]
		anns := ing.Annotations
		if anns == nil {
			continue
		}
		raw, ok := anns[nginxRewriteTargetAnnotation]
		if !ok {
			continue
		}
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}
		perIngress[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}] = val
	}

	if len(perIngress) == 0 {
		return errs
	}

	// Map per-Ingress rewrite target onto HTTPRoute policies using RuleBackendSources.
	ruleGroups := common.GetRuleGroups(ingresses)
	for _, rg := range ruleGroups {
		routeKey := types.NamespacedName{
			Namespace: rg.Namespace,
			Name:      common.RouteName(rg.Name, rg.Host),
		}

		httpCtx, ok := ir.HTTPRoutes[routeKey]
		if !ok {
			continue
		}

		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &providerir.IngressNginxHTTPRouteIR{
				Policies: map[string]providerir.Policy{},
			}
		}
		if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]providerir.Policy{}
		}

		// host-scoped: any rewrite-target forces regex mode for host.
		anyRewrite := false
		for _, r := range rg.Rules {
			ing := r.Ingress
			if _, ok := perIngress[types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}]; ok {
				anyRewrite = true
				break
			}
		}
		if anyRewrite {
			httpCtx.ProviderSpecificIR.IngressNginx.RegexForcedByRewrite = true
			if httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost == nil {
				httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost = ptr.To(true)
			} else {
				*httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost =
					*httpCtx.ProviderSpecificIR.IngressNginx.RegexLocationForHost || true
			}
		}

		// policy-scoped: attach rewrite target to each ingress policy with coverage.
		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}

				ingKey := types.NamespacedName{Namespace: src.Ingress.Namespace, Name: src.Ingress.Name}
				rt, ok := perIngress[ingKey]
				if !ok {
					continue
				}

				p := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name]
				p.RewriteTarget = ptr.To(rt)
				p = p.AddRuleBackendSources([]providerir.PolicyIndex{{Rule: ruleIdx, Backend: backendIdx}})
				httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingKey.Name] = p
			}
		}

		ir.HTTPRoutes[routeKey] = httpCtx
	}

	return errs
}
