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

package ingressnginx

import (
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	providerir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const backendProtocolAnnotation = "nginx.ingress.kubernetes.io/backend-protocol"

// backendProtocolFeature is a FeatureParser that projects the
// backend-protocol annotation into the ingress-nginx ProviderSpecificIR.
//
// Semantics:
//   - Only GRPC/GRPCS are currently supported and are mapped to Policy.BackendProtocol = grpc.
//   - HTTP/HTTPS/AUTO_HTTP are treated as the default HTTP/1 behavior and do not set BackendProtocol.
//   - FCGI (and any other unknown values) are reported as invalid.
//   - Coverage is recorded via Policy.RuleBackendSources so the emitter can apply protocol selection
//     only to the specific backends contributed by the annotated Ingress.
func backendProtocolFeature(
	ingresses []networkingv1.Ingress,
	_ map[types.NamespacedName]map[string]int32,
	ir *providerir.ProviderIR,
) field.ErrorList {
	var errs field.ErrorList

	// Per-Ingress backend protocol derived from backend-protocol.
	ingressProtocols := make(map[types.NamespacedName]intermediate.BackendProtocol, len(ingresses))

	for i := range ingresses {
		ing := &ingresses[i]
		if ing.Annotations == nil {
			continue
		}

		raw, ok := ing.Annotations[backendProtocolAnnotation]
		if !ok {
			continue
		}

		value := strings.TrimSpace(strings.ToUpper(raw))
		if value == "" {
			continue
		}

		ingKey := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}

		switch value {
		case "GRPC", "GRPCS":
			ingressProtocols[ingKey] = intermediate.BackendProtocolGRPC
		case "HTTP", "HTTPS", "AUTO_HTTP":
			// Default HTTP/1.x behavior; nothing to emit into IR here.
			continue
		default:
			// Values like FCGI/AJP are not supported in Kgateway/Envoy today.
			errs = append(errs, field.Invalid(
				field.NewPath("ingress", ing.Namespace, ing.Name, "metadata", "annotations").Key(backendProtocolAnnotation),
				raw,
				`unsupported backend-protocol; only "GRPC" and "GRPCS" are mapped by the Kgateway emitter`,
			))
			continue
		}
	}

	if len(ingressProtocols) == 0 {
		return errs
	}

	// Map per-Ingress protocol onto HTTPRoute IR using RuleBackendSources.
	for httpKey, httpCtx := range ir.HTTPRoutes {
		// Group backend indices by source Ingress (namespace/name).
		srcByIngress := map[types.NamespacedName][]intermediate.PolicyIndex{}

		for ruleIdx, perRule := range httpCtx.RuleBackendSources {
			for backendIdx, src := range perRule {
				if src.Ingress == nil {
					continue
				}
				ingressKey := types.NamespacedName{
					Namespace: src.Ingress.Namespace,
					Name:      src.Ingress.Name,
				}
				srcByIngress[ingressKey] = append(
					srcByIngress[ingressKey],
					intermediate.PolicyIndex{Rule: ruleIdx, Backend: backendIdx},
				)
			}
		}

		if len(srcByIngress) == 0 {
			continue
		}

		// Ensure provider-specific IR is initialized.
		if httpCtx.ProviderSpecificIR.IngressNginx == nil {
			httpCtx.ProviderSpecificIR.IngressNginx = &intermediate.IngressNginxHTTPRouteIR{
				Policies: map[string]intermediate.Policy{},
			}
		} else if httpCtx.ProviderSpecificIR.IngressNginx.Policies == nil {
			httpCtx.ProviderSpecificIR.IngressNginx.Policies = map[string]intermediate.Policy{}
		}

		for ingressKey, idxs := range srcByIngress {
			proto, ok := ingressProtocols[ingressKey]
			if !ok {
				continue
			}

			// NOTE: Provider policies are keyed by Ingress name.
			ingressName := ingressKey.Name

			existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName]

			pCopy := proto
			existing.BackendProtocol = &pCopy

			// Record coverage so the emitter can apply protocol selection to the right backends.
			existing = existing.AddRuleBackendSources(idxs)

			httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName] = existing
		}

		// Write back mutated HTTPRouteContext into IR.
		ir.HTTPRoutes[httpKey] = httpCtx
	}

	return errs
}
