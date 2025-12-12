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
	"fmt"
	"strings"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

const backendProtocolAnnotation = "nginx.ingress.kubernetes.io/backend-protocol"

// backendProtocolFeature is a FeatureParser that projects the
// backend-protocol annotation into the ingress-nginx ProviderSpecificIR.
//
// Semantics:
//   - Only GRPC/GRPCS are currently supported and are mapped to Backend.Protocol = grpc.
//   - HTTP/HTTPS/AUTO_HTTP are treated as the default HTTP/1 behavior and do not set Protocol.
//   - FCGI (and any other unknown values) are reported as invalid.
//   - This feature is independent of service-upstream; it will create IR Backends
//     when needed so that the Kgateway emitter can produce Backend CRs even when
//     service-upstream is not set.
func backendProtocolFeature(
	ingresses []networkingv1.Ingress,
	servicePorts map[types.NamespacedName]map[string]int32,
	ir *intermediate.IR,
) field.ErrorList {
	var errs field.ErrorList

	// Per-Ingress backend protocol derived from backend-protocol.
	ingressProtocols := make(map[types.NamespacedName]intermediate.BackendProtocol, len(ingresses))

	for _, ing := range ingresses {
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

		nsName := types.NamespacedName{Namespace: ing.Namespace, Name: ing.Name}

		switch value {
		case "GRPC", "GRPCS":
			ingressProtocols[nsName] = intermediate.BackendProtocolGRPC
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

	// Map per-Ingress protocol onto HTTPRoute IR using BackendSource.
	for httpKey, httpCtx := range ir.HTTPRoutes {
		// Group BackendSources by source Ingress name+namespace.
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

			ingressName := ingressKey.Name

			existing := httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName]
			if existing.Backends == nil {
				existing.Backends = make(map[types.NamespacedName]intermediate.Backend)
			}

			for _, idx := range idxs {
				if idx.Rule >= len(httpCtx.Spec.Rules) {
					continue
				}
				rule := httpCtx.Spec.Rules[idx.Rule]
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
				if br.BackendRef.Name == "" {
					continue
				}

				svcName := string(br.BackendRef.Name)
				svcKey := types.NamespacedName{
					Namespace: httpKey.Namespace,
					Name:      svcName,
				}

				// Resolve port.
				var port int32
				if br.BackendRef.Port != nil {
					port = int32(*br.BackendRef.Port)
				} else if svcPorts, ok := servicePorts[svcKey]; ok && len(svcPorts) == 1 {
					for _, p := range svcPorts {
						port = p
					}
				}
				if port == 0 {
					// Cannot determine port; skip creating backend metadata.
					continue
				}

				backendName := fmt.Sprintf("%s-service-upstream", svcName)
				backendKey := types.NamespacedName{
					Namespace: httpKey.Namespace,
					Name:      backendName,
				}

				be := existing.Backends[backendKey]
				if be.Name == "" {
					be.Namespace = backendKey.Namespace
					be.Name = backendKey.Name
					be.Port = port
					// Use cluster-local Service DNS by convention.
					be.Host = fmt.Sprintf("%s.%s.svc.cluster.local", svcName, httpKey.Namespace)
				}
				// Always set / override protocol for this Ingress.
				pCopy := proto
				be.Protocol = &pCopy

				existing.Backends[backendKey] = be
			}

			// Record (rule, backend) coverage to allow the emitter
			// to know which backends this policy applies to.
			existing = existing.AddRuleBackendSources(idxs)

			httpCtx.ProviderSpecificIR.IngressNginx.Policies[ingressName] = existing
		}

		// Write back mutated HTTPRouteContext into IR.
		ir.HTTPRoutes[httpKey] = httpCtx
	}

	return errs
}
