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
	"strings"

	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/provider_intermediate/ingressnginx"

	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/api/v1alpha1/shared"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// applyBackendTLSPolicy projects the BackendTLS IR policy into one or more
// Kgateway BackendConfigPolicies.
//
// Semantics:
//   - We create at most one BackendConfigPolicy per Service.
//   - That policy's Spec.TLS is configured with client certificates, CA certificates,
//     SNI hostname, and verification settings from the Policy.BackendTLS.
//   - TargetRefs are populated with all core Service backends that this Policy covers
//     (based on RuleBackendSources).
func applyBackendTLSPolicy(
	pol ingressnginx.Policy,
	httpRouteKey types.NamespacedName,
	httpRouteCtx emitterir.HTTPRouteContext,
	backendCfg map[types.NamespacedName]*kgateway.BackendConfigPolicy,
) bool {
	if pol.BackendTLS == nil {
		return false
	}

	backendTLS := pol.BackendTLS

	// Parse secret name (format: "namespace/secretName" or just "secretName")
	secretName := backendTLS.SecretName
	if parts := strings.SplitN(backendTLS.SecretName, "/", 2); len(parts) == 2 {
		secretName = parts[1]
	}

	for _, idx := range pol.RuleBackendSources {
		if idx.Rule >= len(httpRouteCtx.Spec.Rules) {
			continue
		}
		rule := httpRouteCtx.Spec.Rules[idx.Rule]
		if idx.Backend >= len(rule.BackendRefs) {
			continue
		}

		br := rule.BackendRefs[idx.Backend]

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

		// Create or reuse BackendConfigPolicy per Service
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
							Name:  gatewayv1.ObjectName(svcName),
						},
					},
				},
			}
			bcp.SetGroupVersionKind(BackendConfigPolicyGVK)
			backendCfg[svcKey] = bcp
		}

		// Configure TLS settings
		if bcp.Spec.TLS == nil {
			bcp.Spec.TLS = &kgateway.TLS{}
		}

		// Set SNI hostname if specified
		if backendTLS.Hostname != "" {
			bcp.Spec.TLS.Sni = ptr.To(backendTLS.Hostname)
		}

		// Set verification: InsecureSkipVerify is false when verify is on, true when verify is off
		if !backendTLS.Verify {
			bcp.Spec.TLS.InsecureSkipVerify = ptr.To(true)
		} else if secretName != "" {
			// Set secret reference (contains tls.crt, tls.key, and optionally ca.crt)
			bcp.Spec.TLS.SecretRef = &corev1.LocalObjectReference{
				Name: secretName,
			}
		}
	}

	return true
}
