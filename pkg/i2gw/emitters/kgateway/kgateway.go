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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitters/utils"
	implkgateway "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/implementations/kgateway"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func init() {
	i2gw.EmitterConstructorByName["kgateway"] = NewEmitter
}

type Emitter struct{}

// NewEmitter returns a new instance of KgatewayEmitter.
func NewEmitter(_ *i2gw.EmitterConf) i2gw.Emitter {
	return &Emitter{}
}

// Emit converts EmitterIR to Gateway API resources plus kgateway-specific extensions.
func (e *Emitter) Emit(ir emitterir.EmitterIR) (i2gw.GatewayResources, field.ErrorList) {
	gatewayResources, errs := utils.ToGatewayResources(ir)
	if len(errs) > 0 {
		return gatewayResources, errs
	}

	// Set GatewayClassName to "kgateway" for all Gateways
	for key := range gatewayResources.Gateways {
		gateway := gatewayResources.Gateways[key]
		gateway.Spec.GatewayClassName = "kgateway"
		gatewayResources.Gateways[key] = gateway
	}

	// Convert EmitterIR to intermediate.IR format for the existing kgateway emitter
	intermediateIR := convertEmitterIRToIntermediateIR(ir)

	// Use the existing kgateway implementation emitter to generate kgateway-specific resources
	// This may modify intermediateIR (e.g., split HTTPRoutes for SSL redirect)
	implEmitter := implkgateway.NewKgatewayEmitter()
	kgatewayObjs, err := implEmitter.Emit(intermediateIR)
	if err != nil {
		errs = append(errs, field.InternalError(field.NewPath("kgateway"), err))
		return gatewayResources, errs
	}

	// Update GatewayResources HTTPRoutes from the modified intermediateIR
	// This is necessary because the old emitter modifies intermediateIR in place
	// (e.g., splits routes for SSL redirect)
	gatewayResources.HTTPRoutes = make(map[types.NamespacedName]gatewayv1.HTTPRoute)
	for k, v := range intermediateIR.HTTPRoutes {
		gatewayResources.HTTPRoutes[k] = v.HTTPRoute
	}

	// Convert kgateway objects to unstructured and add to GatewayExtensions
	for _, obj := range kgatewayObjs {
		u, err := toUnstructured(obj)
		if err != nil {
			errs = append(errs, field.InternalError(field.NewPath("kgateway"), err))
			continue
		}
		gatewayResources.GatewayExtensions = append(gatewayResources.GatewayExtensions, *u)
	}

	return gatewayResources, errs
}

// convertEmitterIRToIntermediateIR converts EmitterIR to intermediate.IR format
// for compatibility with the existing kgateway implementation emitter.
func convertEmitterIRToIntermediateIR(eir emitterir.EmitterIR) *intermediate.IR {
	ir := &intermediate.IR{
		Gateways:           make(map[types.NamespacedName]intermediate.GatewayContext),
		HTTPRoutes:         make(map[types.NamespacedName]intermediate.HTTPRouteContext),
		Services:           make(map[types.NamespacedName]intermediate.ProviderSpecificServiceIR),
		GatewayClasses:     make(map[types.NamespacedName]gatewayv1.GatewayClass),
		TLSRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.TLSRoute),
		TCPRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.TCPRoute),
		UDPRoutes:          make(map[types.NamespacedName]gatewayv1alpha2.UDPRoute),
		GRPCRoutes:         make(map[types.NamespacedName]gatewayv1.GRPCRoute),
		BackendTLSPolicies: make(map[types.NamespacedName]gatewayv1.BackendTLSPolicy),
		ReferenceGrants:    make(map[types.NamespacedName]gatewayv1beta1.ReferenceGrant),
	}

	// Convert Gateways
	for k, v := range eir.Gateways {
		ir.Gateways[k] = intermediate.GatewayContext{
			Gateway: v.Gateway,
		}
	}

	// Convert HTTPRoutes with IngressNginx data
	for k, v := range eir.HTTPRoutes {
		httpRouteCtx := intermediate.HTTPRouteContext{
			HTTPRoute:          v.HTTPRoute,
			RuleBackendSources: convertBackendSources(v.RuleBackendSources),
		}
		if v.IngressNginx != nil {
			httpRouteCtx.ProviderSpecificIR.IngressNginx = v.IngressNginx
		}
		ir.HTTPRoutes[k] = httpRouteCtx
	}

	// Convert other route types
	for k, v := range eir.GRPCRoutes {
		ir.GRPCRoutes[k] = v.GRPCRoute
	}
	for k, v := range eir.TLSRoutes {
		ir.TLSRoutes[k] = v.TLSRoute
	}
	for k, v := range eir.TCPRoutes {
		ir.TCPRoutes[k] = v.TCPRoute
	}
	for k, v := range eir.UDPRoutes {
		ir.UDPRoutes[k] = v.UDPRoute
	}
	for k, v := range eir.GatewayClasses {
		ir.GatewayClasses[k] = v.GatewayClass
	}
	for k, v := range eir.BackendTLSPolicies {
		ir.BackendTLSPolicies[k] = v.BackendTLSPolicy
	}
	for k, v := range eir.ReferenceGrants {
		ir.ReferenceGrants[k] = v.ReferenceGrant
	}

	return ir
}

// convertBackendSources converts emitterir.BackendSource to intermediate.BackendSource
func convertBackendSources(sources [][]emitterir.BackendSource) [][]intermediate.BackendSource {
	result := make([][]intermediate.BackendSource, len(sources))
	for i, ruleSources := range sources {
		result[i] = make([]intermediate.BackendSource, len(ruleSources))
		for j, src := range ruleSources {
			result[i][j] = intermediate.BackendSource{
				Ingress:        src.Ingress,
				Path:           src.Path,
				DefaultBackend: src.DefaultBackend,
			}
		}
	}
	return result
}

// toUnstructured converts a runtime.Object to unstructured.Unstructured
func toUnstructured(obj runtime.Object) (*unstructured.Unstructured, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: unstructuredObj}, nil
}
