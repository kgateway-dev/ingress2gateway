/*
Copyright 2024 The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Emitter struct{}

func NewEmitter(conf *i2gw.EmitterConf) i2gw.Emitter {
	return &Emitter{}
}

func init() {
	i2gw.EmitterConstructorByName["kgateway"] = NewEmitter
}

// Emit converts EmitterIR to GatewayResources
// This is a simple pass-through for now that uses the standard conversion
func (e *Emitter) Emit(ir emitterir.EmitterIR) (i2gw.GatewayResources, field.ErrorList) {
	return utils.ToGatewayResources(ir)
}
