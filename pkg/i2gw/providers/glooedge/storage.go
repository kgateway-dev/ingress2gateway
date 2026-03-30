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

package glooedge

import (
	"k8s.io/apimachinery/pkg/types"
)

type storage struct {
	VirtualServices map[types.NamespacedName]*VirtualService
}

func newResourcesStorage() *storage {
	return &storage{
		VirtualServices: make(map[types.NamespacedName]*VirtualService),
	}
}

func (s *storage) addVirtualService(vs *VirtualService) {
	key := types.NamespacedName{
		Namespace: vs.Namespace,
		Name:      vs.Name,
	}
	s.VirtualServices[key] = vs
}
