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
	emitterir "github.com/kgateway-dev/ingress2gateway/pkg/i2gw/emitter_intermediate"
)

// uniquePolicyIndices returns a slice of PolicyIndex values with duplicates
// removed. Uniqueness is defined by the (Rule, Backend) pair.
func uniquePolicyIndices(indices []emitterir.PolicyIndex) []emitterir.PolicyIndex {
	if len(indices) == 0 {
		return indices
	}

	seen := make(map[emitterir.PolicyIndex]struct{}, len(indices))
	out := make([]emitterir.PolicyIndex, 0, len(indices))

	for _, idx := range indices {
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}
