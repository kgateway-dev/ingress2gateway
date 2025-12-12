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
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/intermediate"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

// validateRegexCookiePath enforces if regex location modifier is enabled for host
// AND affinity=cookie is used by an ingress, then session-cookie-path must be set
// (cookie paths do not support regex).
//
// **Note:** This validation should be in IR package but keeping separate to avoid
//	         polluting core IR package with downstream logic.
func validateRegexCookiePath(ir *intermediate.IR) field.ErrorList {
	var errs field.ErrorList

	for _, httpCtx := range ir.HTTPRoutes {
		ing := httpCtx.ProviderSpecificIR.IngressNginx
		if ing == nil || ing.RegexLocationForHost == nil || !*ing.RegexLocationForHost {
			continue
		}
		if ing.Policies == nil {
			continue
		}
		for ingressName, pol := range ing.Policies {
			if pol.SessionAffinity == nil {
				continue
			}
			if pol.SessionAffinity.CookiePath == "" {
				errs = append(errs, field.Invalid(
					field.NewPath("ingress", ingressName, "metadata", "annotations").Key("nginx.ingress.kubernetes.io/session-cookie-path"),
					"",
					"session-cookie-path must be set when cookie affinity is used with regex location matching (use-regex or rewrite-target forces regex)",
				))
			}
		}
	}

	return errs
}
