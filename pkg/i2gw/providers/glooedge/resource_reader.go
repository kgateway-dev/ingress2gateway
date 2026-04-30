/*
Copyright The Kubernetes Authors.

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
	"context"
	"fmt"
	"io"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw/providers/common"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type resourceReader struct {
	conf *i2gw.ProviderConf
}

func newResourceReader(conf *i2gw.ProviderConf) *resourceReader {
	return &resourceReader{
		conf: conf,
	}
}

func (r *resourceReader) readResourcesFromCluster(ctx context.Context) (*storage, error) {
	storage := newResourcesStorage()

	// Read VirtualServices from cluster
	virtualServices, err := common.ReadVirtualServicesFromCluster(ctx, r.conf.Client)
	if err != nil {
		return nil, err
	}

	for _, u := range virtualServices {
		vs, vsErr := unstructuredToVirtualService(u, r.conf.Namespace)
		if vsErr != nil {
			return nil, vsErr
		}
		storage.addVirtualService(vs)
	}

	// Read Upstreams from cluster
	upstreams, err := readUpstreamsFromCluster(ctx, r.conf.Client)
	if err != nil {
		return nil, err
	}
	for _, upstream := range upstreams {
		storage.addUpstream(upstream)
	}

	return storage, nil
}

func (r *resourceReader) readResourcesFromFile(reader io.Reader) (*storage, error) {
	storage := newResourcesStorage()
	allResources, err := common.ExtractObjectsFromReader(reader, "")
	if err != nil {
		return nil, err
	}
	
	// Separate VirtualServices and Upstreams
	for _, resource := range allResources {
		if resource.GetKind() == "VirtualService" {
			namespace := resource.GetNamespace()
			if namespace == "" {
				namespace = r.conf.Namespace
			}
			vs, vsErr := unstructuredToVirtualService(resource, namespace)
			if vsErr != nil {
				continue
			}
			storage.addVirtualService(vs)
		} else if resource.GetKind() == "Upstream" && resource.GetAPIVersion() == "gloo.solo.io/v1" {
			namespace := resource.GetNamespace()
			if namespace == "" {
				namespace = r.conf.Namespace
			}
			upstream, upErr := unstructuredToUpstream(resource, namespace)
			if upErr != nil {
				continue
			}
			storage.addUpstream(upstream)
		}
	}

	return storage, nil
}

func unstructuredToVirtualService(u *unstructured.Unstructured, defaultNamespace string) (*VirtualService, error) {
	namespace := u.GetNamespace()
	if namespace == "" {
		namespace = defaultNamespace
	}

	// Extract spec
	spec, ok := u.Object["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid VirtualService spec for %s/%s", namespace, u.GetName())
	}

	// Extract virtualHost
	vhRaw, ok := spec["virtualHost"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid virtualHost in VirtualService %s/%s", namespace, u.GetName())
	}

	// Try spec.virtualHost.domains first (real schema)
	domainsRaw, ok := vhRaw["domains"].([]interface{})
	if !ok {
		// Fallback to spec.hosts if domains not found
		hostsRaw, hostsOk := spec["hosts"].([]interface{})
		if !hostsOk {
			return nil, fmt.Errorf("invalid hosts/domains in VirtualService %s/%s", namespace, u.GetName())
		}
		domainsRaw = hostsRaw
	}

	var hosts []string
	for _, h := range domainsRaw {
		hosts = append(hosts, h.(string))
	}

	// Extract routes
	routesRaw, ok := vhRaw["routes"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid routes in VirtualService %s/%s", namespace, u.GetName())
	}

	var routes []Route
	for _, routeRaw := range routesRaw {
		routeMap := routeRaw.(map[string]interface{})

		// Extract matchers
		var matchers []Matcher
		matchersRaw, ok := routeMap["matchers"].([]interface{})
		if ok {
			for _, matcherRaw := range matchersRaw {
				matcherMap := matcherRaw.(map[string]interface{})
				if prefix, prefixOk := matcherMap["prefix"].(string); prefixOk {
					matchers = append(matchers, Matcher{Prefix: prefix})
				}
			}
		}

		// Extract routeAction
		routeActionRaw, ok := routeMap["routeAction"].(map[string]interface{})
		if !ok {
			continue
		}

		singleRaw, ok := routeActionRaw["single"].(map[string]interface{})
		if !ok {
			continue
		}

		upstreamRaw, ok := singleRaw["upstream"].(map[string]interface{})
		if !ok {
			continue
		}

		upstreamName, _ := upstreamRaw["name"].(string)
		upstreamNamespace, _ := upstreamRaw["namespace"].(string)

		routes = append(routes, Route{
			Matchers: matchers,
			RouteAction: RouteAction{
				Single: SingleUpstream{
					Upstream: Upstream{
						Name:      upstreamName,
						Namespace: upstreamNamespace,
					},
				},
			},
		})
	}

	return &VirtualService{
		Name:      u.GetName(),
		Namespace: namespace,
		Spec: VirtualServiceSpec{
			Hosts: hosts,
			VirtualHost: VirtualHost{
				Routes: routes,
			},
		},
	}, nil
}

// unstructuredToUpstream converts an unstructured Upstream to typed Upstream
func unstructuredToUpstream(u *unstructured.Unstructured, defaultNamespace string) (*Upstream, error) {
	namespace := u.GetNamespace()
	if namespace == "" {
		namespace = defaultNamespace
	}

	// Extract spec
	spec, ok := u.Object["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid Upstream spec for %s/%s", namespace, u.GetName())
	}

	upstream := &Upstream{
		Name:      u.GetName(),
		Namespace: namespace,
	}

	// Extract kube configuration (service details)
	kubeRaw, ok := spec["kube"].(map[string]interface{})
	if ok {
		if svcName, ok := kubeRaw["serviceName"].(string); ok {
			upstream.ServiceName = svcName
		}
		if svcNs, ok := kubeRaw["serviceNamespace"].(string); ok {
			upstream.ServiceNamespace = svcNs
		} else {
			upstream.ServiceNamespace = namespace
		}
		
		// Try multiple types for port
		if portVal, ok := kubeRaw["servicePort"]; ok {
			switch v := portVal.(type) {
			case float64:
				upstream.ServicePort = int32(v)
			case int:
				upstream.ServicePort = int32(v)
			case int64:
				upstream.ServicePort = int32(v)
			case string:
				var port int32
				_, err := fmt.Sscanf(v, "%d", &port)
				if err == nil {
					upstream.ServicePort = port
				}
			}
		}
	}

	return upstream, nil
}

// readUpstreamsFromCluster reads Upstream resources from cluster
// TODO: Implement cluster reading for Upstreams using dynamic client
// https://github.com/kgateway-dev/ingress2gateway/issues/112
func readUpstreamsFromCluster(ctx context.Context, client interface{}) ([]*Upstream, error) {
	// TODO: Implement cluster reading for Upstreams using dynamic client
	// For now, return empty list as fallback
	// This would use client.Resource(upstreamGVR).List(ctx, metav1.ListOptions{})
	return []*Upstream{}, nil
}
