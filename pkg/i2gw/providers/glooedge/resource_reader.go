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
package glooedge

import (
	"context"
	"fmt"

	"github.com/kgateway-dev/ingress2gateway/pkg/i2gw"
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

	virtualServices, err := r.readVirtualServicesFromCluster(ctx)
	if err != nil {
		return nil, err
	}

	for _, vs := range virtualServices {
		storage.addVirtualService(vs)
	}

	return storage, nil
}

func (r *resourceReader) readResourcesFromFile(filename string) (*storage, error) {
	storage := newResourcesStorage()

	virtualServices, err := r.readVirtualServicesFromFile(filename)
	if err != nil {
		return nil, err
	}

	for _, vs := range virtualServices {
		storage.addVirtualService(vs)
	}

	return storage, nil
}

func (r *resourceReader) readVirtualServicesFromCluster(ctx context.Context) ([]*VirtualService, error) {
	var unstructuredList unstructured.UnstructuredList
	unstructuredList.SetGroupVersionKind(versionKind)

	err := r.conf.Client.List(ctx, &unstructuredList)
	if err != nil {
		return nil, fmt.Errorf("failed to list VirtualServices from cluster: %w", err)
	}

	var virtualServices []*VirtualService
	for _, u := range unstructuredList.Items {
		vs, err := unstructuredToVirtualService(&u, r.conf.Namespace)
		if err != nil {
			return nil, err
		}
		virtualServices = append(virtualServices, vs)
	}

	return virtualServices, nil
}

func (r *resourceReader) readVirtualServicesFromFile(filename string) ([]*VirtualService, error) {
	unstructuredObjects, err := readObjectsFromFile(filename, r.conf.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to read objects from file: %w", err)
	}

	var virtualServices []*VirtualService
	for _, u := range unstructuredObjects {
		if u.GroupVersionKind().Kind == "VirtualService" {
			vs, err := unstructuredToVirtualService(u, r.conf.Namespace)
			if err != nil {
				return nil, err
			}
			virtualServices = append(virtualServices, vs)
		}
	}

	return virtualServices, nil
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

	// Extract hosts
	hostsRaw, ok := spec["hosts"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid hosts in VirtualService %s/%s", namespace, u.GetName())
	}
	var hosts []string
	for _, h := range hostsRaw {
		hosts = append(hosts, h.(string))
	}

	// Extract virtualHost
	vhRaw, ok := spec["virtualHost"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid virtualHost in VirtualService %s/%s", namespace, u.GetName())
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
				if prefix, ok := matcherMap["prefix"].(string); ok {
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