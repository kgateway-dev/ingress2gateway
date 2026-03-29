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