package glooedge

// VirtualService represents a Gloo Edge VirtualService CRD
type VirtualService struct {
	Name      string
	Namespace string
	Spec      VirtualServiceSpec
}

type VirtualServiceSpec struct {
	Hosts       []string
	VirtualHost VirtualHost
}

type VirtualHost struct {
	Routes []Route
}

type Route struct {
	Matchers   []Matcher
	RouteAction RouteAction
}

type Matcher struct {
	Prefix string
}

type RouteAction struct {
	Single SingleUpstream
}

type SingleUpstream struct {
	Upstream Upstream
}

type Upstream struct {
	Name      string
	Namespace string
}