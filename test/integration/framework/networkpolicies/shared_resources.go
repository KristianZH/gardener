package networkpolicies

import (
	"github.com/gardener/gardener/pkg/apis/garden/v1beta1"
	networkingv1 "k8s.io/api/networking/v1"
)

// SharedResources are shared between Ginkgo Nodes.
type SharedResources struct {
	Mirror        string                       `json:'mirror'`
	External      string                       `json:'external'`
	SeedNodeIP    string                       `json:'seedNodeIP'`
	Policies      []networkingv1.NetworkPolicy `json:'policies'`
	CloudProvider v1beta1.CloudProvider        `json:'cloudProvider'`
}
