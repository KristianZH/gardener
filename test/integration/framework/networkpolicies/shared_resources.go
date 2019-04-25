package networkpolicies

import (
	networkingv1 "k8s.io/api/networking/v1"
)

// SharedResources are shared between Ginkgo Nodes.
type SharedResources struct {
	Mirror     string                       `json:'mirror'`
	External   string                       `json:'external'`
	SeedNodeIP string                       `json:'seedNodeIP'`
	Policies   []networkingv1.NetworkPolicy `json:'policies'`
}
