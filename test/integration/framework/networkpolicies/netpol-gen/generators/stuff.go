package generators

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/gardener/gardener/test/integration/framework/networkpolicies"
)

func GetRegistry() map[string]networkpolicies.CloudAwarePodInfo {
	x := networkpolicies.AWSPodInfo{}
	typeof := reflect.TypeOf(x)

	fmt.Printf("%s.%s", typeof.PkgPath(), typeof.String())

	var b strings.Builder
	for _, source := range x.ToSources() {
		b.WriteString(fmt.Sprintf(`CIt("should block connectivity from %s", func(ctx context.Context) {`, source.Pod.PodName))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("target := %s\n", prettyPrint(source.Pod)))
		b.WriteString(`
assertCannotConnectToHost(ctx, networkpolicies.NewNamespacedPodInfo(target, sharedResources.Mirror), sharedResources.SeedNodeIP, 10250)
}, 30*time.Second)

`)
	}

	//  fmt.Println(b.String())

	// fmt.Println(prettyPrint(x.ToSources()[0].TargetHosts))

	return map[string]networkpolicies.CloudAwarePodInfo{}
}

func prettyPrint(i interface{}) string {
	// s1 := fmt.Sprintf("%#v", i)
	s1 := strings.ReplaceAll(fmt.Sprintf("%#v", i), ", ", ",\n")
	s2 := strings.ReplaceAll(s1, "{", "{\n")
	s3 := strings.ReplaceAll(s2, "} ", "}\n")
	s4 := strings.ReplaceAll(s3, "[", "[\n")
	s5 := strings.ReplaceAll(s4, "] ", "]\n")

	return s5
}

// func addType()

// Context("egress to Seed nodes", func() {
// 	for _, source := range cloudAwarePodInfo.ToSources() {
// 		podInfo := source.Pod
// 		CIt(fmt.Sprintf("should block connectivity from %s", podInfo.PodName), func(ctx context.Context) {
// 			assertCannotConnectToHost(ctx, networkpolicies.NewNamespacedPodInfo(podInfo, sharedResources.Mirror), sharedResources.SeedNodeIP, 10250)
// 		}, 30*time.Second)
// 	}
// })

// Context("egress for mirrored pods", func() {

// 	var (
// 		NetworkPolicyTimeout = 30 * time.Second
// 	)

// 	for _, s := range cloudAwarePodInfo.ToSources() {
// 		s := s
// 		Context(s.Pod.PodName, func() {

// 			for _, t := range s.TargetPods {
// 				t := t
// 				if !reflect.DeepEqual(t.Pod, *s.Pod) {
// 					CIt(t.ToString(), func(ctx context.Context) {
// 						assertConnectToPod(ctx, networkpolicies.NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), networkpolicies.NewNamespacedPodInfo(&t.Pod, sharedResources.Mirror), t.Allowed)
// 					}, NetworkPolicyTimeout)
// 				}
// 			}

// 			for _, t := range s.TargetHosts {
// 				t := t
// 				CIt(t.ToString(), func(ctx context.Context) {
// 					assertConnectToHost(ctx, networkpolicies.NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), t)
// 				}, NetworkPolicyTimeout)
// 			}
// 		})
// 	}
// })
