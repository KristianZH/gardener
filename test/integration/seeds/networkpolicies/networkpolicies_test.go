// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkpolicies

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/gardener/gardener/pkg/apis/garden/v1beta1"
	"github.com/gardener/gardener/pkg/logger"
	. "github.com/gardener/gardener/test/integration/framework"
	. "github.com/gardener/gardener/test/integration/shoots"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	kubeconfig     = flag.String("kubeconfig", "", "the path to the kubeconfig  of the garden cluster that will be used for integration tests")
	shootName      = flag.String("shootName", "", "the name of the shoot we want to test")
	shootNamespace = flag.String("shootNamespace", "", "the namespace name that the shoot resides in")
	logLevel       = flag.String("verbose", "", "verbosity level, when set, logging level will be DEBUG")
	cleanup        = flag.Bool("cleanup", false, "deletes the newly created / existing test shoot after the test suite is done")
)

const (
	InitializationTimeout = 600 * time.Second
	FinalizationTimeout   = 1800 * time.Second
)

func validateFlags() {

	if !StringSet(*kubeconfig) {
		Fail("you need to specify the correct path for the kubeconfig")
	}

	if !FileExists(*kubeconfig) {
		Fail("kubeconfig path does not exist")
	}
}

var _ = Describe("Network Policy Testing", func() {

	// SharedResources are shared between Ginkgo instances
	type SharedResources struct {
		Mirror   string                       `json:"mirror"`
		External string                       `json:"external"`
		Policies []networkingv1.NetworkPolicy `json:"policies"`
	}

	var (
		shootGardenerTest   *ShootGardenerTest
		shootTestOperations *GardenerTestOperation
		shootAppTestLogger  *logrus.Logger
		cloudProvider       v1beta1.CloudProvider
		cloudPodInfo        *CloudAwarePodInfo
		sharedResources     SharedResources

		createBusyBox = func(ctx context.Context, npi *NamespacedPodInfo, ports ...corev1.ContainerPort) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      npi.podName,
					Namespace: npi.namespace,
					Labels:    npi.labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						corev1.Container{
							// listen on on container port
							Args:  []string{"nc", "-lk", "-p", fmt.Sprint(npi.port), "-e", "/bin/echo", "-s", "0.0.0.0"},
							Image: "busybox",
							Name:  "busybox",
							Ports: ports,
						},
					},
				},
			}
			err := shootTestOperations.SeedClient.Client().Create(ctx, pod)
			Expect(err).NotTo(HaveOccurred())

			err = shootTestOperations.WaitUntilPodIsRunning(ctx, pod.GetName(), npi.namespace, shootTestOperations.SeedClient)
			Expect(err).NotTo(HaveOccurred())

		}

		getTargetPod = func(ctx context.Context, targetPod *NamespacedPodInfo) *corev1.Pod {
			By(fmt.Sprintf("Checking that target Pod: %s is running", targetPod.containerName))
			err := shootTestOperations.WaitUntilPodIsRunningWithLabels(ctx, targetPod.Selector(), targetPod.namespace, shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Get target pod: %s", targetPod.containerName))
			trgPod, err := shootTestOperations.GetFirstRunningPodWithLabels(ctx, targetPod.Selector(), targetPod.namespace, shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			return trgPod
		}

		establishConnectionToHost = func(ctx context.Context, sourcePod *NamespacedPodInfo, host string, port int32) (io.Reader, error) {
			By(fmt.Sprintf("Checking for source Pod: %s is running", sourcePod.containerName))
			err := shootTestOperations.WaitUntilPodIsRunningWithLabels(ctx, sourcePod.Selector(), sourcePod.namespace, shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Executing connectivity command from %s/%s to %s:%d", sourcePod.namespace, sourcePod.containerName, host, port))
			command := fmt.Sprintf("nc -v -z -w 2 %s %d", host, port)

			return shootTestOperations.PodExecByLabel(ctx, sourcePod.Selector(), "busybox", command, sourcePod.namespace, shootTestOperations.SeedClient)
		}

		assertCanConnect = func(ctx context.Context, sourcePod *NamespacedPodInfo, targetPod *NamespacedPodInfo) {
			pod := getTargetPod(ctx, targetPod)
			r, err := establishConnectionToHost(ctx, sourcePod, pod.Status.PodIP, targetPod.port)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, r).NotTo(BeNil())
		}

		assertCanConnectToHost = func(ctx context.Context, sourcePod *NamespacedPodInfo, host string, port int32) {
			r, err := establishConnectionToHost(ctx, sourcePod, host, port)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, r).NotTo(BeNil())
		}

		assertCannotConnect = func(ctx context.Context, sourcePod *NamespacedPodInfo, targetPod *NamespacedPodInfo) {
			pod := getTargetPod(ctx, targetPod)
			r, err := establishConnectionToHost(ctx, sourcePod, pod.Status.PodIP, targetPod.port)
			ExpectWithOffset(1, err).To(HaveOccurred())
			bytes, err := ioutil.ReadAll(r)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("Connection message is timed out\n")
			ExpectWithOffset(1, string(bytes)).To(ContainSubstring("Connection timed out"))
		}

		assertCannotConnectToHost = func(ctx context.Context, sourcePod *NamespacedPodInfo, host string, port int32) {
			r, err := establishConnectionToHost(ctx, sourcePod, host, port)
			ExpectWithOffset(1, err).To(HaveOccurred())
			bytes, err := ioutil.ReadAll(r)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("Connection message is timed out\n")
			ExpectWithOffset(1, string(bytes)).To(ContainSubstring("Connection timed out"))
		}
	)

	SynchronizedBeforeSuite(func() []byte {

		// todo fix context
		ctx := context.TODO()

		validateFlags()
		shootAppTestLogger = logger.AddWriter(logger.NewLogger(*logLevel), GinkgoWriter)

		if StringSet(*shootName) {
			var err error
			shootGardenerTest, err = NewShootGardenerTest(*kubeconfig, nil, shootAppTestLogger)
			Expect(err).NotTo(HaveOccurred())

			shoot := &v1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Namespace: *shootNamespace, Name: *shootName}}
			shootTestOperations, err = NewGardenTestOperation(ctx, shootGardenerTest.GardenClient, shootAppTestLogger, shoot)
			Expect(err).NotTo(HaveOccurred())
		}
		var err error
		cloudProvider, err = shootTestOperations.GetCloudProvider()
		Expect(err).NotTo(HaveOccurred())

		fmt.Println("EXECUTED")
		cloudPodInfo = &CloudAwarePodInfo{cloudProvider}

		By("Creating namespace for Ingress testing")
		ns, err := shootTestOperations.SeedClient.CreateNamespace(
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "gardener-e2e-network-policies-",
					Labels: map[string]string{
						"gardener-e2e-test": "networkpolicies",
					},
				},
			}, true)

		Expect(err).NotTo(HaveOccurred())

		sharedResources.External = ns.GetName()

		By("Creating mirror namespace for pod2pod network testing")
		mirrorNamespace, err := shootTestOperations.SeedClient.CreateNamespace(
			&corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "gardener-e2e-mirror-network-policies-",
					Labels: map[string]string{
						"gardener-e2e-test": "networkpolicies",
					},
				},
			}, true)
		Expect(err).NotTo(HaveOccurred())

		sharedResources.Mirror = mirrorNamespace.GetName()

		By(fmt.Sprintf("Getting all network policies in namespace %q", shootTestOperations.ShootSeedNamespace()))
		list := &networkingv1.NetworkPolicyList{}
		err = shootTestOperations.SeedClient.Client().List(ctx, &client.ListOptions{Namespace: shootTestOperations.ShootSeedNamespace()}, list)
		Expect(err).ToNot(HaveOccurred())

		sharedResources.Policies = list.Items

		for _, netPol := range sharedResources.Policies {
			cpy := &networkingv1.NetworkPolicy{}
			cpy.Name = netPol.Name
			cpy.Namespace = sharedResources.Mirror
			cpy.Spec = *netPol.Spec.DeepCopy()
			err = shootTestOperations.SeedClient.Client().Create(ctx, cpy)
			Expect(err).NotTo(HaveOccurred())
		}

		var wg sync.WaitGroup
		wg.Add(len(ListPodsInfo()))

		for _, pi := range ListPodsInfo() {
			pi := pi
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				pod, err := shootTestOperations.GetFirstRunningPodWithLabels(ctx, pi.Selector(), shootTestOperations.ShootSeedNamespace(), shootTestOperations.SeedClient)
				Expect(err).NotTo(HaveOccurred())
				cpy := *pi
				cpy.labels = pod.Labels
				By(fmt.Sprintf("Mirroring Pod %s to namespace %s", cpy.labels.String(), sharedResources.Mirror))

				containerPorts := []corev1.ContainerPort{}

				for _, container := range pod.Spec.Containers {
					if len(container.Ports) > 0 {
						containerPorts = append(containerPorts, container.Ports...)
					}
				}
				createBusyBox(ctx, NewNamespacedPodInfo(&cpy, sharedResources.Mirror), containerPorts...)
			}()
		}
		wg.Wait()

		createBusyBox(ctx, NewNamespacedPodInfo(BusyboxInfo, ns.GetName()))

		b, err := json.Marshal(sharedResources)
		Expect(err).NotTo(HaveOccurred())

		return b
	}, func(data []byte) {

		ctx := context.TODO()

		sr := &SharedResources{}
		err := json.Unmarshal(data, sr)
		Expect(err).NotTo(HaveOccurred())

		validateFlags()
		shootAppTestLogger = logger.AddWriter(logger.NewLogger(*logLevel), GinkgoWriter)

		if StringSet(*shootName) {
			var err error
			shootGardenerTest, err = NewShootGardenerTest(*kubeconfig, nil, shootAppTestLogger)
			Expect(err).NotTo(HaveOccurred())

			shoot := &v1beta1.Shoot{ObjectMeta: metav1.ObjectMeta{Namespace: *shootNamespace, Name: *shootName}}
			shootTestOperations, err = NewGardenTestOperation(ctx, shootGardenerTest.GardenClient, shootAppTestLogger, shoot)
			Expect(err).NotTo(HaveOccurred())
		}

		cloudProvider, err = shootTestOperations.GetCloudProvider()
		Expect(err).NotTo(HaveOccurred())

		sharedResources = *sr

	})
	SynchronizedAfterSuite(func() {

		ctx := context.TODO()

		namespaces := &corev1.NamespaceList{}
		selector := &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(labels.Set{
				"gardener-e2e-test": "networkpolicies",
			}),
		}
		err := shootTestOperations.SeedClient.Client().List(ctx, selector, namespaces)
		Expect(err).NotTo(HaveOccurred())

		for _, ns := range namespaces.Items {
			err = shootTestOperations.SeedClient.Client().Delete(ctx, &ns)
			if err != nil && !errors.IsConflict(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		}
	}, func() {

	})

	Context("Components are selected by correct policies", func() {
		const (
			timeout = 10 * time.Second
		)
		var (
			assertMatchAllPolicies = func(podInfo *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {

					matched := sets.NewString()
					var podLabelSet labels.Set

					By(fmt.Sprintf("Getting first running pod with selectors %q in namespace %q", podInfo.labels, shootTestOperations.ShootSeedNamespace()))
					pod, err := shootTestOperations.GetFirstRunningPodWithLabels(ctx, podInfo.Selector(), shootTestOperations.ShootSeedNamespace(), shootTestOperations.SeedClient)
					podLabelSet = pod.GetLabels()
					Expect(err).NotTo(HaveOccurred())

					for _, netPol := range sharedResources.Policies {
						netPolSelector, err := metav1.LabelSelectorAsSelector(&netPol.Spec.PodSelector)
						Expect(err).NotTo(HaveOccurred())

						if netPolSelector.Matches(podLabelSet) {
							matched.Insert(netPol.GetName())
						}
					}
					By(fmt.Sprintf("Matching actual network policies against expected %s", podInfo.expectedPolicies.List()))
					Expect(matched.List()).Should(ConsistOf(podInfo.expectedPolicies.List()))
				}
			}
		)
		CIt("kube-apiserver", assertMatchAllPolicies(KubeAPIServerInfo), timeout)
		// TODO: All those functions should recieve a provider function
		CIt("kube-controller-manager", func(ctx context.Context) {
			assertMatchAllPolicies(cloudPodInfo.KubeControllerManager())(ctx)
		}, timeout)
		CIt("etcd-main", assertMatchAllPolicies(EtcdMainInfo), timeout)
		CIt("etcd-events", assertMatchAllPolicies(EtcdEventsInfo), timeout)
		CIt("cloud-controller-manager", assertMatchAllPolicies(CloudControllerManagerInfo), timeout)
		CIt("elasticsearch", assertMatchAllPolicies(ElasticSearchInfo), timeout)
		CIt("grafana", assertMatchAllPolicies(GrafanaInfo), timeout)
		CIt("kibana", assertMatchAllPolicies(KibanaInfo), timeout)
		CIt("kube-scheduler", assertMatchAllPolicies(KubeSchedulerInfo), timeout)
		CIt("kube-state-metrics-shoot", assertMatchAllPolicies(KubeStateMetricsShootInfo), timeout)
		CIt("kube-state-metrics-seed", assertMatchAllPolicies(KubeStateMetricsSeedInfo), timeout)
		CIt("machine-controller-manager", assertMatchAllPolicies(MachineControllerManagerInfo), timeout)
		CIt("prometheus", assertMatchAllPolicies(PrometheusInfo), timeout)
	})

	Context("Old Deprecated policies are removed", func() {

		const (
			deprecatedKubeAPIServerPolicy = "kube-apiserver-default"
			deprecatedMetadataAppPolicy   = "cloud-metadata-service-deny-blacklist-app"
			deprecatedMetadataRolePolicy  = "cloud-metadata-service-deny-blacklist-role"
			timeout                       = 10 * time.Second
		)
		var (
			assertPolicyIsGone = func(policyName string) func(ctx context.Context) {
				return func(ctx context.Context) {
					By(fmt.Sprintf("Getting network policy %q in namespace %q", policyName, shootTestOperations.ShootSeedNamespace()))
					getErr := shootTestOperations.SeedClient.Client().Get(ctx, types.NamespacedName{Name: policyName, Namespace: shootTestOperations.ShootSeedNamespace()}, &networkingv1.NetworkPolicy{})
					Expect(getErr).To(HaveOccurred())
					By("error is NotFound")
					Expect(errors.IsNotFound(getErr)).To(BeTrue())
				}
			}
		)

		CIt(deprecatedKubeAPIServerPolicy, assertPolicyIsGone(deprecatedKubeAPIServerPolicy), timeout)
		CIt(deprecatedMetadataAppPolicy, assertPolicyIsGone(deprecatedMetadataAppPolicy), timeout)
		CIt(deprecatedMetadataRolePolicy, assertPolicyIsGone(deprecatedMetadataRolePolicy), timeout)

	})

	Context("Ingress from other namespaces", func() {
		var (
			NetworkPolicyTimeout = 30 * time.Second

			assertConnectivity = func(targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCanConnect(ctx, NewNamespacedPodInfo(BusyboxInfo, sharedResources.External), NewNamespacedPodInfo(targetPod, shootTestOperations.ShootSeedNamespace()))
				}
			}

			assertThereIsNoConnectivity = func(targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCannotConnect(ctx, NewNamespacedPodInfo(BusyboxInfo, sharedResources.External), NewNamespacedPodInfo(targetPod, shootTestOperations.ShootSeedNamespace()))
				}
			}
		)

		CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)

		CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)
	})

	Context("Mirrored pods", func() {

		var (
			allSources = []Source{
				{KubeAPIServerInfo, []*PodInfo{EtcdMainInfo, EtcdEventsInfo}},
				{EtcdMainInfo, nil},
				{EtcdEventsInfo, nil},
				{CloudControllerManagerInfo, []*PodInfo{KubeAPIServerInfo}},
				{ElasticSearchInfo, nil},
				{GrafanaInfo, []*PodInfo{PrometheusInfo}},
				{KibanaInfo, []*PodInfo{ElasticSearchInfo}},
				{AddonManagerInfo, []*PodInfo{KubeAPIServerInfo}},
				{cloudPodInfo.KubeControllerManager(), []*PodInfo{KubeAPIServerInfo}},
				{KubeSchedulerInfo, []*PodInfo{KubeAPIServerInfo}},
				{KubeStateMetricsShootInfo, []*PodInfo{KubeAPIServerInfo}},
				{KubeStateMetricsSeedInfo, nil},
				{MachineControllerManagerInfo, []*PodInfo{KubeAPIServerInfo}},
				{PrometheusInfo, []*PodInfo{
					KubeAPIServerInfo,
					EtcdMainInfo,
					EtcdEventsInfo,
					CloudControllerManagerInfo,
					cloudPodInfo.KubeControllerManager(),
					KubeSchedulerInfo,
					KubeStateMetricsShootInfo,
					KubeStateMetricsSeedInfo,
					MachineControllerManagerInfo,
				}},
			}
			NetworkPolicyTimeout = 30 * time.Second
		)

		// CIt("should connect to external sources", func(ctx context.Context) {
		// 	assertCanConnectToHost(ctx, NewNamespacedPodInfo(KubeAPIServerInfo, sharedResources.Mirror), "kubernetes.default", 443)
		// }, NetworkPolicyTimeout)

		for _, s := range allSources {
			s := s
			Context(s.Pod.podName, func() {

				for _, t := range s.ToTargets() {
					t := t
					if t.ShouldAllow {
						CIt(fmt.Sprintf("should allow connectivity to %s", t.TargetPod.podName), func(ctx context.Context) {
							assertCanConnect(ctx, NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), NewNamespacedPodInfo(t.TargetPod, sharedResources.Mirror))
						}, NetworkPolicyTimeout)
					} else {
						CIt(fmt.Sprintf("should block connectivity to %s", t.TargetPod.podName), func(ctx context.Context) {
							assertCannotConnect(ctx, NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), NewNamespacedPodInfo(t.TargetPod, sharedResources.Mirror))
						}, NetworkPolicyTimeout)
					}
				}

				for _, h := range s.ToHosts(cloudProvider) {
					h := h
					if h.ShouldAllow {
						CIt(fmt.Sprintf("should allow connectivity to %q (%s:%d)", h.Description, h.HostName, h.Port), func(ctx context.Context) {
							assertCanConnectToHost(ctx, NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), h.HostName, h.Port)
						}, NetworkPolicyTimeout)
					} else {
						CIt(fmt.Sprintf("should block connectivity to %q (%s:%d)", h.Description, h.HostName, h.Port), func(ctx context.Context) {
							assertCannotConnectToHost(ctx, NewNamespacedPodInfo(s.Pod, sharedResources.Mirror), h.HostName, h.Port)
						}, NetworkPolicyTimeout)
					}
				}

			})
		}
	})
})
