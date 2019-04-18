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
		sharedResources     SharedResources

		createBusyBox = func(ctx context.Context, npi *NamespacedPodInfo) {
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
							Ports: []corev1.ContainerPort{{ContainerPort: npi.port}},
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
			return shootTestOperations.PodExecByLabel(ctx, sourcePod.Selector(), "busybox", fmt.Sprintf("nc -v -z -w 2 %s %d", host, port), sourcePod.namespace, shootTestOperations.SeedClient)
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
				defer wg.Done()
				pod, err := shootTestOperations.GetFirstRunningPodWithLabels(ctx, pi.Selector(), shootTestOperations.ShootSeedNamespace(), shootTestOperations.SeedClient)
				Expect(err).NotTo(HaveOccurred())
				cpy := pi
				cpy.labels = pod.Labels
				By(fmt.Sprintf("Mirroring Pod %s to namespace %s", cpy.labels.String(), sharedResources.Mirror))
				createBusyBox(ctx, NewNamespacedPodInfo(&cpy, sharedResources.Mirror))
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

		// if true {
		// 	return
		// }
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
		CIt("kube-controller-manager", func(ctx context.Context) {
			podInfo := *KubeControllerManagerInfo
			if cloudProvider != v1beta1.CloudProviderAlicloud {
				newPolicies := sets.NewString(
					"allow-to-public-except-private-and-metadata",
					"allow-to-private-except-metadata-cluster",
					"allow-from-prometheus",
					"allow-to-dns",
					"allow-to-metadata",
					"allow-to-shoot-apiserver",
					"deny-all",
				)
				podInfo.expectedPolicies = newPolicies
			}
			assertMatchAllPolicies(&podInfo)(ctx)
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
			NetworkPolicyTimeout = 30 * time.Second

			assertConnectivity = func(sourcePod *PodInfo, targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCanConnect(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), NewNamespacedPodInfo(targetPod, sharedResources.Mirror))
				}
			}

			assertThereIsNoConnectivity = func(sourcePod *PodInfo, targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCannotConnect(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), NewNamespacedPodInfo(targetPod, sharedResources.Mirror))
				}
			}

			assertCannotConnectToMetadataService = func(sourcePod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					var host string
					if cloudProvider == v1beta1.CloudProviderAlicloud {
						host = "100.100.100.200"
					} else {
						host = "169.254.169.254"
					}
					assertCannotConnectToHost(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), host, 80)
				}
			}

			assertCanConnectToMetadataService = func(sourcePod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					var host string
					if cloudProvider == v1beta1.CloudProviderAlicloud {
						host = "100.100.100.200"
					} else {
						host = "169.254.169.254"
					}
					assertCanConnectToHost(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), host, 80)
				}
			}
		)

		Context("kube-apiserver", func() {

			CIt("should connect to etcd-main", assertConnectivity(KubeAPIServerInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-events", assertConnectivity(KubeAPIServerInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should connect to external sources", func(ctx context.Context) {
				assertCanConnectToHost(ctx, NewNamespacedPodInfo(KubeAPIServerInfo, sharedResources.Mirror), "kubernetes.default", 443)
			}, NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KubeAPIServerInfo), NetworkPolicyTimeout)
		})

		Context("etcd-main", func() {

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(EtcdMainInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdMainInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(EtcdMainInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(EtcdMainInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(EtcdMainInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(EtcdMainInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(EtcdMainInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(EtcdMainInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(EtcdMainInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(EtcdMainInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(EtcdMainInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(EtcdMainInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(EtcdMainInfo), NetworkPolicyTimeout)
		})

		Context("etcd-events", func() {

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(EtcdEventsInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(EtcdEventsInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(EtcdEventsInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(EtcdEventsInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(EtcdEventsInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(EtcdEventsInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(EtcdEventsInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(EtcdEventsInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(EtcdEventsInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(EtcdEventsInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(EtcdEventsInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(EtcdEventsInfo), NetworkPolicyTimeout)
		})

		Context("cloud-controller-manager", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(KubeControllerManagerInfo, KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(CloudControllerManagerInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(CloudControllerManagerInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(CloudControllerManagerInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(CloudControllerManagerInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(CloudControllerManagerInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(CloudControllerManagerInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(CloudControllerManagerInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(CloudControllerManagerInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(CloudControllerManagerInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should connect to metadataService", assertCanConnectToMetadataService(CloudControllerManagerInfo), NetworkPolicyTimeout)
		})

		Context("elasticsearch", func() {

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(ElasticSearchInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(ElasticSearchInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(ElasticSearchInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(ElasticSearchInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(ElasticSearchInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(ElasticSearchInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(ElasticSearchInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(ElasticSearchInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(ElasticSearchInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(ElasticSearchInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(ElasticSearchInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(ElasticSearchInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(ElasticSearchInfo), NetworkPolicyTimeout)
		})

		Context("grafana", func() {

			CIt("should connect to prometheus", assertConnectivity(GrafanaInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(GrafanaInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(GrafanaInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(GrafanaInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(GrafanaInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch", assertThereIsNoConnectivity(GrafanaInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(GrafanaInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(GrafanaInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(GrafanaInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(GrafanaInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(GrafanaInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(GrafanaInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(GrafanaInfo), NetworkPolicyTimeout)
		})

		Context("kibana", func() {

			CIt("should connect to elasticsearch", assertConnectivity(KibanaInfo, ElasticSearchInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KibanaInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(KibanaInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(KibanaInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(KibanaInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(KibanaInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KibanaInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KibanaInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KibanaInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KibanaInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(KibanaInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(KibanaInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KibanaInfo), NetworkPolicyTimeout)
		})

		Context("kube-controller-manager", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(KubeControllerManagerInfo, KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(KubeControllerManagerInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(KubeControllerManagerInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(KubeControllerManagerInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch", assertThereIsNoConnectivity(KubeControllerManagerInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana", assertThereIsNoConnectivity(KubeControllerManagerInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeControllerManagerInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeControllerManagerInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeControllerManagerInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(KubeControllerManagerInfo, PrometheusInfo), NetworkPolicyTimeout)

			if cloudProvider == v1beta1.CloudProviderAlicloud {
				CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KubeControllerManagerInfo), NetworkPolicyTimeout)
			} else {
				CIt("should connect to metadataService", assertCanConnectToMetadataService(KubeControllerManagerInfo), NetworkPolicyTimeout)
			}

		})

		Context("kube-scheduler", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(KubeSchedulerInfo, KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(KubeSchedulerInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(KubeSchedulerInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(KubeSchedulerInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(KubeSchedulerInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(KubeSchedulerInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KubeSchedulerInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeSchedulerInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeSchedulerInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeSchedulerInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(KubeSchedulerInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(KubeSchedulerInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KubeSchedulerInfo), NetworkPolicyTimeout)
		})

		Context("kube-state-metrics-shoot", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(KubeStateMetricsShootInfo, KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(KubeStateMetricsShootInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
		})

		Context("kube-state-metrics-seed", func() {

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
		})

		Context("machine-controller-manager", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(MachineControllerManagerInfo, KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(MachineControllerManagerInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(MachineControllerManagerInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(MachineControllerManagerInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(MachineControllerManagerInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(MachineControllerManagerInfo, KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(MachineControllerManagerInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(MachineControllerManagerInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(MachineControllerManagerInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(MachineControllerManagerInfo, PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(MachineControllerManagerInfo), NetworkPolicyTimeout)
		})

		Context("prometheus", func() {

			CIt("should connect to kube-apiserver", assertConnectivity(PrometheusInfo, KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-main", assertConnectivity(PrometheusInfo, EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-events", assertConnectivity(PrometheusInfo, EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should connect to cloud-controller-manager", assertConnectivity(PrometheusInfo, CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-controller-manager", assertConnectivity(PrometheusInfo, KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-scheduler", assertConnectivity(PrometheusInfo, KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-state-metrics-shoot", assertConnectivity(PrometheusInfo, KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-state-metrics-seed", assertConnectivity(PrometheusInfo, KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should connect to machine-controller-manager", assertConnectivity(PrometheusInfo, MachineControllerManagerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(PrometheusInfo, ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(PrometheusInfo, GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(PrometheusInfo, KibanaInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(PrometheusInfo), NetworkPolicyTimeout)
		})

	})
})
