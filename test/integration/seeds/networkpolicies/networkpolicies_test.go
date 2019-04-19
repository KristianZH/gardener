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

			sourcePod *PodInfo

			assertConnectivity = func(targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCanConnect(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), NewNamespacedPodInfo(targetPod, sharedResources.Mirror))
				}
			}

			assertThereIsNoConnectivity = func(targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCannotConnect(ctx, NewNamespacedPodInfo(sourcePod, sharedResources.Mirror), NewNamespacedPodInfo(targetPod, sharedResources.Mirror))
				}
			}

			assertCannotConnectToMetadataService = func() func(ctx context.Context) {
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

			assertCanConnectToMetadataService = func() func(ctx context.Context) {
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

			BeforeEach(func() {
				sourcePod = KubeAPIServerInfo
			})

			CIt("should connect to etcd-main", assertConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-events", assertConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should connect to external sources", func(ctx context.Context) {
				assertCanConnectToHost(ctx, NewNamespacedPodInfo(KubeAPIServerInfo, sharedResources.Mirror), "kubernetes.default", 443)
			}, NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("etcd-main", func() {

			BeforeEach(func() {
				sourcePod = EtcdMainInfo
			})

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
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

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("etcd-events", func() {

			BeforeEach(func() {
				sourcePod = EtcdEventsInfo
			})

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
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

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("cloud-controller-manager", func() {

			BeforeEach(func() {
				sourcePod = CloudControllerManagerInfo
			})

			CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should connect to metadataService", assertCanConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("elasticsearch", func() {

			BeforeEach(func() {
				sourcePod = ElasticSearchInfo
			})

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("grafana", func() {

			BeforeEach(func() {
				sourcePod = ElasticSearchInfo
			})

			CIt("should connect to prometheus", assertConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("kibana", func() {

			BeforeEach(func() {
				sourcePod = KibanaInfo
			})

			CIt("should connect to elasticsearch", assertConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("kube-controller-manager", func() {

			BeforeEach(func() {
				sourcePod = KubeControllerManagerInfo
			})

			CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			if cloudProvider == v1beta1.CloudProviderAlicloud {
				CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
			} else {
				CIt("should connect to metadataService", assertCanConnectToMetadataService(), NetworkPolicyTimeout)
			}

		})

		Context("kube-scheduler", func() {

			BeforeEach(func() {
				sourcePod = KubeSchedulerInfo
			})

			CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("kube-state-metrics-shoot", func() {

			BeforeEach(func() {
				sourcePod = KubeStateMetricsShootInfo
			})

			CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-seed", assertThereIsNoConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("kube-state-metrics-seed", func() {

			BeforeEach(func() {
				sourcePod = KubeStateMetricsSeedInfo
			})

			CIt("should block connectivity to kube-apiserver", assertThereIsNoConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-main", assertThereIsNoConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to etcd-events", assertThereIsNoConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to cloud-controller-manager", assertThereIsNoConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-controller-manager", assertThereIsNoConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-scheduler", assertThereIsNoConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kube-state-metrics-shoot", assertThereIsNoConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to machine-controller-manager", assertThereIsNoConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("machine-controller-manager", func() {

			BeforeEach(func() {
				sourcePod = MachineControllerManagerInfo
			})

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
			CIt("should block connectivity to prometheus", assertThereIsNoConnectivity(PrometheusInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

		Context("prometheus", func() {

			BeforeEach(func() {
				sourcePod = PrometheusInfo
			})

			CIt("should connect to kube-apiserver", assertConnectivity(KubeAPIServerInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-main", assertConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
			CIt("should connect to etcd-events", assertConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
			CIt("should connect to cloud-controller-manager", assertConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-controller-manager", assertConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-scheduler", assertConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-state-metrics-shoot", assertConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
			CIt("should connect to kube-state-metrics-seed", assertConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
			CIt("should connect to machine-controller-manager", assertConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)

			CIt("should block connectivity to elasticsearch-logging", assertThereIsNoConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to grafana", assertThereIsNoConnectivity(GrafanaInfo), NetworkPolicyTimeout)
			CIt("should block connectivity to kibana-logging", assertThereIsNoConnectivity(KibanaInfo), NetworkPolicyTimeout)

			CIt("should block connection to metadataService", assertCannotConnectToMetadataService(), NetworkPolicyTimeout)
		})

	})
})
