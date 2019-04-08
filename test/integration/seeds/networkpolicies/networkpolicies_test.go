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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	var (
		shootGardenerTest   *ShootGardenerTest
		shootTestOperations *GardenerTestOperation
		shootAppTestLogger  *logrus.Logger
		cloudProvider       v1beta1.CloudProvider
		networkPolicies     []networkingv1.NetworkPolicy
		busyBox             *NamespacedPodInfo
		mirrorNamespaceName string

		createBusyBox = func(ctx context.Context, npi *NamespacedPodInfo) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "busybox-",
					Namespace:    npi.namespace,
					Labels:       npi.labels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						corev1.Container{
							// listen on on container port
							Args:  []string{"nc", "-lk", "-p", string(npi.port), "-e", "/bin/echo", "-s", "0.0.0.0"},
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

			busyBox = NewNamespacedPodInfo(BusyboxInfo, npi.namespace)
		}

		establishConnection = func(ctx context.Context, sourcePod *NamespacedPodInfo, targetPod *NamespacedPodInfo) (io.Reader, error) {
			By(fmt.Sprintf("Checking for source Pod: %s is running", sourcePod.containerName))
			err := shootTestOperations.WaitUntilPodIsRunningWithLabels(ctx, sourcePod.Selector(), sourcePod.namespace, shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Checking that target Pod: %s is running", targetPod.containerName))
			err = shootTestOperations.WaitUntilPodIsRunningWithLabels(ctx, targetPod.Selector(), shootTestOperations.ShootSeedNamespace(), shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Get target pod: %s", targetPod.containerName))
			trgPod, err := shootTestOperations.GetFirstRunningPodWithLabels(ctx, targetPod.Selector(), shootTestOperations.ShootSeedNamespace(), shootTestOperations.SeedClient)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By(fmt.Sprintf("Executing connectivity command from %s to %s", sourcePod.containerName, targetPod.containerName))
			return shootTestOperations.PodExecByLabel(ctx, sourcePod.Selector(), "busybox", fmt.Sprintf("nc -v -z -w 2 %s %d", trgPod.Status.PodIP, targetPod.port), sourcePod.namespace, shootTestOperations.SeedClient)

		}
		assertCanConnect = func(ctx context.Context, sourcePod *NamespacedPodInfo, targetPod *NamespacedPodInfo) {
			r, err := establishConnection(ctx, sourcePod, targetPod)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, r).NotTo(BeNil())
		}
		assertCannotConnect = func(ctx context.Context, sourcePod *NamespacedPodInfo, targetPod *NamespacedPodInfo) {
			r, err := establishConnection(ctx, sourcePod, targetPod)
			ExpectWithOffset(1, err).To(HaveOccurred())
			bytes, err := ioutil.ReadAll(r)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())

			By("Connection message is timed out\n")
			ExpectWithOffset(1, string(bytes)).To(ContainSubstring("Connection timed out"))
		}
	)

	CBeforeSuite(func(ctx context.Context) {
		// validate flags
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

		mirrorNamespaceName = mirrorNamespace.GetName()

		By(fmt.Sprintf("Getting all network policies in namespace %q", shootTestOperations.ShootSeedNamespace()))
		list := &networkingv1.NetworkPolicyList{}
		err = shootTestOperations.SeedClient.Client().List(ctx, &client.ListOptions{Namespace: shootTestOperations.ShootSeedNamespace()}, list)
		Expect(err).ToNot(HaveOccurred())

		networkPolicies = list.Items

		for _, netPol := range networkPolicies {
			cpy := netPol.DeepCopy()
			cpy.ObjectMeta.Namespace = mirrorNamespaceName
			By(fmt.Sprintf("Mirroring NetworkPolicy %s to namespace %s", cpy.GetName(), mirrorNamespaceName))
			shootTestOperations.SeedClient.Client().Create(ctx, cpy)
			Expect(err).NotTo(HaveOccurred())
		}

		for _, pi := range ListPodsInfo() {
			By(fmt.Sprintf("Mirroring Pod %s to namespace %s", pi.labels.String(), mirrorNamespaceName))
			createBusyBox(ctx, NewNamespacedPodInfo(&pi, mirrorNamespaceName))
		}

		createBusyBox(ctx, NewNamespacedPodInfo(BusyboxInfo, ns.GetName()))

	}, InitializationTimeout)

	CAfterSuite(func(ctx context.Context) {
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

	}, FinalizationTimeout)

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

					for _, netPol := range networkPolicies {
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
					assertCannotConnect(ctx, busyBox, NewNamespacedPodInfo(targetPod, shootTestOperations.ShootSeedNamespace()))
				}
			}
		)

		CIt("should allow connectivity to kube-apiserver", func(ctx context.Context) {
			assertCanConnect(ctx, busyBox, NewNamespacedPodInfo(KubeAPIServerInfo, shootTestOperations.ShootSeedNamespace()))
		}, NetworkPolicyTimeout)

		CIt("should block connectivity to etcd-main", assertConnectivity(EtcdMainInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to etcd-events", assertConnectivity(EtcdEventsInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to cloud-controller-manager", assertConnectivity(CloudControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to elasticsearch-logging", assertConnectivity(ElasticSearchInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to grafana", assertConnectivity(GrafanaInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kibana-logging", assertConnectivity(KibanaInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-controller-manager", assertConnectivity(KubeControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-scheduler", assertConnectivity(KubeSchedulerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-state-metrics-shoot", assertConnectivity(KubeStateMetricsShootInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to kube-state-metrics-seed", assertConnectivity(KubeStateMetricsSeedInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to machine-controller-manager", assertConnectivity(MachineControllerManagerInfo), NetworkPolicyTimeout)
		CIt("should block connectivity to prometheus", assertConnectivity(PrometheusInfo), NetworkPolicyTimeout)

	})

	Context("Mirrored pods", func() {

		var (
			NetworkPolicyTimeout = 30 * time.Second

			assertConnectivity = func(sourcePod *PodInfo, targetPod *PodInfo) func(ctx context.Context) {
				return func(ctx context.Context) {
					assertCanConnect(ctx, NewNamespacedPodInfo(sourcePod, mirrorNamespaceName), NewNamespacedPodInfo(targetPod, mirrorNamespaceName))
				}
			}
		)

		Context("kube-apiserver", func() {

			CIt("should connect to etcd-main", assertConnectivity(KubeAPIServerInfo, EtcdMainInfo), NetworkPolicyTimeout)

		})

	})
})
