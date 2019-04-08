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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
)

//Info about pods in Shoot-namespace
var (
	KubeAPIServerInfo = &PodInfo{
		containerName: "kube-apiserver",
		port:          443,
		labels: labels.Set{
			"app":  "kubernetes",
			"role": "apiserver",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-kube-apiserver",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-shoot-networks",
			"deny-all",
		),
	}
	KubeControllerManagerInfo = &PodInfo{
		containerName: "kube-controller-manager",
		port:          10252,
		labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "controller-manager",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"deny-all",
		),
	}
	KubeSchedulerInfo = &PodInfo{
		containerName: "kube-scheduler",
		port:          10251,
		labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "scheduler",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"deny-all",
		),
	}
	EtcdMainInfo = &PodInfo{
		containerName: "etcd",
		port:          2379,
		labels: labels.Set{
			"app":                     "etcd-statefulset",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "main",
		},
		expectedPolicies: sets.NewString(
			"allow-from-apiserver-to-etcd",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-etcd-main-peering",
			"deny-all",
		),
	}
	EtcdEventsInfo = &PodInfo{
		containerName: "etcd",
		port:          2379,
		labels: labels.Set{
			"app":                     "etcd-statefulset",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "events",
		},
		expectedPolicies: sets.NewString(
			"allow-from-apiserver-to-etcd",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-etcd-events-peering",
			"deny-all",
		),
	}
	CloudControllerManagerInfo = &PodInfo{
		containerName: "cloud-controller-manager",
		port:          10253,
		labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "cloud-controller-manager",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-metadata",
			"deny-all",
		),
	}
	ElasticSearchInfo = &PodInfo{
		containerName: "elasticsearch-logging",
		port:          9200,
		labels: labels.Set{
			"app":                     "elasticsearch-logging",
			"garden.sapcloud.io/role": "logging",
			"role":                    "logging",
		},
		expectedPolicies: sets.NewString(
			"allow-elasticsearch",
			"deny-all",
		),
	}
	GrafanaInfo = &PodInfo{
		containerName: "grafana",
		port:          3000,
		labels: labels.Set{
			"component":               "grafana",
			"garden.sapcloud.io/role": "monitoring",
		},
		expectedPolicies: sets.NewString(
			"allow-grafana",
			"allow-to-dns",
			"deny-all",
		),
	}
	KibanaInfo = &PodInfo{
		containerName: "kibana-logging",
		port:          5601,
		labels: labels.Set{
			"app":                     "kibana-logging",
			"garden.sapcloud.io/role": "logging",
			"role":                    "logging",
		},
		expectedPolicies: sets.NewString(
			"allow-kibana",
			"allow-to-dns",
			"allow-to-elasticsearch",
			"deny-all",
		),
	}
	KubeStateMetricsSeedInfo = &PodInfo{
		containerName: "kube-state-metrics",
		port:          8080,
		labels: labels.Set{
			"component":               "kube-state-metrics",
			"garden.sapcloud.io/role": "monitoring",
			"type":                    "seed",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-seed-apiserver",
			"deny-all",
		),
	}
	KubeStateMetricsShootInfo = &PodInfo{
		containerName: "kube-state-metrics",
		port:          8080,
		labels: labels.Set{
			"component":               "kube-state-metrics",
			"garden.sapcloud.io/role": "monitoring",
			"type":                    "shoot",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}
	MachineControllerManagerInfo = &PodInfo{
		containerName: "machine-controller-manager",
		port:          10258,
		labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "machine-controller-manager",
		},
		expectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-seed-apiserver",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}
	PrometheusInfo = &PodInfo{
		containerName: "prometheus",
		port:          9090,
		labels: labels.Set{
			"app":                     "prometheus",
			"garden.sapcloud.io/role": "monitoring",
			"role":                    "monitoring",
		},
		expectedPolicies: sets.NewString(
			"allow-prometheus",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-seed-apiserver",
			"allow-to-shoot-apiserver",
			"allow-to-shoot-networks",
			"deny-all",
		),
	}
	BusyboxInfo = &PodInfo{
		containerName: "busybox",
		port:          8080,
		labels: labels.Set{
			"app":  "busybox",
			"role": "testing",
		},
	}
)

// PodInfo holds the data about pods in the shoot namespace and their services.
type PodInfo struct {
	containerName    string
	port             int32
	portName         string
	labels           labels.Set
	expectedPolicies sets.String
}

// Selector returns label selector for specific pod.
func (p *PodInfo) Selector() labels.Selector {
	return labels.SelectorFromSet(p.labels)
}

// ListPodsInfo return slice with info for all pods.
func ListPodsInfo() []PodInfo {
	return []PodInfo{
		*KubeAPIServerInfo,
		*KubeControllerManagerInfo,
		*KubeSchedulerInfo,
		*EtcdMainInfo,
		*EtcdEventsInfo,
		*CloudControllerManagerInfo,
		*ElasticSearchInfo,
		*GrafanaInfo,
		*KibanaInfo,
		*KubeStateMetricsSeedInfo,
		*KubeStateMetricsShootInfo,
		*MachineControllerManagerInfo,
		*PrometheusInfo,
	}
}

// NamespacedPodInfo holds namespaced PodInfo.
type NamespacedPodInfo struct {
	*PodInfo
	namespace string
}

// NewNamespacedPodInfo creates a new NamespacedPodInfo.
func NewNamespacedPodInfo(pi *PodInfo, namespace string) *NamespacedPodInfo {
	return &NamespacedPodInfo{PodInfo: pi, namespace: namespace}
}
