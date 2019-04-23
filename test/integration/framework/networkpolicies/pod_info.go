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

// PodInfo holds the data about pods in the shoot namespace and their services.
type PodInfo struct {
	PodName          string
	Port             int32
	PortName         string
	Labels           labels.Set
	ExpectedPolicies sets.String
}

// Selector returns label selector for specific pod.
func (p *PodInfo) Selector() labels.Selector {
	return labels.SelectorFromSet(p.Labels)
}

//Info about pods in Shoot-namespace
var (
	KubeAPIServerInfo = &PodInfo{
		PodName: "kube-apiserver",
		Port:    443,
		Labels: labels.Set{
			"app":  "kubernetes",
			"role": "apiserver",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-kube-apiserver",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"allow-to-shoot-networks",
			"deny-all",
		),
	}
	KubeControllerManagerInfo = &PodInfo{
		PodName: "kube-controller-manager",
		Port:    10252,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "controller-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"deny-all",
		),
	}
	KubeSchedulerInfo = &PodInfo{
		PodName: "kube-scheduler",
		Port:    10251,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "scheduler",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"deny-all",
		),
	}
	EtcdMainInfo = &PodInfo{
		PodName: "etcd-main",
		Port:    2379,
		Labels: labels.Set{
			"app":                     "etcd-statefulset",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "main",
		},
		ExpectedPolicies: sets.NewString(
			"allow-etcd",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"deny-all",
		),
	}
	EtcdEventsInfo = &PodInfo{
		PodName: "etcd-events",
		Port:    2379,
		Labels: labels.Set{
			"app":                     "etcd-statefulset",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "events",
		},
		ExpectedPolicies: sets.NewString(
			"allow-etcd",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"deny-all",
		),
	}
	CloudControllerManagerInfo = &PodInfo{
		PodName: "cloud-controller-manager",
		Port:    10253,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "cloud-controller-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-shoot-apiserver",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"allow-to-metadata",
			"deny-all",
		),
	}
	ElasticSearchInfo = &PodInfo{
		PodName: "elasticsearch-logging",
		Port:    9200,
		Labels: labels.Set{
			"app":                     "elasticsearch-logging",
			"garden.sapcloud.io/role": "logging",
			"role":                    "logging",
		},
		ExpectedPolicies: sets.NewString(
			"allow-elasticsearch",
			"deny-all",
		),
	}
	GrafanaInfo = &PodInfo{
		PodName: "grafana",
		Port:    3000,
		Labels: labels.Set{
			"component":               "grafana",
			"garden.sapcloud.io/role": "monitoring",
		},
		ExpectedPolicies: sets.NewString(
			"allow-grafana",
			"allow-to-dns",
			"deny-all",
		),
	}
	KibanaInfo = &PodInfo{
		PodName: "kibana-logging",
		Port:    5601,
		Labels: labels.Set{
			"app":                     "kibana-logging",
			"garden.sapcloud.io/role": "logging",
			"role":                    "logging",
		},
		ExpectedPolicies: sets.NewString(
			"allow-kibana",
			"allow-to-dns",
			"allow-to-elasticsearch",
			"deny-all",
		),
	}
	KubeStateMetricsSeedInfo = &PodInfo{
		PodName: "kube-state-metrics-seed",
		Port:    8080,
		Labels: labels.Set{
			"component":               "kube-state-metrics",
			"garden.sapcloud.io/role": "monitoring",
			"type":                    "seed",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-seed-apiserver",
			"deny-all",
		),
	}
	KubeStateMetricsShootInfo = &PodInfo{
		PodName: "kube-state-metrics-shoot",
		Port:    8080,
		Labels: labels.Set{
			"component":               "kube-state-metrics",
			"garden.sapcloud.io/role": "monitoring",
			"type":                    "shoot",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}
	MachineControllerManagerInfo = &PodInfo{
		PodName: "machine-controller-manager",
		Port:    10258,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "machine-controller-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"allow-to-seed-apiserver",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}
	PrometheusInfo = &PodInfo{
		PodName: "prometheus",
		Port:    9090,
		Labels: labels.Set{
			"app":                     "prometheus",
			"garden.sapcloud.io/role": "monitoring",
			"role":                    "monitoring",
		},
		ExpectedPolicies: sets.NewString(
			"allow-prometheus",
			"allow-to-dns",
			"allow-to-public-except-private-and-metadata",
			"allow-to-seed-apiserver",
			"allow-to-shoot-apiserver",
			"allow-to-shoot-networks",
			"deny-all",
		),
	}
	AddonManagerInfo = &PodInfo{
		PodName: "kube-addon-manager",
		// TODO it actually does nothing
		Port: 9090,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "addon-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-to-dns",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}
	BusyboxInfo = &PodInfo{
		PodName: "busybox",
		Port:    8080,
		Labels: labels.Set{
			"app":  "busybox",
			"role": "testing",
		},
	}

	ExternalHost = &Host{
		Description: "External host",
		HostName:    "8.8.8.8",
		Port:        53,
	}

	SeedKubeAPIServer = &Host{
		Description: "Seed Kube APIServer",
		HostName:    "kubernetes.default",
		Port:        443,
	}

	GardenPrometheus = &Host{
		Description: "Garden Prometheus",
		HostName:    "prometheus-web.garden",
		Port:        80,
	}
)

type CloudAwarePodInfo interface {
	// provider v1beta1.CloudProvider
	ToSources() []Source
}

// NamespacedPodInfo holds namespaced PodInfo.
type NamespacedPodInfo struct {
	*PodInfo
	Namespace string
}

// NewNamespacedPodInfo creates a new NamespacedPodInfo.
func NewNamespacedPodInfo(pi *PodInfo, namespace string) *NamespacedPodInfo {
	return &NamespacedPodInfo{PodInfo: pi, Namespace: namespace}
}
