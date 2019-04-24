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

var (

	// OpenStackKubeControllerManagerInfo points to openstack-specific kube-controller-manager.
	OpenStackKubeControllerManagerInfo = &PodInfo{
		PodName: "kube-controller-manager",
		Port:    10252,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "controller-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-to-public-except-private-and-metadata",
			"allow-to-private-except-metadata-cluster",
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-metadata",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}

	// OpenStackMetadataServiceHost points to openstack-specific Metadata service.
	OpenStackMetadataServiceHost = &Host{
		Description: "Metadata service",
		HostName:    "169.254.169.254",
		Port:        80,
	}
)

// OpenStackPodInfo holds openstack-specific podInfo.
// +gen-netpoltests=true
// +gen-packagename=openstack
type OpenStackPodInfo struct {
}

// ToSources returns list of all openstack-specific sources and targets.
func (a *OpenStackPodInfo) ToSources() []Source {

	return []Source{
		a.newSource(KubeAPIServerInfo).AllowPod(EtcdMainInfo, EtcdEventsInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(EtcdMainInfo).AllowHost(ExternalHost).Build(),
		a.newSource(EtcdEventsInfo).AllowHost(ExternalHost).Build(),
		a.newSource(CloudControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(OpenStackMetadataServiceHost, ExternalHost).Build(),
		a.newSource(ElasticSearchInfo).Build(),
		a.newSource(GrafanaInfo).AllowPod(PrometheusInfo).Build(),
		a.newSource(KibanaInfo).AllowPod(ElasticSearchInfo).Build(),
		a.newSource(AddonManagerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(OpenStackKubeControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(OpenStackMetadataServiceHost, ExternalHost).Build(),
		a.newSource(KubeSchedulerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsShootInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsSeedInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(MachineControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(PrometheusInfo).AllowPod(
			KubeAPIServerInfo,
			EtcdMainInfo,
			EtcdEventsInfo,
			CloudControllerManagerInfo,
			OpenStackKubeControllerManagerInfo,
			KubeSchedulerInfo,
			KubeStateMetricsShootInfo,
			KubeStateMetricsSeedInfo,
			MachineControllerManagerInfo,
		).AllowHost(SeedKubeAPIServer, ExternalHost, GardenPrometheus).Build(),
	}
}

// EgressFromOtherNamespaces returns list of all openstack-specific sources and targets.
func (a *OpenStackPodInfo) EgressFromOtherNamespaces() []TargetPod {
	return []TargetPod{
		{*KubeAPIServerInfo, true},
		{*OpenStackKubeControllerManagerInfo, false},
		{*KubeSchedulerInfo, false},
		{*EtcdMainInfo, false},
		{*EtcdEventsInfo, false},
		{*CloudControllerManagerInfo, false},
		{*ElasticSearchInfo, false},
		{*GrafanaInfo, false},
		{*KibanaInfo, false},
		{*KubeStateMetricsSeedInfo, false},
		{*KubeStateMetricsShootInfo, false},
		{*MachineControllerManagerInfo, false},
		{*PrometheusInfo, false},
		{*AddonManagerInfo, false},
	}
}

func (a *OpenStackPodInfo) newSource(sourcePod *PodInfo) *SourceBuilder {
	denyAll := []*PodInfo{
		KubeAPIServerInfo,
		OpenStackKubeControllerManagerInfo,
		KubeSchedulerInfo,
		EtcdMainInfo,
		EtcdEventsInfo,
		CloudControllerManagerInfo,
		ElasticSearchInfo,
		GrafanaInfo,
		KibanaInfo,
		KubeStateMetricsSeedInfo,
		KubeStateMetricsShootInfo,
		MachineControllerManagerInfo,
		PrometheusInfo,
		AddonManagerInfo,
	}
	return NewSource(sourcePod).DenyPod(denyAll...).DenyHost(OpenStackMetadataServiceHost, ExternalHost, GardenPrometheus)
}
