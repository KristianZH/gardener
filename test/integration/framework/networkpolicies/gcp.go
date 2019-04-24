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

	// GCPKubeControllerManagerInfo points to gcp-specific kube-controller-manager.
	GCPKubeControllerManagerInfo = &PodInfo{
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

	// GCPMetadataServiceHost points to gcp-specific Metadata service.
	GCPMetadataServiceHost = &Host{
		Description: "Metadata service",
		HostName:    "169.254.169.254",
		Port:        80,
	}
)

// GCPPodInfo holds gcp-specific podInfo.
// +gen-netpoltests=true
// +gen-packagename=gcp
type GCPPodInfo struct {
}

// ToSources returns list of all gcp-specific sources and targets.
func (a *GCPPodInfo) ToSources() []Source {

	return []Source{
		a.newSource(KubeAPIServerInfo).AllowPod(EtcdMainInfo, EtcdEventsInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(EtcdMainInfo).AllowHost(ExternalHost).Build(),
		a.newSource(EtcdEventsInfo).AllowHost(ExternalHost).Build(),
		a.newSource(CloudControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(GCPMetadataServiceHost, ExternalHost).Build(),
		a.newSource(ElasticSearchInfo).Build(),
		a.newSource(GrafanaInfo).AllowPod(PrometheusInfo).Build(),
		a.newSource(KibanaInfo).AllowPod(ElasticSearchInfo).Build(),
		a.newSource(AddonManagerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(GCPKubeControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(GCPMetadataServiceHost, ExternalHost).Build(),
		a.newSource(KubeSchedulerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsShootInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsSeedInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(MachineControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(PrometheusInfo).AllowPod(
			KubeAPIServerInfo,
			EtcdMainInfo,
			EtcdEventsInfo,
			CloudControllerManagerInfo,
			GCPKubeControllerManagerInfo,
			KubeSchedulerInfo,
			KubeStateMetricsShootInfo,
			KubeStateMetricsSeedInfo,
			MachineControllerManagerInfo,
		).AllowHost(SeedKubeAPIServer, ExternalHost, GardenPrometheus).Build(),
	}
}

// EgressFromOtherNamespaces returns list of all gcp-specific sources and targets.
func (a *GCPPodInfo) EgressFromOtherNamespaces() []TargetPod {
	return []TargetPod{
		{*KubeAPIServerInfo, true},
		{*GCPKubeControllerManagerInfo, false},
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

func (a *GCPPodInfo) newSource(sourcePod *PodInfo) *SourceBuilder {
	denyAll := []*PodInfo{
		KubeAPIServerInfo,
		GCPKubeControllerManagerInfo,
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
	return NewSource(sourcePod).DenyPod(denyAll...).DenyHost(GCPMetadataServiceHost, ExternalHost, GardenPrometheus)
}
