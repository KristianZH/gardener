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
	"github.com/gardener/gardener/pkg/apis/garden/v1beta1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (

	// AlicloudKubeControllerManagerInfo points to alicloud-specific kube-controller-manager.
	AlicloudKubeControllerManagerInfo = &PodInfo{
		PodName: "kube-controller-manager",
		Port:    10252,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "controller-manager",
		},
		ExpectedPolicies: sets.NewString(
			"allow-from-prometheus",
			"allow-to-dns",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}

	// AlicloudCSIPluginInfo points to alicloud-specific CSI Plugin.
	AlicloudCSIPluginInfo = &PodInfo{
		PodName: "csi-plugin-controller",
		Port:    80,
		Labels: labels.Set{
			"app":                     "kubernetes",
			"garden.sapcloud.io/role": "controlplane",
			"role":                    "csi-plugin-controller",
		},
		ExpectedPolicies: sets.NewString(
			"allow-to-public-networks",
			"allow-to-private-networks",
			"allow-to-dns",
			"allow-to-shoot-apiserver",
			"deny-all",
		),
	}

	// AlicloudMetadataServiceHost points to alicloud-specific Metadata service.
	AlicloudMetadataServiceHost = &Host{
		Description: "Metadata service",
		HostName:    "100.100.100.200",
		Port:        80,
	}
)

// Alicloud holds alicloud-specific podInfo.
// +gen-netpoltests=true
// +gen-packagename=alicloud
type AlicloudPodInfo struct {
}

// ToSources returns list of all alicloud-specific sources and targets.
func (a *AlicloudPodInfo) ToSources() []Source {

	return []Source{
		a.newSource(KubeAPIServerInfo).AllowPod(EtcdMainInfo, EtcdEventsInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(EtcdMainInfo).AllowHost(ExternalHost).Build(),
		a.newSource(EtcdEventsInfo).AllowHost(ExternalHost).Build(),
		a.newSource(CloudControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(AlicloudMetadataServiceHost, ExternalHost).Build(),
		a.newSource(ElasticSearchInfo).Build(),
		a.newSource(GrafanaInfo).AllowPod(PrometheusInfo).Build(),
		a.newSource(KibanaInfo).AllowPod(ElasticSearchInfo).Build(),
		a.newSource(AddonManagerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(AlicloudKubeControllerManagerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeSchedulerInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsShootInfo).AllowPod(KubeAPIServerInfo).Build(),
		a.newSource(KubeStateMetricsSeedInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(MachineControllerManagerInfo).AllowPod(KubeAPIServerInfo).AllowHost(SeedKubeAPIServer, ExternalHost).Build(),
		a.newSource(AlicloudCSIPluginInfo).AllowPod(KubeAPIServerInfo).AllowHost(ExternalHost).Build(),
		a.newSource(PrometheusInfo).AllowPod(
			KubeAPIServerInfo,
			EtcdMainInfo,
			EtcdEventsInfo,
			CloudControllerManagerInfo,
			AlicloudKubeControllerManagerInfo,
			KubeSchedulerInfo,
			KubeStateMetricsShootInfo,
			KubeStateMetricsSeedInfo,
			MachineControllerManagerInfo,
		).AllowHost(SeedKubeAPIServer, ExternalHost, GardenPrometheus).Build(),
	}
}

// ToSources returns list of all alicloud-specific sources and targets.
func (a *AlicloudPodInfo) EgressFromOtherNamespaces() []TargetPod {
	return []TargetPod{
		{*KubeAPIServerInfo, true},
		{*AlicloudKubeControllerManagerInfo, false},
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
		{*AlicloudCSIPluginInfo, false},
	}
}

func (a *AlicloudPodInfo) newSource(sourcePod *PodInfo) *SourceBuilder {
	denyAll := []*PodInfo{
		KubeAPIServerInfo,
		AlicloudKubeControllerManagerInfo,
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
		AlicloudCSIPluginInfo,
	}
	return NewSource(sourcePod).DenyPod(denyAll...).DenyHost(AlicloudMetadataServiceHost, ExternalHost, GardenPrometheus)
}

// Provider returns Alicloud cloud provider.
func (a *AlicloudPodInfo) Provider() v1beta1.CloudProvider {
	return v1beta1.CloudProviderAlicloud
}
