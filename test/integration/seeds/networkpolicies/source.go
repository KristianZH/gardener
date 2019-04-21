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
	"reflect"

	"github.com/gardener/gardener/pkg/apis/garden/v1beta1"
)

type Target struct {
	TargetPod   *PodInfo
	ShouldAllow bool
}

type Hosts struct {
	Description string
	HostName    string
	Port        int32
}

type Source struct {
	Pod         *PodInfo
	AllowedPods []*PodInfo
}

func (s *Source) ToTargets() []Target {

	targets := []Target{}

	for _, allowedPod := range s.AllowedPods {
		targets = append(targets, Target{allowedPod, true})
	}

	for _, pod := range ListPodsInfo() {
		if reflect.DeepEqual(pod, s.Pod) {
			continue
		}
		found := false
		for _, allowedPod := range s.AllowedPods {
			if reflect.DeepEqual(pod, allowedPod) {
				found = true
				break
			}
		}
		if !found {
			targets = append(targets, Target{pod, false})
		}
	}

	return targets
}

func (s *Source) ToHosts(cp v1beta1.CloudProvider) []Hosts {
	var metadataHost string
	metadataPort := int32(80)
	if cp == v1beta1.CloudProviderAlicloud {
		metadataHost = "100.100.100.200"
	} else {
		metadataHost = "169.254.169.254"
	}

	return []Hosts{{"Metadata Service", metadataHost, metadataPort}}
}
