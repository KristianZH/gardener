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

import "fmt"

type TargetHost struct {
	Host    *Host
	Allowed bool
}

func (t *TargetHost) ToString() string {
	action := "block"
	if t.Allowed {
		action = "allow"
	}
	return fmt.Sprintf("should %s connection to %q (%s:%d)", action, t.Host.Description, t.Host.HostName, t.Host.Port)
}

type TargetPod struct {
	Pod     *PodInfo
	Allowed bool
}

func (t *TargetPod) ToString() string {
	action := "block"
	if t.Allowed {
		action = "allow"
	}
	return fmt.Sprintf("should %s connection to %s at port %d", action, t.Pod.PodName, t.Pod.Port)
}

type Host struct {
	Description string
	HostName    string
	Port        int32
}

type Source struct {
	Pod         *PodInfo
	TargetPods  []TargetPod
	TargetHosts []TargetHost
}

type SourceBuilder struct {
	source Source
}

func NewSource(pi *PodInfo) *SourceBuilder {
	return &SourceBuilder{source: Source{Pod: pi}}
}

func (s *SourceBuilder) AllowHost(allowedHosts ...*Host) *SourceBuilder {
	return s.conditionalHost(true, allowedHosts...)
}

func (s *SourceBuilder) AllowTo(description, hostname string, port int32) *SourceBuilder {
	return s.conditionalHost(true, &Host{Description: description, HostName: hostname, Port: port})
}

func (s *SourceBuilder) AllowPod(allowedPods ...*PodInfo) *SourceBuilder {
	return s.conditionalPod(true, allowedPods...)
}

func (s *SourceBuilder) DenyHost(deniedHosts ...*Host) *SourceBuilder {
	return s.conditionalHost(false, deniedHosts...)
}

func (s *SourceBuilder) DenyPod(deniedPods ...*PodInfo) *SourceBuilder {
	return s.conditionalPod(false, deniedPods...)
}

func (s *SourceBuilder) DenyTo(description, hostname string, port int32) *SourceBuilder {
	return s.conditionalHost(false, &Host{Description: description, HostName: hostname, Port: port})
}

// func (s *SourceBuilder) SkipPod(skippedPods ...*PodInfo) *SourceBuilder {
// 	for _, skippedPod := range skippedPods {
// 		for i := 0; i < len(s.denyPodTargets); i++ {
// 			if s.denyPodTargets[i].PodName == skippedPod.PodName {
// 				s.denyPodTargets = append(s.denyPodTargets[:i], s.denyPodTargets[i+1:]...)
// 				i--
// 			}
// 		}
// 	}
// 	return s
// }

func (s *SourceBuilder) conditionalPod(allowed bool, pods ...*PodInfo) *SourceBuilder {
	for _, pod := range pods {
		found := false
		for i, existingTarget := range s.source.TargetPods {

			if existingTarget.Pod != nil && pod.PodName == existingTarget.Pod.PodName && pod.Port == existingTarget.Pod.Port {
				s.source.TargetPods[i] = TargetPod{Pod: pod, Allowed: allowed}
				found = true
				break
			}

		}
		if !found {
			s.source.TargetPods = append(s.source.TargetPods, TargetPod{Pod: pod, Allowed: allowed})
		}
	}
	return s
}

func (s *SourceBuilder) conditionalHost(allowed bool, hosts ...*Host) *SourceBuilder {
	for _, host := range hosts {
		found := false
		for i, existingTarget := range s.source.TargetHosts {

			if existingTarget.Host != nil && host.HostName == existingTarget.Host.HostName && host.Port == existingTarget.Host.Port {
				s.source.TargetHosts[i] = TargetHost{Host: host, Allowed: allowed}
				found = true
				break
			}

		}
		if !found {
			s.source.TargetHosts = append(s.source.TargetHosts, TargetHost{Host: host, Allowed: allowed})
		}
	}
	return s
}

func (s *SourceBuilder) Build() Source {
	return s.source
}
