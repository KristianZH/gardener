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

type Target struct {
	Pod     *PodInfo
	Host    *Host
	Allowed bool
}

type Host struct {
	Description string
	HostName    string
	Port        int32
}

type Source struct {
	Pod     *PodInfo
	Targets []Target
}

type SourceBuilder struct {
	source          Source
	denyPodTargets  []PodInfo
	denyHostTargets []Host
}

func NewSource(pi *PodInfo, denyPodTargets []PodInfo, denyHostTargets []Host) *SourceBuilder {
	return &SourceBuilder{source: Source{Pod: pi}, denyPodTargets: denyPodTargets, denyHostTargets: denyHostTargets}
}

func (s *SourceBuilder) AllowHost(allowedHosts ...*Host) *SourceBuilder {
	for _, allowedHost := range allowedHosts {
		s.source.Targets = append(s.source.Targets, Target{Host: allowedHost, Allowed: true})
	}
	return s
}

func (s *SourceBuilder) AllowTo(description, hostname string, port int32) *SourceBuilder {
	s.source.Targets = append(s.source.Targets, Target{Host: &Host{description, hostname, port}, Allowed: true})
	return s
}

func (s *SourceBuilder) AllowPod(allowedPods ...*PodInfo) *SourceBuilder {
	for _, allowedPod := range allowedPods {

		for i := 0; i < len(s.source.Targets); i++ {
			existingTarget := s.source.Targets[i]

			if allowedPod.PodName == existingTarget.Pod.PodName && allowedPod.Port == existingTarget.Pod.Port {
				s.source.Targets[i] = Target{Pod: allowedPod, Allowed: true}
				break
			}

			s.source.Targets = append(s.source.Targets, Target{Pod: allowedPod, Allowed: true})
		}
	}
	for _, allowedPod := range allowedPods {
		s.source.Targets = append(s.source.Targets, Target{Pod: allowedPod, Allowed: true})
	}
	return s
}

func (s *SourceBuilder) SkipPod(skippedPods ...*PodInfo) *SourceBuilder {
	for _, skippedPod := range skippedPods {
		for i := 0; i < len(s.denyPodTargets); i++ {
			if s.denyPodTargets[i].PodName == skippedPod.PodName {
				s.denyPodTargets = append(s.denyPodTargets[:i], s.denyPodTargets[i+1:]...)
				i--
			}
		}
	}
	return s
}

func (s *SourceBuilder) Build() Source {
	// fmt.Printf("DENIED PODS %+v\n", s.denyPodTargets)
	// for _, deniedPod := range s.denyPodTargets {
	// 	skip := false
	// 	fmt.Printf("ALLOWED TARGETS %+v\n", *s.source.Targets)
	// 	for _, allowedTarget := range s.source.Targets {

	// 		fmt.Printf("ALLOWED TARGET %+v\n", *allowedTarget.Pod)
	// 		if allowedTarget.Pod != nil && allowedTarget.Pod.PodName == deniedPod.PodName && allowedTarget.Pod.Port == deniedPod.Port {
	// 			skip = true
	// 			break
	// 		}
	// 	}

	// 	if !skip {
	// 		s.source.Targets = append(s.source.Targets, Target{&deniedPod, nil, false})
	// 	}
	// }

	// fmt.Printf("TARGETS %+v\n", s.source.Targets)

	// for _, denyHost := range s.denyHostTargets {
	// 	found := false
	// 	for i, allowedTarget := range s.source.Targets {
	// 		if allowedTarget.Host != nil && allowedTarget.Host.HostName == denyHost.HostName && allowedTarget.Host.Port == denyHost.Port {
	// 			s.source.Targets[i] = allowedTarget
	// 			found = true
	// 			break
	// 		}
	// 	}

	// 	if !found {
	// 		s.source.Targets = append(s.source.Targets, Target{nil, &denyHost, false})
	// 	}
	// }
	return s.source
}
