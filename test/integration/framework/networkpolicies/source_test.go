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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SourceBuilder test", func() {

	var (
		// denyPod = &PodInfo{
		// 	PodName: "target",
		// 	Port:    8080,
		// }

		denyHost = &Host{
			Description: "metadata service",
			HostName:    "example.com",
			Port:        80,
		}

		allowedPod = &PodInfo{
			PodName: "allowed",
			Port:    443,
		}

		// allowedHost = &Host{
		// 	Description: "some-description",
		// 	HostName:    "example.com",
		// 	Port:        9090,
		// }

		source      *PodInfo
		builder     *SourceBuilder
		deniedPods  []PodInfo
		deniedHosts []Host
	)

	BeforeEach(func() {
		source = &PodInfo{
			PodName: "source",
			Port:    80,
		}
	})
	JustBeforeEach(func() {
		builder = NewSource(source, deniedPods, deniedHosts)
	})

	// Context("no deny all provided", func() {

	// 	It("should not create targets when port and name are same", func() {
	// 		Expect(builder.Build()).To(Equal(Source{Pod: source}))
	// 	})

	// 	It("should return only allowed when pod is provided", func() {
	// 		expected := Source{source, []Target{
	// 			{allowedPod, nil, true},
	// 		}}
	// 		Expect(builder.AllowPod(allowedPod).Build()).To(Equal(expected))
	// 	})

	// 	It("should return only allowed when host is provided", func() {
	// 		expected := Source{source, []Target{
	// 			{nil, allowedHost, true},
	// 		}}
	// 		Expect(builder.AllowTo("some-description", "example.com", 9090).Build()).To(Equal(expected))
	// 	})

	// 	It("should return only allowed when host is passed", func() {
	// 		expected := Source{source, []Target{
	// 			{nil, allowedHost, true},
	// 		}}
	// 		Expect(builder.AllowHost(allowedHost).Build()).To(Equal(expected))
	// 	})

	// 	It("should return host and pod as allowed", func() {
	// 		expected := Source{source, []Target{
	// 			{allowedPod, nil, true},
	// 			{nil, allowedHost, true},
	// 		}}
	// 		Expect(builder.AllowPod(allowedPod).AllowTo("some-description", "example.com", 9090).Build()).To(Equal(expected))
	// 	})
	// })

	// Context("deny provided", func() {
	// 	BeforeEach(func() {
	// 		deniedPods = []PodInfo{*denyPod}
	// 		deniedHosts = []Host{*denyHost}
	// 	})

	// 	It("should return only target when provided", func() {
	// 		expected := Source{source, []Target{
	// 			{denyPod, nil, false},
	// 			{nil, denyHost, false},
	// 		}}
	// 		Expect(builder.Build()).To(Equal(expected))
	// 	})

	// 	It("should remove only skipped pod", func() {
	// 		expected := Source{source, []Target{
	// 			{nil, denyHost, false},
	// 		}}
	// 		Expect(builder.SkipPod(denyPod).Build()).To(Equal(expected))
	// 	})

	// 	Context("when deny ports are same", func() {
	// 		BeforeEach(func() {
	// 			deniedPods = []PodInfo{*source}
	// 		})

	// 		It("should return no targets", func() {
	// 			expected := Source{source, []Target{
	// 				{nil, denyHost, false},
	// 			}}
	// 			Expect(builder.Build()).To(Equal(expected))
	// 		})
	// 	})

	// 	Context("when override deny", func() {
	// 		BeforeEach(func() {
	// 			deniedPods = []PodInfo{*denyPod}
	// 			deniedHosts = []Host{*denyHost}
	// 		})

	// 		It("should allow all overridden targets", func() {
	// 			expected := Source{source, []Target{
	// 				{denyPod, nil, true},
	// 				{nil, denyHost, true},
	// 			}}
	// 			Expect(builder.AllowPod(denyPod).AllowHost(denyHost).Build()).To(Equal(expected))
	// 		})
	// 	})

	// 	It("should allow additional host and pods", func() {

	// 		expected := Source{source, []Target{
	// 			{allowedPod, nil, true},
	// 			{nil, allowedHost, true},
	// 			{denyPod, nil, false},
	// 			{nil, denyHost, false},
	// 		}}
	// 		Expect(builder.AllowPod(allowedPod).AllowTo("some-description", "example.com", 9090).Build()).To(Equal(expected))
	// 	})

	// })

	Context("multople deny provided", func() {
		var (
			denyPod1 = &PodInfo{
				PodName: "target-1",
				Port:    8080,
			}
			denyPod2 = &PodInfo{
				PodName: "target-2",
				Port:    8080,
			}
		)
		BeforeEach(func() {
			deniedPods = []PodInfo{*denyPod1, *denyPod2}
			deniedHosts = []Host{*denyHost}
		})

		It("should return correct items when passing multiple values", func() {
			expected := Source{source, []Target{
				{allowedPod, nil, true},
				{denyPod1, nil, false},
				{denyPod2, nil, false},
				{nil, denyHost, false},
			}}

			Expect(builder.AllowPod(allowedPod).Build()).To(Equal(expected))
		})
	})

})
