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
		denyPod = &PodInfo{
			PodName: "target",
			Port:    8080,
		}

		source  *PodInfo
		builder *SourceBuilder
	)

	BeforeEach(func() {
		source = &PodInfo{
			PodName: "source",
			Port:    80,
		}
	})
	JustBeforeEach(func() {
		builder = NewSource(source)
	})

	Context("deny and allow", func() {
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

		It("should accept multipe entries", func() {
			result := builder.DenyPod(denyPod1, denyPod2).AllowPod(denyPod2).Build()
			expected := Source{source, []TargetPod{
				{denyPod1, false},
				{denyPod2, true},
			}, nil}
			Expect(result).To(Equal(expected))
		})

		It("should accept multipe entries", func() {
			result := builder.DenyPod(denyPod1, denyPod, denyPod2).AllowPod(denyPod1).Build()
			expected := Source{source, []TargetPod{
				{denyPod1, true},
				{denyPod, false},
				{denyPod2, false},
			}, nil}
			Expect(result).To(Equal(expected))
		})

		It("should accept multipe entries", func() {
			result := builder.AllowPod(denyPod1, denyPod, denyPod2).Build()
			expected := Source{source, []TargetPod{
				{denyPod1, true},
				{denyPod, true},
				{denyPod2, true},
			}, nil}
			Expect(result).To(Equal(expected))
		})
	})

})
