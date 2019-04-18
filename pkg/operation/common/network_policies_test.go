// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package common_test

import (
	gardencorev1alpha1 "github.com/gardener/gardener/pkg/apis/core/v1alpha1"
	. "github.com/gardener/gardener/pkg/operation/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("networkpolicies", func() {

	Describe("Contains functions", func() {

		var (
			input       []gardencorev1alpha1.CIDR
			result      []gardencorev1alpha1.CIDR
			resultError error
		)

		BeforeEach(func() {
			input = nil
			result = nil
			resultError = nil
		})

		type testcase struct {
			name            string
			function        func(cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error)
			notOverlapping  []gardencorev1alpha1.CIDR
			overLapping     []gardencorev1alpha1.CIDR
			expectedMatched []gardencorev1alpha1.CIDR
		}

		cases := []testcase{
			{
				name:            "#Private8BitBlockContains",
				function:        Private8BitBlockContains,
				notOverlapping:  []gardencorev1alpha1.CIDR{"1.1.1.1/32", "1.1.1.2/32"},
				overLapping:     []gardencorev1alpha1.CIDR{"1.1.1.1/32", "10.10.0.0/24"},
				expectedMatched: []gardencorev1alpha1.CIDR{"10.10.0.0/24"},
			}, {
				name:            "#Private12BitBlockContains",
				function:        Private12BitBlockContains,
				notOverlapping:  []gardencorev1alpha1.CIDR{"1.1.1.1/32", "1.1.1.2/32"},
				overLapping:     []gardencorev1alpha1.CIDR{"1.1.1.1/32", "172.16.1.0/24"},
				expectedMatched: []gardencorev1alpha1.CIDR{"172.16.1.0/24"},
			}, {
				name:            "#Private16BitBlockContains",
				function:        Private16BitBlockContains,
				notOverlapping:  []gardencorev1alpha1.CIDR{"1.1.1.1/32", "1.1.1.2/32"},
				overLapping:     []gardencorev1alpha1.CIDR{"1.1.1.1/32", "192.168.1.0/24"},
				expectedMatched: []gardencorev1alpha1.CIDR{"192.168.1.0/24"},
			}, {
				name:            "#CarrierGradeNATBlockContains",
				function:        CarrierGradeNATBlockContains,
				notOverlapping:  []gardencorev1alpha1.CIDR{"1.1.1.1/32", "1.1.1.2/32"},
				overLapping:     []gardencorev1alpha1.CIDR{"1.1.1.1/32", "100.64.1.0/24"},
				expectedMatched: []gardencorev1alpha1.CIDR{"100.64.1.0/24"},
			},
		}

		for _, tc := range cases {
			tc := tc
			Context(tc.name, func() {
				JustBeforeEach(func() {
					result, resultError = tc.function(input...)
				})

				Context("when invalid CIDR is provided", func() {
					BeforeEach(func() {
						input = []gardencorev1alpha1.CIDR{"foo"}
					})

					It("should return error", func() {
						Expect(resultError).To(HaveOccurred())
					})

					It("should not return any CIDRs", func() {
						Expect(result).To(BeEmpty())
					})
				})

				Context("when valid not overlapping CIDR is provided", func() {
					BeforeEach(func() {
						input = tc.notOverlapping
					})

					It("should not return error", func() {
						Expect(resultError).ToNot(HaveOccurred())
					})

					It("should not return any CIDRs", func() {
						Expect(result).To(BeEmpty())
					})
				})

				Context("when valid overlapping CIDR is provided", func() {
					BeforeEach(func() {
						input = tc.overLapping
					})

					It("should not return error", func() {
						Expect(resultError).ToNot(HaveOccurred())
					})

					It("should return only matched CIDRs", func() {
						Expect(result).To(ConsistOf(tc.expectedMatched))
					})
				})
			})
		}

	})

	Describe("#ToExceptNetworks", func() {

		It("should return correct result", func() {

			result, err := ToExceptNetworks("10.10.0.0/24", "172.16.1.0/24", "192.168.1.0/24", "100.64.1.0/24")
			expectedResult := []interface{}{
				map[string]interface{}{
					"network": "10.0.0.0/8",
					"except":  []gardencorev1alpha1.CIDR{"10.10.0.0/24"},
				},
				map[string]interface{}{
					"network": "172.16.0.0/12",
					"except":  []gardencorev1alpha1.CIDR{"172.16.1.0/24"},
				},
				map[string]interface{}{
					"network": "192.168.0.0/16",
					"except":  []gardencorev1alpha1.CIDR{"192.168.1.0/24"},
				},
				map[string]interface{}{
					"network": "100.64.0.0/10",
					"except":  []gardencorev1alpha1.CIDR{"100.64.1.0/24"},
				},
			}

			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(ConsistOf(expectedResult))

		})

	})

})
