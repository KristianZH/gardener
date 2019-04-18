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

package common

import (
	"net"

	gardencorev1alpha1 "github.com/gardener/gardener/pkg/apis/core/v1alpha1"
)

var (
	// Private networks (RFC1918)
	private8BitBlock  = &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}
	private12BitBlock = &net.IPNet{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)}
	private16BitBlock = &net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)}

	// Carrier-grade NAT (RFC 6598)
	carrierGradeNATBlock = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
)

// Private8BitBlockContains returns CIDRs which are part of 10.0.0.0/8 block.
func Private8BitBlockContains(cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error) {
	return excludeBlock(private8BitBlock, cidrs...)
}

// Private12BitBlockContains returns CIDRs which are part of 172.16.0.0/12 block.
func Private12BitBlockContains(cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error) {
	return excludeBlock(private12BitBlock, cidrs...)
}

// Private16BitBlockContains returns CIDRs which are part of 192.168.0.0/16 block.
func Private16BitBlockContains(cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error) {
	return excludeBlock(private16BitBlock, cidrs...)
}

// CarrierGradeNATBlockContains returns CIDRs which are part of 100.64.0.0/10 block.
func CarrierGradeNATBlockContains(cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error) {
	return excludeBlock(carrierGradeNATBlock, cidrs...)
}

// ToExceptNetworks returns a list of maps with `network` key containing private (RFC1918) and Carrier-grade NAT (RFC 6598) CIDRs
// and `except` key containgn list of `cidr` which are part of those CIDRs.
//
// Calling `ToExceptNetworks("10.10.0.0/24","172.16.1.0/24","192.168.1.0/24","100.64.1.0/24")` produces:
//
// [
//		{"network": "10.0.0.0/8", "except": ["10.10.0.0/24"]},
//		{"network": "172.16.0.0/12", "except": ["172.16.1.0/24"]},
//		{"network": "192.168.0.0/16", "except": ["192.168.1.0/24"]},
//		{"network": "100.64.0.0/10", "except": ["100.64.1.0/24"]},
// ]
func ToExceptNetworks(cidrs ...gardencorev1alpha1.CIDR) ([]interface{}, error) {

	matched8Bit, err := Private8BitBlockContains(cidrs...)
	if err != nil {
		return nil, err
	}

	matched12Bit, err := Private12BitBlockContains(cidrs...)
	if err != nil {
		return nil, err
	}

	matched16Bit, err := Private16BitBlockContains(cidrs...)
	if err != nil {
		return nil, err
	}

	matchedCarrierGradeNat, err := CarrierGradeNATBlockContains(cidrs...)
	if err != nil {
		return nil, err
	}

	values := []interface{}{
		map[string]interface{}{
			"network": private8BitBlock.String(),
			"except":  matched8Bit,
		},
		map[string]interface{}{
			"network": private12BitBlock.String(),
			"except":  matched12Bit,
		},
		map[string]interface{}{
			"network": private16BitBlock.String(),
			"except":  matched16Bit,
		},
		map[string]interface{}{
			"network": carrierGradeNATBlock.String(),
			"except":  matchedCarrierGradeNat,
		},
	}

	return values, nil

}

func excludeBlock(parentBlock *net.IPNet, cidrs ...gardencorev1alpha1.CIDR) ([]gardencorev1alpha1.CIDR, error) {
	matchedCIDRs := []gardencorev1alpha1.CIDR{}

	for _, cidr := range cidrs {
		ip, _, err := net.ParseCIDR(string(cidr))
		if err != nil {
			return matchedCIDRs, err
		}
		if parentBlock.Contains(ip) {
			matchedCIDRs = append(matchedCIDRs, cidr)
		}
	}
	return matchedCIDRs, nil
}
