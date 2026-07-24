// Copyright 2026 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validations

import (
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
)

const (
	// capabilityEphemeralOSDiskSupported is the Microsoft.Compute Resource SKU
	// capability that indicates whether a VM size supports ephemeral OS disks.
	capabilityEphemeralOSDiskSupported = "EphemeralOSDiskSupported"
	// capabilityVCPUs is the Microsoft.Compute Resource SKU capability that
	// advertises the number of vCPUs for a VM size.
	capabilityVCPUs = "vCPUs"

	// usageNameTotalRegionalVCPUs is the Compute usage Name.Value for the
	// subscription's total regional vCPU quota (localized as "Total Regional vCPUs").
	usageNameTotalRegionalVCPUs = "cores"
)

// resourceSKUCapabilityString returns the named Resource SKU capability value.
func resourceSKUCapabilityString(sku *armcompute.ResourceSKU, name string) (string, bool) {
	if sku == nil {
		return "", false
	}
	for _, capability := range sku.Capabilities {
		if capability == nil || capability.Name == nil || capability.Value == nil {
			continue
		}
		if strings.EqualFold(*capability.Name, name) {
			return *capability.Value, true
		}
	}
	return "", false
}

// resourceSKUCapabilityEnabled reports whether the named Resource SKU capability
// is present with a True value (case-insensitive). Missing capabilities are treated
// as not enabled.
func resourceSKUCapabilityEnabled(sku *armcompute.ResourceSKU, name string) bool {
	value, ok := resourceSKUCapabilityString(sku, name)
	if !ok {
		return false
	}
	return strings.EqualFold(value, "True")
}

// resourceSKUCapabilityInt returns the named Resource SKU capability as an int.
func resourceSKUCapabilityInt(sku *armcompute.ResourceSKU, name string) (int, bool) {
	value, ok := resourceSKUCapabilityString(sku, name)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, false
	}
	return parsed, true
}
