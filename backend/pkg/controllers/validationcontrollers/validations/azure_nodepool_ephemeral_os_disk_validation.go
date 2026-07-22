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
	"context"
	"fmt"

	"github.com/Azure/ARO-HCP/backend/pkg/azure/cachedreader"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/api/arm"
	"github.com/Azure/ARO-HCP/internal/utils"
)

// AzureNodePoolEphemeralOSDiskValidation validates that a node pool requesting
// an ephemeral OS disk uses a VM size that advertises EphemeralOSDiskSupported.
// Node pools with managed OS disks are skipped.
type AzureNodePoolEphemeralOSDiskValidation struct {
	resourceSKUsCachedReader cachedreader.ResourceSKUsCachedReader
}

func NewAzureNodePoolEphemeralOSDiskValidation(
	resourceSKUsCachedReader cachedreader.ResourceSKUsCachedReader,
) *AzureNodePoolEphemeralOSDiskValidation {
	return &AzureNodePoolEphemeralOSDiskValidation{
		resourceSKUsCachedReader: resourceSKUsCachedReader,
	}
}

var _ NodePoolValidation = (*AzureNodePoolEphemeralOSDiskValidation)(nil)

func (v *AzureNodePoolEphemeralOSDiskValidation) Name() string {
	return "AzureNodePoolEphemeralOSDiskValidation"
}

func (v *AzureNodePoolEphemeralOSDiskValidation) Validate(
	ctx context.Context,
	_ *api.HCPOpenShiftCluster,
	nodePoolSubscription *arm.Subscription,
	nodePool *api.HCPOpenShiftClusterNodePool,
) error {
	if nodePool.Properties.Platform.OSDisk.DiskType != api.OsDiskTypeEphemeral {
		return nil
	}

	vmSize := nodePool.Properties.Platform.VMSize
	sku, err := v.resourceSKUsCachedReader.GetVirtualMachineSKU(
		ctx,
		*nodePoolSubscription.Properties.TenantId,
		nodePool.ID.SubscriptionID,
		vmSize,
	)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get Resource SKU for VM size %q: %w", vmSize, err))
	}

	if !resourceSKUCapabilityEnabled(sku, capabilityEphemeralOSDiskSupported) {
		return utils.TrackError(fmt.Errorf(
			"VM size %q does not support ephemeral OS disks",
			vmSize,
		))
	}

	return nil
}
