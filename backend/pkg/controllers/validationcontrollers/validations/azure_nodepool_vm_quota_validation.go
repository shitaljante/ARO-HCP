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
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/Azure/ARO-HCP/backend/pkg/azure/cachedreader"
	azureclient "github.com/Azure/ARO-HCP/backend/pkg/azure/client"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/api/arm"
	"github.com/Azure/ARO-HCP/internal/utils"
)

// AzureNodePoolVMQuotaValidation validates that the customer's subscription has
// enough Compute vCPU quota in the node pool's location to deploy the requested
// VM size at the requested scale (replicas, or autoscaler max).
//
// Quota is checked against both the VM size family quota and the total regional
// vCPU quota.
type AzureNodePoolVMQuotaValidation struct {
	resourceSKUsCachedReader cachedreader.ResourceSKUsCachedReader
	azureFPAClientBuilder    azureclient.FirstPartyApplicationClientBuilder
}

func NewAzureNodePoolVMQuotaValidation(
	resourceSKUsCachedReader cachedreader.ResourceSKUsCachedReader,
	azureFPAClientBuilder azureclient.FirstPartyApplicationClientBuilder,
) *AzureNodePoolVMQuotaValidation {
	return &AzureNodePoolVMQuotaValidation{
		resourceSKUsCachedReader: resourceSKUsCachedReader,
		azureFPAClientBuilder:    azureFPAClientBuilder,
	}
}

var _ NodePoolValidation = (*AzureNodePoolVMQuotaValidation)(nil)

func (v *AzureNodePoolVMQuotaValidation) Name() string {
	return "AzureNodePoolVMQuotaValidation"
}

func (v *AzureNodePoolVMQuotaValidation) Validate(
	ctx context.Context,
	_ *api.HCPOpenShiftCluster,
	nodePoolSubscription *arm.Subscription,
	nodePool *api.HCPOpenShiftClusterNodePool,
) error {
	instanceCount := requiredInstanceCount(nodePool)
	if instanceCount <= 0 {
		return nil
	}

	vmSize := nodePool.Properties.Platform.VMSize
	tenantID := *nodePoolSubscription.Properties.TenantId
	subscriptionID := nodePool.ID.SubscriptionID

	sku, err := v.resourceSKUsCachedReader.GetVirtualMachineSKU(ctx, tenantID, subscriptionID, vmSize)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get Resource SKU for VM size %q: %w", vmSize, err))
	}
	if sku.Family == nil || *sku.Family == "" {
		return utils.TrackError(fmt.Errorf("Resource SKU for VM size %q is missing family", vmSize))
	}
	family := *sku.Family

	vcpusPerInstance, ok := resourceSKUCapabilityInt(sku, capabilityVCPUs)
	if !ok || vcpusPerInstance <= 0 {
		return utils.TrackError(fmt.Errorf("Resource SKU for VM size %q is missing a valid %s capability", vmSize, capabilityVCPUs))
	}

	requiredVCPUs := int64(instanceCount) * int64(vcpusPerInstance)

	usageClient, err := v.azureFPAClientBuilder.UsageClient(tenantID, subscriptionID)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to create Usage client: %w", err))
	}

	familyUsage, regionalUsage, err := listVMQuotaUsages(ctx, usageClient, nodePool.Location, family)
	if err != nil {
		return err
	}

	if err := checkQuotaSufficient(familyUsage, requiredVCPUs); err != nil {
		return utils.TrackError(fmt.Errorf(
			"insufficient quota for VM size %q family %q: %w",
			vmSize, family, err,
		))
	}
	if err := checkQuotaSufficient(regionalUsage, requiredVCPUs); err != nil {
		return utils.TrackError(fmt.Errorf(
			"insufficient total regional vCPU quota for VM size %q: %w",
			vmSize, err,
		))
	}

	return nil
}

// requiredInstanceCount returns the number of VMs the node pool may run at peak.
// Autoscaled pools use Max; fixed pools use Replicas.
func requiredInstanceCount(nodePool *api.HCPOpenShiftClusterNodePool) int32 {
	if nodePool.Properties.AutoScaling != nil {
		return nodePool.Properties.AutoScaling.Max
	}
	return nodePool.Properties.Replicas
}

type quotaUsage struct {
	name           string
	localizedName  string
	currentValue   int32
	limit          int64
	unlimitedLimit bool
}

func listVMQuotaUsages(
	ctx context.Context,
	usageClient azureclient.UsageClient,
	location string,
	family string,
) (familyUsage, regionalUsage *quotaUsage, err error) {
	pager := usageClient.NewListPager(location, nil)
	for pager.More() {
		page, pageErr := pager.NextPage(ctx)
		if pageErr != nil {
			return nil, nil, utils.TrackError(fmt.Errorf(
				"failed to list Compute usages for location %q: %w", location, pageErr,
			))
		}
		for _, usage := range page.Value {
			parsed, ok := parseQuotaUsage(usage)
			if !ok {
				continue
			}
			if strings.EqualFold(parsed.name, family) {
				familyUsage = parsed
			}
			if strings.EqualFold(parsed.name, usageNameTotalRegionalVCPUs) {
				regionalUsage = parsed
			}
			if familyUsage != nil && regionalUsage != nil {
				return familyUsage, regionalUsage, nil
			}
		}
	}

	if familyUsage == nil {
		return nil, nil, utils.TrackError(fmt.Errorf(
			"Compute usage for VM family %q was not found in location %q", family, location,
		))
	}
	if regionalUsage == nil {
		return nil, nil, utils.TrackError(fmt.Errorf(
			"Compute usage %q (total regional vCPUs) was not found in location %q",
			usageNameTotalRegionalVCPUs, location,
		))
	}
	return familyUsage, regionalUsage, nil
}

func parseQuotaUsage(usage *armcompute.Usage) (*quotaUsage, bool) {
	if usage == nil || usage.Name == nil || usage.Name.Value == nil || *usage.Name.Value == "" {
		return nil, false
	}
	if usage.CurrentValue == nil || usage.Limit == nil {
		return nil, false
	}

	parsed := &quotaUsage{
		name:         *usage.Name.Value,
		currentValue: *usage.CurrentValue,
		limit:        *usage.Limit,
	}
	if usage.Name.LocalizedValue != nil {
		parsed.localizedName = *usage.Name.LocalizedValue
	}
	// Azure reports unlimited quotas as Limit == -1.
	if *usage.Limit < 0 {
		parsed.unlimitedLimit = true
	}
	return parsed, true
}

func checkQuotaSufficient(usage *quotaUsage, requiredVCPUs int64) error {
	if usage.unlimitedLimit {
		return nil
	}
	remaining := int64(usage.limit) - int64(usage.currentValue)
	if requiredVCPUs <= remaining {
		return nil
	}

	displayName := usage.name
	if usage.localizedName != "" {
		displayName = usage.localizedName
	}
	return fmt.Errorf(
		"need %d vCPUs, have %d remaining for %q (current %d, limit %d)",
		requiredVCPUs, remaining, displayName, usage.currentValue, usage.limit,
	)
}
