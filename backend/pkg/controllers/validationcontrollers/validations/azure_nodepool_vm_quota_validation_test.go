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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	azureclient "github.com/Azure/ARO-HCP/backend/pkg/azure/client"
	"github.com/Azure/ARO-HCP/internal/api"
)

const (
	testVMFamily           = "standardDASv4Family"
	testFamilyLocalized    = "Standard DASv4 Family vCPUs"
	testRegionalLocalized  = "Total Regional vCPUs"
	testLocation           = "eastus"
)

type mockUsageClient struct {
	usages   []*armcompute.Usage
	fetchErr error
	location string
	calls    int
}

var _ azureclient.UsageClient = (*mockUsageClient)(nil)

func (m *mockUsageClient) NewListPager(location string, _ *armcompute.UsageClientListOptions) *runtime.Pager[armcompute.UsageClientListResponse] {
	m.calls++
	m.location = location
	pages := []armcompute.UsageClientListResponse{{
		ListUsagesResult: armcompute.ListUsagesResult{Value: m.usages},
	}}
	idx := -1
	fetchErr := m.fetchErr
	return runtime.NewPager(runtime.PagingHandler[armcompute.UsageClientListResponse]{
		More: func(page armcompute.UsageClientListResponse) bool {
			return idx+1 < len(pages)
		},
		Fetcher: func(ctx context.Context, page *armcompute.UsageClientListResponse) (armcompute.UsageClientListResponse, error) {
			if fetchErr != nil {
				return armcompute.UsageClientListResponse{}, fetchErr
			}
			idx++
			return pages[idx], nil
		},
	})
}

type mockFPAClientBuilder struct {
	usageClient azureclient.UsageClient
	usageErr    error
}

func (m *mockFPAClientBuilder) BuilderType() azureclient.FirstPartyApplicationClientBuilderType {
	return azureclient.FirstPartyApplicationClientBuilderTypeValue
}

func (m *mockFPAClientBuilder) ResourceGroupsClient(string, string) (azureclient.ResourceGroupsClient, error) {
	panic("unexpected ResourceGroupsClient call")
}

func (m *mockFPAClientBuilder) ResourceProvidersClient(string, string) (azureclient.ResourceProvidersClient, error) {
	panic("unexpected ResourceProvidersClient call")
}

func (m *mockFPAClientBuilder) ResourceSKUsClient(string, string) (azureclient.ResourceSKUsClient, error) {
	panic("unexpected ResourceSKUsClient call")
}

func (m *mockFPAClientBuilder) UsageClient(string, string) (azureclient.UsageClient, error) {
	if m.usageErr != nil {
		return nil, m.usageErr
	}
	return m.usageClient, nil
}

var _ azureclient.FirstPartyApplicationClientBuilder = (*mockFPAClientBuilder)(nil)

func makeUsage(name, localized string, current int32, limit int64) *armcompute.Usage {
	return &armcompute.Usage{
		Name: &armcompute.UsageName{
			Value:          ptr.To(name),
			LocalizedValue: ptr.To(localized),
		},
		CurrentValue: ptr.To(current),
		Limit:        ptr.To(limit),
	}
}

func makeQuotaTestSKU(vcpus string) *armcompute.ResourceSKU {
	return &armcompute.ResourceSKU{
		Name:   ptr.To(testVMSize),
		Family: ptr.To(testVMFamily),
		Capabilities: []*armcompute.ResourceSKUCapabilities{
			{Name: ptr.To(capabilityVCPUs), Value: ptr.To(vcpus)},
		},
	}
}

func newQuotaTestNodePool(t *testing.T, replicas int32, autoScaling *api.NodePoolAutoScaling) *api.HCPOpenShiftClusterNodePool {
	t.Helper()
	np := newTestNodePool(t, api.OsDiskTypeManaged, testVMSize)
	np.Location = testLocation
	np.Properties.Replicas = replicas
	np.Properties.AutoScaling = autoScaling
	return np
}

func TestAzureNodePoolVMQuotaValidation_Validate(t *testing.T) {
	ctx := context.Background()
	cluster := &api.HCPOpenShiftCluster{}
	subscription := newTestSubscription()

	tests := []struct {
		name         string
		nodePool     *api.HCPOpenShiftClusterNodePool
		skuReader    *mockResourceSKUsCachedReader
		fpaBuilder   *mockFPAClientBuilder
		wantErr      string
		wantSKUCalls int
		wantUsageLoc string
	}{
		{
			name:     "zero replicas skips quota checks",
			nodePool: newQuotaTestNodePool(t, 0, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{},
			},
		},
		{
			name:     "fixed replicas succeeds when family and regional quota are sufficient",
			nodePool: newQuotaTestNodePool(t, 3, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						makeUsage(testVMFamily, testFamilyLocalized, 10, 100),
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 50, 200),
					},
				},
			},
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name: "autoscaling uses max for required instances",
			nodePool: newQuotaTestNodePool(t, 0, &api.NodePoolAutoScaling{
				Min: 1,
				Max: 5,
			}),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						// 5 * 4 = 20 required; remaining 15 -> fail family
						makeUsage(testVMFamily, testFamilyLocalized, 85, 100),
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 50, 200),
					},
				},
			},
			wantErr:      `insufficient quota for VM size "Standard_D8ds_v5" family "standardDASv4Family": need 20 vCPUs, have 15 remaining for "Standard DASv4 Family vCPUs" (current 85, limit 100)`,
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name:     "fails when family quota is insufficient",
			nodePool: newQuotaTestNodePool(t, 4, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						makeUsage(testVMFamily, testFamilyLocalized, 90, 100),
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 10, 200),
					},
				},
			},
			wantErr:      `insufficient quota for VM size "Standard_D8ds_v5" family "standardDASv4Family": need 16 vCPUs, have 10 remaining for "Standard DASv4 Family vCPUs" (current 90, limit 100)`,
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name:     "fails when total regional quota is insufficient",
			nodePool: newQuotaTestNodePool(t, 4, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						makeUsage(testVMFamily, testFamilyLocalized, 10, 100),
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 195, 200),
					},
				},
			},
			wantErr:      `insufficient total regional vCPU quota for VM size "Standard_D8ds_v5": need 16 vCPUs, have 5 remaining for "Total Regional vCPUs" (current 195, limit 200)`,
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name:     "unlimited family limit is treated as sufficient",
			nodePool: newQuotaTestNodePool(t, 10, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("8"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						makeUsage(testVMFamily, testFamilyLocalized, 0, -1),
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 0, 1000),
					},
				},
			},
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name:     "fails when SKU lookup fails",
			nodePool: newQuotaTestNodePool(t, 2, nil),
			skuReader: &mockResourceSKUsCachedReader{
				err: errors.New("VM size not found"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{},
			},
			wantErr:      `failed to get Resource SKU for VM size "Standard_D8ds_v5": VM size not found`,
			wantSKUCalls: 1,
		},
		{
			name:     "fails when SKU is missing vCPUs capability",
			nodePool: newQuotaTestNodePool(t, 2, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: &armcompute.ResourceSKU{
					Name:   ptr.To(testVMSize),
					Family: ptr.To(testVMFamily),
				},
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{},
			},
			wantErr:      `Resource SKU for VM size "Standard_D8ds_v5" is missing a valid vCPUs capability`,
			wantSKUCalls: 1,
		},
		{
			name:     "fails when family usage is missing",
			nodePool: newQuotaTestNodePool(t, 2, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					usages: []*armcompute.Usage{
						makeUsage(usageNameTotalRegionalVCPUs, testRegionalLocalized, 10, 200),
					},
				},
			},
			wantErr:      `Compute usage for VM family "standardDASv4Family" was not found in location "eastus"`,
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
		{
			name:     "fails when usage list fails",
			nodePool: newQuotaTestNodePool(t, 2, nil),
			skuReader: &mockResourceSKUsCachedReader{
				sku: makeQuotaTestSKU("4"),
			},
			fpaBuilder: &mockFPAClientBuilder{
				usageClient: &mockUsageClient{
					fetchErr: errors.New("service unavailable"),
				},
			},
			wantErr:      `failed to list Compute usages for location "eastus": service unavailable`,
			wantSKUCalls: 1,
			wantUsageLoc: testLocation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validation := NewAzureNodePoolVMQuotaValidation(tt.skuReader, tt.fpaBuilder)

			err := validation.Validate(ctx, cluster, subscription, tt.nodePool)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantSKUCalls, tt.skuReader.calls)
			if tt.wantUsageLoc != "" {
				usageClient := tt.fpaBuilder.usageClient.(*mockUsageClient)
				assert.Equal(t, 1, usageClient.calls)
				assert.Equal(t, tt.wantUsageLoc, usageClient.location)
			}
		})
	}
}

func TestAzureNodePoolVMQuotaValidation_Name(t *testing.T) {
	validation := NewAzureNodePoolVMQuotaValidation(&mockResourceSKUsCachedReader{}, &mockFPAClientBuilder{})
	assert.Equal(t, "AzureNodePoolVMQuotaValidation", validation.Name())
}

func TestRequiredInstanceCount(t *testing.T) {
	assert.Equal(t, int32(3), requiredInstanceCount(newQuotaTestNodePool(t, 3, nil)))
	assert.Equal(t, int32(7), requiredInstanceCount(newQuotaTestNodePool(t, 1, &api.NodePoolAutoScaling{
		Min: 1,
		Max: 7,
	})))
}
