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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/utils/ptr"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/Azure/ARO-HCP/backend/pkg/azure/cachedreader"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/api/arm"
)

const (
	testTenantID       = "11111111-1111-1111-1111-111111111111"
	testSubscriptionID = "22222222-2222-2222-2222-222222222222"
	testResourceGroup  = "test-rg"
	testClusterName    = "test-cluster"
	testNodePoolName   = "test-nodepool"
	testVMSize         = "Standard_D8ds_v5"
)

type mockResourceSKUsCachedReader struct {
	sku *armcompute.ResourceSKU
	err error

	gotTenantID       string
	gotSubscriptionID string
	gotVMSize         string
	calls             int
}

var _ cachedreader.ResourceSKUsCachedReader = (*mockResourceSKUsCachedReader)(nil)

func (m *mockResourceSKUsCachedReader) ListVirtualMachineSKUs(context.Context, string, string) ([]*armcompute.ResourceSKU, error) {
	panic("unexpected ListVirtualMachineSKUs call")
}

func (m *mockResourceSKUsCachedReader) GetVirtualMachineSKU(_ context.Context, tenantID, subscriptionID, vmSize string) (*armcompute.ResourceSKU, error) {
	m.calls++
	m.gotTenantID = tenantID
	m.gotSubscriptionID = subscriptionID
	m.gotVMSize = vmSize
	if m.err != nil {
		return nil, m.err
	}
	return m.sku, nil
}

func newTestSubscription() *arm.Subscription {
	subResourceID := api.Must(azcorearm.ParseResourceID("/subscriptions/" + testSubscriptionID))
	return &arm.Subscription{
		CosmosMetadata: api.CosmosMetadata{
			ResourceID:   subResourceID,
			PartitionKey: strings.ToLower(subResourceID.SubscriptionID),
		},
		ResourceID: subResourceID,
		State:      arm.SubscriptionStateRegistered,
		Properties: &arm.SubscriptionProperties{
			TenantId: ptr.To(testTenantID),
		},
	}
}

func newTestNodePool(t *testing.T, diskType api.OsDiskType, vmSize string) *api.HCPOpenShiftClusterNodePool {
	t.Helper()
	resourceID := api.Must(azcorearm.ParseResourceID(
		"/subscriptions/" + testSubscriptionID +
			"/resourceGroups/" + testResourceGroup +
			"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + testClusterName +
			"/nodePools/" + testNodePoolName))
	return &api.HCPOpenShiftClusterNodePool{
		CosmosMetadata: arm.CosmosMetadata{
			ResourceID:   resourceID,
			PartitionKey: strings.ToLower(resourceID.SubscriptionID),
		},
		TrackedResource: arm.TrackedResource{
			Resource: arm.Resource{
				ID:   resourceID,
				Name: testNodePoolName,
				Type: api.NodePoolResourceType.String(),
			},
			Location: "eastus",
		},
		Properties: api.HCPOpenShiftClusterNodePoolProperties{
			Platform: api.NodePoolPlatformProfile{
				VMSize: vmSize,
				OSDisk: api.OSDiskProfile{
					DiskType: diskType,
				},
			},
		},
	}
}

func makeVMResourceSKU(name string, capabilities ...*armcompute.ResourceSKUCapabilities) *armcompute.ResourceSKU {
	return &armcompute.ResourceSKU{
		Name:         ptr.To(name),
		Capabilities: capabilities,
	}
}

func TestAzureNodePoolEphemeralOSDiskValidation_Validate(t *testing.T) {
	ctx := context.Background()
	cluster := &api.HCPOpenShiftCluster{}
	subscription := newTestSubscription()

	tests := []struct {
		name          string
		nodePool      *api.HCPOpenShiftClusterNodePool
		reader        *mockResourceSKUsCachedReader
		wantErr       string
		wantSKUCalls  int
		wantVMSizeArg string
	}{
		{
			name:     "managed OS disk skips SKU lookup",
			nodePool: newTestNodePool(t, api.OsDiskTypeManaged, testVMSize),
			reader:   &mockResourceSKUsCachedReader{},
		},
		{
			name:     "ephemeral OS disk succeeds when capability is True",
			nodePool: newTestNodePool(t, api.OsDiskTypeEphemeral, testVMSize),
			reader: &mockResourceSKUsCachedReader{
				sku: makeVMResourceSKU(testVMSize, &armcompute.ResourceSKUCapabilities{
					Name:  ptr.To(capabilityEphemeralOSDiskSupported),
					Value: ptr.To("True"),
				}),
			},
			wantSKUCalls:  1,
			wantVMSizeArg: testVMSize,
		},
		{
			name:     "ephemeral OS disk succeeds when capability is true (case-insensitive)",
			nodePool: newTestNodePool(t, api.OsDiskTypeEphemeral, testVMSize),
			reader: &mockResourceSKUsCachedReader{
				sku: makeVMResourceSKU(testVMSize, &armcompute.ResourceSKUCapabilities{
					Name:  ptr.To("ephemeralosdisksupported"),
					Value: ptr.To("true"),
				}),
			},
			wantSKUCalls:  1,
			wantVMSizeArg: testVMSize,
		},
		{
			name:     "ephemeral OS disk fails when capability is False",
			nodePool: newTestNodePool(t, api.OsDiskTypeEphemeral, testVMSize),
			reader: &mockResourceSKUsCachedReader{
				sku: makeVMResourceSKU(testVMSize, &armcompute.ResourceSKUCapabilities{
					Name:  ptr.To(capabilityEphemeralOSDiskSupported),
					Value: ptr.To("False"),
				}),
			},
			wantErr:       `VM size "Standard_D8ds_v5" does not support ephemeral OS disks`,
			wantSKUCalls:  1,
			wantVMSizeArg: testVMSize,
		},
		{
			name:     "ephemeral OS disk fails when capability is missing",
			nodePool: newTestNodePool(t, api.OsDiskTypeEphemeral, testVMSize),
			reader: &mockResourceSKUsCachedReader{
				sku: makeVMResourceSKU(testVMSize),
			},
			wantErr:       `VM size "Standard_D8ds_v5" does not support ephemeral OS disks`,
			wantSKUCalls:  1,
			wantVMSizeArg: testVMSize,
		},
		{
			name:     "ephemeral OS disk fails when SKU lookup fails",
			nodePool: newTestNodePool(t, api.OsDiskTypeEphemeral, testVMSize),
			reader: &mockResourceSKUsCachedReader{
				err: errors.New("VM size not found"),
			},
			wantErr:       `failed to get Resource SKU for VM size "Standard_D8ds_v5": VM size not found`,
			wantSKUCalls:  1,
			wantVMSizeArg: testVMSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validation := NewAzureNodePoolEphemeralOSDiskValidation(tt.reader)

			err := validation.Validate(ctx, cluster, subscription, tt.nodePool)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
			}
			assert.Equal(t, tt.wantSKUCalls, tt.reader.calls)
			if tt.wantSKUCalls > 0 {
				assert.Equal(t, testTenantID, tt.reader.gotTenantID)
				assert.Equal(t, testSubscriptionID, tt.reader.gotSubscriptionID)
				assert.Equal(t, tt.wantVMSizeArg, tt.reader.gotVMSize)
			}
		})
	}
}

func TestAzureNodePoolEphemeralOSDiskValidation_Name(t *testing.T) {
	validation := NewAzureNodePoolEphemeralOSDiskValidation(&mockResourceSKUsCachedReader{})
	assert.Equal(t, "AzureNodePoolEphemeralOSDiskValidation", validation.Name())
}

func TestResourceSKUCapabilityEnabled(t *testing.T) {
	tests := []struct {
		name       string
		sku        *armcompute.ResourceSKU
		capability string
		want       bool
	}{
		{
			name: "nil sku",
			sku:  nil,
			want: false,
		},
		{
			name: "true value",
			sku: makeVMResourceSKU(testVMSize, &armcompute.ResourceSKUCapabilities{
				Name:  ptr.To(capabilityEphemeralOSDiskSupported),
				Value: ptr.To("True"),
			}),
			capability: capabilityEphemeralOSDiskSupported,
			want:       true,
		},
		{
			name: "false value",
			sku: makeVMResourceSKU(testVMSize, &armcompute.ResourceSKUCapabilities{
				Name:  ptr.To(capabilityEphemeralOSDiskSupported),
				Value: ptr.To("False"),
			}),
			capability: capabilityEphemeralOSDiskSupported,
			want:       false,
		},
		{
			name:       "missing capability",
			sku:        makeVMResourceSKU(testVMSize),
			capability: capabilityEphemeralOSDiskSupported,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resourceSKUCapabilityEnabled(tt.sku, tt.capability))
		})
	}
}
