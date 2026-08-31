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

package status

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/hypershift/api/hypershift/v1beta1"

	"github.com/Azure/ARO-HCP/backend/pkg/utils/controllerutils"
	operationtesting "github.com/Azure/ARO-HCP/backend/pkg/utils/operationutils/operationtesting"
	"github.com/Azure/ARO-HCP/backend/pkg/utils/statusutils"
	"github.com/Azure/ARO-HCP/internal/api/coreapi"
	"github.com/Azure/ARO-HCP/internal/api/kubeapplierapi"
	"github.com/Azure/ARO-HCP/internal/api/metadataapi"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstoragetesting/corecosmosstoragetesting"
	"github.com/Azure/ARO-HCP/internal/database/listertesting/corelistertesting"
	"github.com/Azure/ARO-HCP/internal/database/listertesting/kubeapplierlistertesting"
)

func TestUserFacingConditionsFromOIDCClients(t *testing.T) {
	t.Parallel()

	now := statusutils.FixedNow
	externalAuth := newTestExternalAuthForAggregator()
	consoleClient := configv1.OIDCClientStatus{
		ComponentName:      "console",
		ComponentNamespace: "openshift-console",
	}

	tests := []struct {
		name                  string
		clients               []configv1.OIDCClientStatus
		wantAvailable         metav1.ConditionStatus
		wantAvailableReason   string
		wantDegraded          metav1.ConditionStatus
		wantDegradedReason    string
		wantDegradedSubstr    string
		wantProgressing       metav1.ConditionStatus
		wantProgressingReason string
	}{
		{
			name:                  "no OIDC clients emits Progressing pending",
			clients:               nil,
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionFalse,
			wantDegradedReason:    reasonAsExpected,
			wantProgressing:       metav1.ConditionTrue,
			wantProgressingReason: reasonOIDCConfigPending,
		},
		{
			name: "Available True OIDCConfigAvailable",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:   userFacingConditionTypeAvailable,
					Status: metav1.ConditionTrue,
					Reason: reasonOIDCConfigAvailable,
				}),
			},
			wantAvailable:         metav1.ConditionTrue,
			wantAvailableReason:   reasonOIDCConfigAvailable,
			wantDegraded:          metav1.ConditionFalse,
			wantDegradedReason:    reasonAsExpected,
			wantProgressing:       metav1.ConditionFalse,
			wantProgressingReason: reasonAsExpected,
		},
		{
			name: "Degraded True OIDCClientSecretGet",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:   userFacingConditionTypeDegraded,
					Status: metav1.ConditionTrue,
					Reason: reasonOIDCClientSecretGet,
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionTrue,
			wantDegradedReason:    reasonOIDCClientSecretGet,
			wantDegradedSubstr:    "openshift-config",
			wantProgressing:       metav1.ConditionFalse,
			wantProgressingReason: reasonAsExpected,
		},
		{
			name: "Progressing True DeploymentOIDCConfig",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:    userFacingConditionTypeProgressing,
					Status:  metav1.ConditionTrue,
					Reason:  "DeploymentOIDCConfig",
					Message: "deploying oauth",
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionFalse,
			wantDegradedReason:    reasonAsExpected,
			wantProgressing:       metav1.ConditionTrue,
			wantProgressingReason: "DeploymentOIDCConfig",
		},
		{
			name: "Progressing True CLIOIDCConfigAvailable",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(configv1.OIDCClientStatus{
					ComponentName:      "cli",
					ComponentNamespace: "openshift-console",
				}, metav1.Condition{
					Type:   userFacingConditionTypeProgressing,
					Status: metav1.ConditionTrue,
					Reason: "CLIOIDCConfigAvailable",
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionFalse,
			wantDegradedReason:    reasonAsExpected,
			wantProgressing:       metav1.ConditionTrue,
			wantProgressingReason: "CLIOIDCConfigAvailable",
		},
		{
			name: "Degraded True with error reason",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:    userFacingConditionTypeDegraded,
					Status:  metav1.ConditionTrue,
					Reason:  "OIDCClientConfigInvalid",
					Message: "client secret is invalid",
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionTrue,
			wantDegradedReason:    "OIDCClientConfigInvalid",
			wantDegradedSubstr:    "client secret is invalid",
			wantProgressing:       metav1.ConditionFalse,
			wantProgressingReason: reasonAsExpected,
		},
		{
			name: "OIDCClientSecretGet preferred over other Degraded reasons",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:    userFacingConditionTypeDegraded,
					Status:  metav1.ConditionTrue,
					Reason:  reasonOIDCClientSecretGet,
					Message: "missing secret",
				}),
				withOIDCConditions(configv1.OIDCClientStatus{
					ComponentName:      "cli",
					ComponentNamespace: "openshift-console",
				}, metav1.Condition{
					Type:    userFacingConditionTypeDegraded,
					Status:  metav1.ConditionTrue,
					Reason:  "SomeOtherError",
					Message: "boom",
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionTrue,
			wantDegradedReason:    reasonOIDCClientSecretGet,
			wantDegradedSubstr:    "missing secret",
			wantProgressing:       metav1.ConditionFalse,
			wantProgressingReason: reasonAsExpected,
		},
		{
			name: "all clients must be Available for Available True",
			clients: []configv1.OIDCClientStatus{
				withOIDCConditions(consoleClient, metav1.Condition{
					Type:   userFacingConditionTypeAvailable,
					Status: metav1.ConditionTrue,
					Reason: reasonOIDCConfigAvailable,
				}),
				withOIDCConditions(configv1.OIDCClientStatus{
					ComponentName:      "cli",
					ComponentNamespace: "openshift-console",
				}, metav1.Condition{
					Type:   userFacingConditionTypeProgressing,
					Status: metav1.ConditionTrue,
					Reason: "CLIOIDCConfigAvailable",
				}),
			},
			wantAvailable:         metav1.ConditionFalse,
			wantAvailableReason:   reasonOIDCConfigPending,
			wantDegraded:          metav1.ConditionFalse,
			wantDegradedReason:    reasonAsExpected,
			wantProgressing:       metav1.ConditionTrue,
			wantProgressingReason: "CLIOIDCConfigAvailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := userFacingConditionsFromOIDCClients(now, nil, tt.clients, externalAuth)

			available := apimeta.FindStatusCondition(got, userFacingConditionTypeAvailable)
			require.NotNil(t, available)
			assert.Equal(t, tt.wantAvailable, available.Status)
			assert.Equal(t, tt.wantAvailableReason, available.Reason)

			degraded := apimeta.FindStatusCondition(got, userFacingConditionTypeDegraded)
			require.NotNil(t, degraded)
			assert.Equal(t, tt.wantDegraded, degraded.Status)
			assert.Equal(t, tt.wantDegradedReason, degraded.Reason)
			if tt.wantDegradedSubstr != "" {
				assert.Contains(t, degraded.Message, tt.wantDegradedSubstr)
			}

			progressing := apimeta.FindStatusCondition(got, userFacingConditionTypeProgressing)
			require.NotNil(t, progressing)
			assert.Equal(t, tt.wantProgressing, progressing.Status)
			assert.Equal(t, tt.wantProgressingReason, progressing.Reason)
		})
	}
}

func TestMatchingOIDCClientStatuses(t *testing.T) {
	t.Parallel()

	observed := []configv1.OIDCClientStatus{
		{ComponentName: "console", ComponentNamespace: "openshift-console"},
		{ComponentName: "cli", ComponentNamespace: "openshift-console"},
	}

	t.Run("no external auth clients returns all observed", func(t *testing.T) {
		t.Parallel()
		got := matchingOIDCClientStatuses(newTestExternalAuthForAggregator(), observed)
		assert.Equal(t, observed, got)
	})

	t.Run("filters to matching component name and namespace", func(t *testing.T) {
		t.Parallel()
		ea := newTestExternalAuthForAggregator(func(ea *coreapi.HCPOpenShiftClusterExternalAuth) {
			ea.Properties.Clients = []coreapi.ExternalAuthClientProfile{
				{
					Component: coreapi.ExternalAuthClientComponentProfile{
						Name:                "console",
						AuthClientNamespace: "openshift-console",
					},
				},
			}
		})
		got := matchingOIDCClientStatuses(ea, observed)
		require.Len(t, got, 1)
		assert.Equal(t, "console", got[0].ComponentName)
	})
}

func TestExternalAuthOIDCClientStatus_SyncOnce(t *testing.T) {
	t.Parallel()

	parentClusterID := metadataapi.Must(azcorearm.ParseResourceID(
		"/subscriptions/" + statusutils.TestSubscriptionID +
			"/resourceGroups/" + statusutils.TestResourceGroupName +
			"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + statusutils.TestClusterName,
	))

	newParentCluster := func() *coreapi.HCPOpenShiftCluster {
		return &coreapi.HCPOpenShiftCluster{
			CosmosMetadata: coreapi.CosmosMetadata{
				ResourceID:   parentClusterID,
				PartitionKey: strings.ToLower(parentClusterID.SubscriptionID),
			},
			TrackedResource: coreapi.TrackedResource{
				Resource: coreapi.Resource{ID: parentClusterID, Name: statusutils.TestClusterName, Type: parentClusterID.ResourceType.String()},
			},
		}
	}

	hostedClusterWithOIDC := func(clients ...configv1.OIDCClientStatus) *v1beta1.HostedCluster {
		return &v1beta1.HostedCluster{
			Status: v1beta1.HostedClusterStatus{
				Configuration: &v1beta1.ConfigurationStatus{
					Authentication: configv1.AuthenticationStatus{
						OIDCClients: clients,
					},
				},
			},
		}
	}

	tests := []struct {
		name                string
		externalAuth        *coreapi.HCPOpenShiftClusterExternalAuth
		hostedCluster       *v1beta1.HostedCluster
		wantAvailable       metav1.ConditionStatus
		wantAvailableReason string
		wantDegradedReason  string
		skipConditions      bool
	}{
		{
			name:                "no HostedCluster emits Progressing pending",
			externalAuth:        newTestExternalAuthForAggregator(),
			wantAvailable:       metav1.ConditionFalse,
			wantAvailableReason: reasonOIDCConfigPending,
			wantDegradedReason:  reasonAsExpected,
		},
		{
			name:                "HostedCluster without authentication status emits Progressing pending",
			externalAuth:        newTestExternalAuthForAggregator(),
			hostedCluster:       &v1beta1.HostedCluster{},
			wantAvailable:       metav1.ConditionFalse,
			wantAvailableReason: reasonOIDCConfigPending,
			wantDegradedReason:  reasonAsExpected,
		},
		{
			name:         "mirrors Available True OIDCConfigAvailable",
			externalAuth: newTestExternalAuthForAggregator(),
			hostedCluster: hostedClusterWithOIDC(withOIDCConditions(configv1.OIDCClientStatus{
				ComponentName:      "console",
				ComponentNamespace: "openshift-console",
			}, metav1.Condition{
				Type:   userFacingConditionTypeAvailable,
				Status: metav1.ConditionTrue,
				Reason: reasonOIDCConfigAvailable,
			})),
			wantAvailable:       metav1.ConditionTrue,
			wantAvailableReason: reasonOIDCConfigAvailable,
			wantDegradedReason:  reasonAsExpected,
		},
		{
			name: "skips when deletion timestamp is set",
			externalAuth: newTestExternalAuthForAggregator(func(ea *coreapi.HCPOpenShiftClusterExternalAuth) {
				ea.ServiceProviderProperties.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			}),
			hostedCluster: hostedClusterWithOIDC(withOIDCConditions(configv1.OIDCClientStatus{
				ComponentName:      "console",
				ComponentNamespace: "openshift-console",
			}, metav1.Condition{
				Type:   userFacingConditionTypeAvailable,
				Status: metav1.ConditionTrue,
				Reason: reasonOIDCConfigAvailable,
			})),
			skipConditions: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()

			seed := []any{newParentCluster(), tt.externalAuth}
			mockDB, err := corecosmosstoragetesting.NewMockResourcesDBClientWithResources(ctx, seed)
			require.NoError(t, err)

			lister := &kubeapplierlistertesting.SliceReadDesireLister{}
			if tt.hostedCluster != nil {
				lister.Desires = []*kubeapplierapi.ReadDesire{operationtesting.NewHostedClusterReadDesire(t, tt.hostedCluster)}
			}

			syncer := &externalAuthOIDCClientStatusSyncer{
				externalAuthLister: &corelistertesting.DBExternalAuthLister{ResourcesDBClient: mockDB},
				readDesireLister:   lister,
				resourcesDBClient:  mockDB,
				clock:              clocktesting.NewFakePassiveClock(statusutils.FixedNow),
			}

			err = syncer.SyncOnce(ctx, controllerutils.HCPExternalAuthKey{
				SubscriptionID:      statusutils.TestSubscriptionID,
				ResourceGroupName:   statusutils.TestResourceGroupName,
				HCPClusterName:      statusutils.TestClusterName,
				HCPExternalAuthName: statusutils.TestExternalAuthName,
			})
			require.NoError(t, err)

			updated, err := mockDB.HCPClusters(statusutils.TestSubscriptionID, statusutils.TestResourceGroupName).ExternalAuth(statusutils.TestClusterName).Get(ctx, statusutils.TestExternalAuthName)
			require.NoError(t, err)

			if tt.skipConditions {
				assert.Empty(t, updated.Status.UserFacingConditions)
				return
			}

			available := apimeta.FindStatusCondition(updated.Status.UserFacingConditions, userFacingConditionTypeAvailable)
			require.NotNil(t, available)
			assert.Equal(t, tt.wantAvailable, available.Status)
			assert.Equal(t, tt.wantAvailableReason, available.Reason)

			degraded := apimeta.FindStatusCondition(updated.Status.UserFacingConditions, userFacingConditionTypeDegraded)
			require.NotNil(t, degraded)
			assert.Equal(t, tt.wantDegradedReason, degraded.Reason)
		})
	}
}

func withOIDCConditions(client configv1.OIDCClientStatus, conditions ...metav1.Condition) configv1.OIDCClientStatus {
	client.Conditions = append([]metav1.Condition(nil), conditions...)
	return client
}
