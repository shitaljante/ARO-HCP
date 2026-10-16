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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

	"github.com/Azure/ARO-HCP/backend/pkg/utils/controllerutils"
	"github.com/Azure/ARO-HCP/backend/pkg/utils/statusutils"
	"github.com/Azure/ARO-HCP/internal/api/coreapi"
	"github.com/Azure/ARO-HCP/internal/api/metadataapi"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstoragetesting/corecosmosstoragetesting"
	"github.com/Azure/ARO-HCP/internal/database/listertesting/corelistertesting"
)

// mustMakeCAPEM creates a self-signed CA PEM for testing with the specified
// subject CN and validity window.
func mustMakeCAPEM(t *testing.T, cn string, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate test CA key")
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err, "create test CA certificate")
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestCACertValidityConditions exercises the getCaCertValidityConditions helper in isolation,
// covering both the expiry and not-yet-valid cases. Certs use wide margins
// around time.Now() so the assertions are not sensitive to wall-clock drift.
func TestCACertValidityConditions(t *testing.T) {
	now := time.Now()

	validCA := mustMakeCAPEM(t, "valid-ca", now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
	expiredCA := mustMakeCAPEM(t, "expired-ca", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	futureCA := mustMakeCAPEM(t, "future-ca", now.Add(24*time.Hour), now.Add(90*24*time.Hour))

	tests := []struct {
		name               string
		ca                 string
		expectExpiryStatus metav1.ConditionStatus
		expectExpiryReason string
		expectExpiryMsg    string
		expectNYVStatus    metav1.ConditionStatus
		expectNYVReason    string
		expectNYVMsg       string
	}{
		{
			name:               "empty CA — both False",
			ca:                 "",
			expectExpiryStatus: metav1.ConditionFalse,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
			expectNYVStatus:    metav1.ConditionFalse,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:               "currently valid CA — both False",
			ca:                 validCA,
			expectExpiryStatus: metav1.ConditionFalse,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
			expectNYVStatus:    metav1.ConditionFalse,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:               "expired CA — expiry True, notYetValid False",
			ca:                 expiredCA,
			expectExpiryStatus: metav1.ConditionTrue,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectExpiryMsg:    "have expired",
			expectNYVStatus:    metav1.ConditionFalse,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:               "future CA — expiry False, notYetValid True",
			ca:                 futureCA,
			expectExpiryStatus: metav1.ConditionFalse,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
			expectNYVStatus:    metav1.ConditionTrue,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectNYVMsg:       "are not yet valid",
		},
		{
			name:               "bundle: one valid, one expired — expiry True",
			ca:                 validCA + expiredCA,
			expectExpiryStatus: metav1.ConditionTrue,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectExpiryMsg:    "have expired",
			expectNYVStatus:    metav1.ConditionFalse,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:               "bundle: one valid, one future — notYetValid True",
			ca:                 validCA + futureCA,
			expectExpiryStatus: metav1.ConditionFalse,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
			expectNYVStatus:    metav1.ConditionTrue,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectNYVMsg:       "are not yet valid",
		},
		{
			name:               "bundle: expired and future — both True",
			ca:                 expiredCA + futureCA,
			expectExpiryStatus: metav1.ConditionTrue,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectExpiryMsg:    "have expired",
			expectNYVStatus:    metav1.ConditionTrue,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectNYVMsg:       "are not yet valid",
		},
		{
			name:               "unparseable PEM — both False",
			ca:                 "NOT A PEM",
			expectExpiryStatus: metav1.ConditionFalse,
			expectExpiryReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
			expectNYVStatus:    metav1.ConditionFalse,
			expectNYVReason:    coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expiry, notYetValid := getCaCertValidityConditions(tc.ca)

			assert.Equal(t, coreapi.ExternalAuthOIDCIssuerCACertificateExpiredCondition, expiry.Type)
			assert.Equal(t, tc.expectExpiryStatus, expiry.Status, "expiry status")
			assert.Equal(t, tc.expectExpiryReason, expiry.Reason, "expiry reason")
			if tc.expectExpiryMsg != "" {
				assert.Contains(t, expiry.Message, tc.expectExpiryMsg, "expiry message")
			}

			assert.Equal(t, coreapi.ExternalAuthOIDCIssuerCACertificateNotYetValidCondition, notYetValid.Type)
			assert.Equal(t, tc.expectNYVStatus, notYetValid.Status, "notYetValid status")
			assert.Equal(t, tc.expectNYVReason, notYetValid.Reason, "notYetValid reason")
			if tc.expectNYVMsg != "" {
				assert.Contains(t, notYetValid.Message, tc.expectNYVMsg, "notYetValid message")
			}
		})
	}
}

// TestExternalAuthUserFacingAggregator_SyncOnce_CACertConditions verifies that SyncOnce
// correctly aggregates CA certificate validity conditions from SPEA (set by
// the CA cert validity controller) into the Degraded condition on
// ExternalAuth.Status.UserFacingConditions.
func TestExternalAuthUserFacingAggregator_SyncOnce_CACertConditions(t *testing.T) {
	tests := []struct {
		name                string
		speaConditions      []metav1.Condition
		wantStatus          metav1.ConditionStatus
		wantMessageContains string
	}{
		{
			name:           "no conditions on SPEA — Degraded=Unknown (not yet reported)",
			speaConditions: nil,
			wantStatus:     metav1.ConditionUnknown,
		},
		{
			name: "expired CA condition on SPEA — Degraded=True",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateExpiredCondition, Status: metav1.ConditionTrue, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation, Message: "1 CA certificate(s) in the issuer bundle have expired: CN=test-ca"},
			},
			wantStatus:          metav1.ConditionTrue,
			wantMessageContains: "have expired",
		},
		{
			name: "not-yet-valid CA condition on SPEA — Degraded=True",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateNotYetValidCondition, Status: metav1.ConditionTrue, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation, Message: "1 CA certificate(s) in the issuer bundle are not yet valid: CN=test-ca"},
			},
			wantStatus:          metav1.ConditionTrue,
			wantMessageContains: "are not yet valid",
		},
		{
			name: "CA cert conditions False on SPEA — Degraded=False",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateExpiredCondition, Status: metav1.ConditionFalse, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected, Message: coreapi.ExternalAuthMessageAllOperational},
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateNotYetValidCondition, Status: metav1.ConditionFalse, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected, Message: coreapi.ExternalAuthMessageAllOperational},
			},
			wantStatus: metav1.ConditionFalse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			parentClusterID := metadataapi.Must(azcorearm.ParseResourceID(
				"/subscriptions/" + statusutils.TestSubscriptionID +
					"/resourceGroups/" + statusutils.TestResourceGroupName +
					"/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/" + statusutils.TestClusterName,
			))
			existing := newTestExternalAuthForAggregatorTests()
			serviceProviderExternalAuth := newTestServiceProviderExternalAuth(func(spea *coreapi.ServiceProviderExternalAuth) {
				spea.Status.Conditions = tc.speaConditions
			})
			parentCluster := &coreapi.Cluster{
				CosmosMetadata: coreapi.CosmosMetadata{
					ResourceID:   parentClusterID,
					PartitionKey: strings.ToLower(parentClusterID.SubscriptionID),
				},
				TrackedResource: coreapi.TrackedResource{
					Resource: coreapi.Resource{ID: parentClusterID, Name: statusutils.TestClusterName, Type: parentClusterID.ResourceType.String()},
				},
			}

			mockDB, err := corecosmosstoragetesting.NewMockResourcesDBClientWithResources(ctx, []any{parentCluster, existing, serviceProviderExternalAuth})
			require.NoError(t, err)

			syncer := &externalAuthUserFacingConditionsDegradedAggregator{
				externalAuthLister:                &corelistertesting.DBExternalAuthLister{ResourcesDBClient: mockDB},
				serviceProviderExternalAuthLister: &corelistertesting.DBServiceProviderExternalAuthLister{ResourcesDBClient: mockDB},
				resourcesDBClient:                 mockDB,
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

			degraded := apimeta.FindStatusCondition(updated.Status.UserFacingConditions, statusutils.DegradedConditionType)
			require.NotNil(t, degraded, "Degraded condition must always be present")
			assert.Equal(t, tc.wantStatus, degraded.Status, "Degraded status")
			if tc.wantMessageContains != "" {
				assert.Contains(t, degraded.Message, tc.wantMessageContains, "Degraded message")
			}
		})
	}
}
