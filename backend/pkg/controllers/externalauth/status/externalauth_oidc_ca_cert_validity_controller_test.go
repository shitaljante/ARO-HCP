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

// TestGetCaCertValidityCondition exercises the getCaCertValidityCondition helper
// in isolation, covering expired, not-yet-valid, mixed, and healthy cases.
// Certs use wide margins around time.Now() so assertions are not sensitive to
// wall-clock drift.
func TestGetCaCertValidityCondition(t *testing.T) {
	now := time.Now()

	validCA := mustMakeCAPEM(t, "valid-ca", now.Add(-24*time.Hour), now.Add(90*24*time.Hour))
	expiredCA := mustMakeCAPEM(t, "expired-ca", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	futureCA := mustMakeCAPEM(t, "future-ca", now.Add(24*time.Hour), now.Add(90*24*time.Hour))

	tests := []struct {
		name         string
		ca           string
		expectStatus metav1.ConditionStatus
		expectReason string
		expectMsg    string
	}{
		{
			name:         "empty CA — False",
			ca:           "",
			expectStatus: metav1.ConditionFalse,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:         "currently valid CA — False",
			ca:           validCA,
			expectStatus: metav1.ConditionFalse,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
		{
			name:         "expired CA — True with expiry message",
			ca:           expiredCA,
			expectStatus: metav1.ConditionTrue,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectMsg:    "have expired",
		},
		{
			name:         "future CA — True with not-yet-valid message",
			ca:           futureCA,
			expectStatus: metav1.ConditionTrue,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectMsg:    "are not yet valid",
		},
		{
			name:         "bundle: one valid, one expired — True",
			ca:           validCA + expiredCA,
			expectStatus: metav1.ConditionTrue,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectMsg:    "have expired",
		},
		{
			name:         "bundle: one valid, one future — True",
			ca:           validCA + futureCA,
			expectStatus: metav1.ConditionTrue,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectMsg:    "are not yet valid",
		},
		{
			name:         "bundle: expired and future — True with both messages",
			ca:           expiredCA + futureCA,
			expectStatus: metav1.ConditionTrue,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation,
			expectMsg:    "have expired",
		},
		{
			name:         "unparseable PEM — False",
			ca:           "NOT A PEM",
			expectStatus: metav1.ConditionFalse,
			expectReason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cond := getCaCertValidityCondition(tc.ca)

			assert.Equal(t, coreapi.ExternalAuthOIDCIssuerCACertificateValidityCompromisedCondition, cond.Type)
			assert.Equal(t, tc.expectStatus, cond.Status, "condition status")
			assert.Equal(t, tc.expectReason, cond.Reason, "condition reason")
			if tc.expectMsg != "" {
				assert.Contains(t, cond.Message, tc.expectMsg, "condition message")
			}
		})
	}
}

// TestGetCaCertValidityCondition_MixedBundle_BothMessages verifies that when the
// bundle has both expired and not-yet-valid certs, the single condition message
// contains information about both issues.
func TestGetCaCertValidityCondition_MixedBundle_BothMessages(t *testing.T) {
	now := time.Now()
	expiredCA := mustMakeCAPEM(t, "expired-ca", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	futureCA := mustMakeCAPEM(t, "future-ca", now.Add(24*time.Hour), now.Add(90*24*time.Hour))

	cond := getCaCertValidityCondition(expiredCA + futureCA)

	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Contains(t, cond.Message, "have expired", "message should mention expired certs")
	assert.Contains(t, cond.Message, "are not yet valid", "message should mention not-yet-valid certs")
}

// TestExternalAuthUserFacingAggregator_SyncOnce_CACertConditions verifies that SyncOnce
// correctly aggregates the CA certificate validity condition from SPEA (set by
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
			name: "compromised CA condition on SPEA (expired) — Degraded=True",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateValidityCompromisedCondition, Status: metav1.ConditionTrue, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation, Message: "1 CA certificate(s) in the issuer bundle have expired: CN=test-ca"},
			},
			wantStatus:          metav1.ConditionTrue,
			wantMessageContains: "have expired",
		},
		{
			name: "compromised CA condition on SPEA (not-yet-valid) — Degraded=True",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateValidityCompromisedCondition, Status: metav1.ConditionTrue, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation, Message: "1 CA certificate(s) in the issuer bundle are not yet valid: CN=test-ca"},
			},
			wantStatus:          metav1.ConditionTrue,
			wantMessageContains: "are not yet valid",
		},
		{
			name: "CA cert condition False on SPEA — Degraded=False",
			speaConditions: []metav1.Condition{
				{Type: coreapi.ExternalAuthOIDCIssuerCACertificateValidityCompromisedCondition, Status: metav1.ConditionFalse, Reason: coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected, Message: coreapi.ExternalAuthMessageAllOperational},
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
