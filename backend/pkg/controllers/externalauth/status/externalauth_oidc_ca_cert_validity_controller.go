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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Azure/ARO-HCP/backend/pkg/utils/controllerutils"
	"github.com/Azure/ARO-HCP/internal/api/coreapi"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstorage/corecosmosstorage"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstorage/cosmosstorageutils"
	"github.com/Azure/ARO-HCP/internal/database/informers/coreinformers"
	"github.com/Azure/ARO-HCP/internal/database/listers/corelisters"
	"github.com/Azure/ARO-HCP/internal/utils"
)

const (
	// ExternalAuthCACertValidityControllerName is the controller name used for
	// metrics labels, ctx values, log fields, and the Controller document name.
	ExternalAuthCACertValidityControllerName = "ExternalAuthCACertValidityController"
)

// externalAuthCACertValidityController reads the CA certificate PEM from the
// ExternalAuth and produces two conditions on
// ServiceProviderExternalAuth.Status.Conditions:
//   - OIDCIssuerCACertificateExpired: True when any cert in the bundle has expired.
//   - OIDCIssuerCACertificateNotYetValid: True when any cert has a NotBefore in the future.
//
// This controller is independent of HostedCluster state. It only inspects the
// CA PEM stored on the ExternalAuth document. The
// ExternalAuthUserFacingDegradedAggregator reads these conditions (alongside
// OIDCClientsDegraded) and folds them into the single user-facing Degraded
// condition on ExternalAuth.Status.UserFacingConditions.
//
// IMPORTANT: Messages written to these conditions are surfaced verbatim to
// end users through the ARM API. Never include internal implementation
// details or cluster infrastructure paths in condition messages.
type externalAuthCACertValidityController struct {
	externalAuthLister                corelisters.ExternalAuthLister
	serviceProviderExternalAuthLister corelisters.ServiceProviderExternalAuthLister
	resourcesDBClient                 corecosmosstorage.ResourcesDBClient
}

var _ controllerutils.ExternalAuthSyncer = (*externalAuthCACertValidityController)(nil)

// NewExternalAuthCACertValidityController creates a controller that inspects
// the CA certificate PEM on the ExternalAuth and writes expiry/not-yet-valid
// conditions onto ServiceProviderExternalAuth.Status.Conditions. The
// ExternalAuthUserFacingDegradedAggregator is responsible for promoting these
// into the user-facing Degraded condition.
//
// Messages written to these conditions are surfaced to end users through the
// ARM API. Ensure all messages are safe for external consumption.
func NewExternalAuthCACertValidityController(
	resourcesDBClient corecosmosstorage.ResourcesDBClient,
	externalAuthLister corelisters.ExternalAuthLister,
	serviceProviderExternalAuthLister corelisters.ServiceProviderExternalAuthLister,
	informers coreinformers.BackendInformers,
) controllerutils.Controller {
	syncer := &externalAuthCACertValidityController{
		externalAuthLister:                externalAuthLister,
		serviceProviderExternalAuthLister: serviceProviderExternalAuthLister,
		resourcesDBClient:                 resourcesDBClient,
	}
	return controllerutils.NewExternalAuthWatchingController(
		ExternalAuthCACertValidityControllerName,
		resourcesDBClient,
		informers,
		1*time.Minute,
		syncer,
	)
}

func (c *externalAuthCACertValidityController) needsWork(externalAuth *coreapi.ExternalAuth) bool {
	return externalAuth.ServiceProviderProperties.DeletionTimestamp == nil
}

func (c *externalAuthCACertValidityController) SyncOnce(ctx context.Context, key controllerutils.HCPExternalAuthKey) error {
	existing, err := c.externalAuthLister.Get(ctx, key.SubscriptionID, key.ResourceGroupName, key.HCPClusterName, key.HCPExternalAuthName)
	if cosmosstorageutils.IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get ExternalAuth from cache: %w", err))
	}

	if !c.needsWork(existing) {
		return nil
	}

	serviceProviderExternalAuth, err := c.serviceProviderExternalAuthLister.Get(ctx, key.SubscriptionID, key.ResourceGroupName, key.HCPClusterName, key.HCPExternalAuthName)
	if cosmosstorageutils.IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get ServiceProviderExternalAuth from cache: %w", err))
	}

	expiryCond, notYetValidCond := getCaCertValidityConditions(existing.Properties.Issuer.CA)

	replacement := serviceProviderExternalAuth.DeepCopy()
	apimeta.SetStatusCondition(&replacement.Status.Conditions, expiryCond)
	apimeta.SetStatusCondition(&replacement.Status.Conditions, notYetValidCond)

	if equality.Semantic.DeepEqual(serviceProviderExternalAuth.Status.Conditions, replacement.Status.Conditions) {
		return nil
	}

	serviceProviderExternalAuthCRUD := c.resourcesDBClient.ServiceProviderExternalAuths(key.SubscriptionID, key.ResourceGroupName, key.HCPClusterName, key.HCPExternalAuthName)
	_, err = serviceProviderExternalAuthCRUD.Replace(ctx, replacement, nil)
	if cosmosstorageutils.IsPreconditionFailedError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to replace ServiceProviderExternalAuth: %w", err))
	}
	return nil
}

// getCaCertValidityConditions inspects all CERTIFICATE PEM blocks in ca and returns
// two conditions: expiryCond (CACertificateExpired) and notYetValidCond (CACertificateNotYetValid).
//   - expiryCond is True when any cert has expired;
//   - notYetValidCond is True when any cert has a start date in the future;
//
// When the CA is empty or contains no parseable certificates, both conditions
// are returned as False/AsExpected.
func getCaCertValidityConditions(ca string) (expiryCond, notYetValidCond metav1.Condition) {
	expiryCond = metav1.Condition{
		Type:    coreapi.ExternalAuthOIDCIssuerCACertificateExpiredCondition,
		Status:  metav1.ConditionFalse,
		Reason:  coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		Message: coreapi.ExternalAuthMessageAllOperational,
	}
	notYetValidCond = metav1.Condition{
		Type:    coreapi.ExternalAuthOIDCIssuerCACertificateNotYetValidCondition,
		Status:  metav1.ConditionFalse,
		Reason:  coreapi.ExternalAuthOIDCClientsDegradedReasonAsExpected,
		Message: coreapi.ExternalAuthMessageAllOperational,
	}

	if ca == "" {
		return expiryCond, notYetValidCond
	}

	var expired []*x509.Certificate
	var notYetValidCerts []*x509.Certificate
	now := time.Now()

	rest := []byte(ca)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if now.After(cert.NotAfter) {
			expired = append(expired, cert)
		}
		if now.Before(cert.NotBefore) {
			notYetValidCerts = append(notYetValidCerts, cert)
		}
	}

	if len(expired) > 0 {
		expiryCond.Status = metav1.ConditionTrue
		expiryCond.Reason = coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation
		expiryCond.Message = formatCACertExpiredMessage(expired)
	}

	if len(notYetValidCerts) > 0 {
		notYetValidCond.Status = metav1.ConditionTrue
		notYetValidCond.Reason = coreapi.ExternalAuthOIDCClientsDegradedReasonDegradation
		notYetValidCond.Message = formatCACertNotYetValidMessage(notYetValidCerts)
	}

	return expiryCond, notYetValidCond
}

func formatCACertExpiredMessage(certs []*x509.Certificate) string {
	parts := make([]string, len(certs))
	for i, cert := range certs {
		parts[i] = fmt.Sprintf("CN=%s (NotAfter %s)", cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("%d CA certificate(s) in the issuer bundle have expired: %s", len(certs), strings.Join(parts, "; "))
}

func formatCACertNotYetValidMessage(certs []*x509.Certificate) string {
	parts := make([]string, len(certs))
	for i, cert := range certs {
		parts[i] = fmt.Sprintf("CN=%s (NotBefore %s)", cert.Subject.CommonName, cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("%d CA certificate(s) in the issuer bundle are not yet valid: %s", len(certs), strings.Join(parts, "; "))
}
