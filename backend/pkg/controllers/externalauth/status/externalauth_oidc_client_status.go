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
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilsclock "k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/Azure/ARO-HCP/backend/pkg/kubeapplierhelpers"
	"github.com/Azure/ARO-HCP/backend/pkg/utils/controllerutils"
	"github.com/Azure/ARO-HCP/internal/api/coreapi"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstorage/corecosmosstorage"
	"github.com/Azure/ARO-HCP/internal/database/cosmosstorage/cosmosstorageutils"
	"github.com/Azure/ARO-HCP/internal/database/informers/coreinformers"
	"github.com/Azure/ARO-HCP/internal/database/listers/corelisters"
	"github.com/Azure/ARO-HCP/internal/database/listers/kubeapplierlisters"
	"github.com/Azure/ARO-HCP/internal/utils"
)

const (
	// ExternalAuthOIDCClientStatusControllerName is the controller name used for
	// metrics labels, ctx values, log fields, and the Controller document name.
	ExternalAuthOIDCClientStatusControllerName = "ExternalAuthOIDCClientStatus"

	userFacingConditionTypeAvailable   = "Available"
	userFacingConditionTypeDegraded    = "Degraded"
	userFacingConditionTypeProgressing = "Progressing"

	reasonOIDCConfigAvailable = "OIDCConfigAvailable"
	reasonOIDCClientSecretGet = "OIDCClientSecretGet"
	reasonOIDCConfigPending   = "OIDCConfigPending"
	reasonAsExpected          = "AsExpected"
)

// externalAuthOIDCClientStatusSyncer mirrors HostedCluster
// Status.Configuration.Authentication.OIDCClients conditions onto
// HCPOpenShiftClusterExternalAuth.Status.UserFacingConditions, which the
// ARM API exposes as properties.status.conditions.
type externalAuthOIDCClientStatusSyncer struct {
	externalAuthLister corelisters.ExternalAuthLister
	readDesireLister   kubeapplierlisters.ReadDesireLister
	resourcesDBClient  corecosmosstorage.ResourcesDBClient
	clock              utilsclock.PassiveClock
}

var _ controllerutils.ExternalAuthSyncer = (*externalAuthOIDCClientStatusSyncer)(nil)

// NewExternalAuthOIDCClientStatusController creates a controller that
// copies OIDC client Available / Degraded / Progressing conditions from the
// cached HostedCluster onto the ExternalAuth's user-facing status.
func NewExternalAuthOIDCClientStatusController(
	resourcesDBClient corecosmosstorage.ResourcesDBClient,
	externalAuthLister corelisters.ExternalAuthLister,
	readDesireLister kubeapplierlisters.ReadDesireLister,
	informers coreinformers.BackendInformers,
	clock utilsclock.PassiveClock,
) controllerutils.Controller {
	if clock == nil {
		clock = utilsclock.RealClock{}
	}
	syncer := &externalAuthOIDCClientStatusSyncer{
		externalAuthLister: externalAuthLister,
		readDesireLister:   readDesireLister,
		resourcesDBClient:  resourcesDBClient,
		clock:              clock,
	}
	return controllerutils.NewExternalAuthWatchingController(
		ExternalAuthOIDCClientStatusControllerName,
		resourcesDBClient,
		informers,
		1*time.Minute,
		syncer,
	)
}

func (c *externalAuthOIDCClientStatusSyncer) SyncOnce(ctx context.Context, key controllerutils.HCPExternalAuthKey) error {
	existing, err := c.externalAuthLister.Get(ctx, key.SubscriptionID, key.ResourceGroupName, key.HCPClusterName, key.HCPExternalAuthName)
	if cosmosstorageutils.IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to get ExternalAuth from cache: %w", err))
	}
	if existing.ServiceProviderProperties.DeletionTimestamp != nil {
		return nil
	}

	hostedCluster, err := kubeapplierhelpers.GetCachedHostedClusterForCluster(
		ctx,
		c.readDesireLister,
		key.SubscriptionID,
		key.ResourceGroupName,
		key.HCPClusterName,
	)
	if err != nil {
		return utils.TrackError(err)
	}

	var oidcClients []configv1.OIDCClientStatus
	if hostedCluster != nil && hostedCluster.Status.Configuration != nil {
		oidcClients = matchingOIDCClientStatuses(existing, hostedCluster.Status.Configuration.Authentication.OIDCClients)
	}

	replacement := existing.DeepCopy()
	desired := userFacingConditionsFromOIDCClients(c.clock.Now(), existing.Status.UserFacingConditions, oidcClients, existing)
	replacement.Status.UserFacingConditions = desired
	if equality.Semantic.DeepEqual(existing.Status.UserFacingConditions, replacement.Status.UserFacingConditions) {
		return nil
	}

	externalAuthCRUD := c.resourcesDBClient.HCPClusters(key.SubscriptionID, key.ResourceGroupName).ExternalAuth(key.HCPClusterName)
	_, err = externalAuthCRUD.Replace(ctx, replacement, nil)
	if cosmosstorageutils.IsPreconditionFailedError(err) {
		return nil
	}
	if cosmosstorageutils.IsNotFoundError(err) {
		return nil
	}
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to replace ExternalAuth: %w", err))
	}
	return nil
}

// matchingOIDCClientStatuses returns HostedCluster OIDC client statuses that
// correspond to this ExternalAuth's clients (component name + namespace).
// When the ExternalAuth has no clients, all observed OIDC clients are used.
func matchingOIDCClientStatuses(externalAuth *coreapi.HCPOpenShiftClusterExternalAuth, observed []configv1.OIDCClientStatus) []configv1.OIDCClientStatus {
	if len(externalAuth.Properties.Clients) == 0 {
		return observed
	}
	wanted := make(map[string]struct{}, len(externalAuth.Properties.Clients))
	for _, client := range externalAuth.Properties.Clients {
		wanted[oidcClientKey(client.Component.Name, client.Component.AuthClientNamespace)] = struct{}{}
	}
	matched := make([]configv1.OIDCClientStatus, 0, len(observed))
	for _, client := range observed {
		if _, ok := wanted[oidcClientKey(client.ComponentName, client.ComponentNamespace)]; ok {
			matched = append(matched, client)
		}
	}
	return matched
}

func oidcClientKey(name, namespace string) string {
	return strings.ToLower(name) + "/" + strings.ToLower(namespace)
}

// userFacingConditionsFromOIDCClients unions per-client Available / Degraded /
// Progressing conditions into the three ARM condition types. Reasons are
// passed through from HostedCluster (they become part of the public API).
func userFacingConditionsFromOIDCClients(
	now time.Time,
	existing []metav1.Condition,
	clients []configv1.OIDCClientStatus,
	externalAuth *coreapi.HCPOpenShiftClusterExternalAuth,
) []metav1.Condition {
	result := append([]metav1.Condition(nil), existing...)

	available := metav1.Condition{
		Type:               userFacingConditionTypeAvailable,
		Status:             metav1.ConditionFalse,
		Reason:             reasonOIDCConfigPending,
		Message:            "Waiting for OIDC client status from the hosted cluster.",
		LastTransitionTime: metav1.NewTime(now),
	}
	degraded := metav1.Condition{
		Type:               userFacingConditionTypeDegraded,
		Status:             metav1.ConditionFalse,
		Reason:             reasonAsExpected,
		Message:            "",
		LastTransitionTime: metav1.NewTime(now),
	}
	progressing := metav1.Condition{
		Type:               userFacingConditionTypeProgressing,
		Status:             metav1.ConditionFalse,
		Reason:             reasonAsExpected,
		Message:            "",
		LastTransitionTime: metav1.NewTime(now),
	}

	if len(clients) == 0 {
		progressing.Status = metav1.ConditionTrue
		progressing.Reason = reasonOIDCConfigPending
		progressing.Message = "Waiting for OIDC client status from the hosted cluster."
		apimeta.SetStatusCondition(&result, available)
		apimeta.SetStatusCondition(&result, degraded)
		apimeta.SetStatusCondition(&result, progressing)
		return result
	}

	allAvailable := true
	anyDegraded := false
	anyProgressing := false
	secretGetMessages := make([]string, 0)
	otherDegradedMessages := make([]string, 0)
	progressingMessages := make([]string, 0)
	otherDegradedReason := ""
	progressingReason := ""

	for i := range clients {
		client := clients[i]
		availableCond := apimeta.FindStatusCondition(client.Conditions, userFacingConditionTypeAvailable)
		if availableCond == nil || availableCond.Status != metav1.ConditionTrue {
			allAvailable = false
		}

		degradedCond := apimeta.FindStatusCondition(client.Conditions, userFacingConditionTypeDegraded)
		if degradedCond != nil && degradedCond.Status == metav1.ConditionTrue {
			anyDegraded = true
			message := strings.TrimSpace(degradedCond.Message)
			if degradedCond.Reason == reasonOIDCClientSecretGet {
				if message == "" {
					message = awaitingSecretMessage(externalAuth, client)
				}
				secretGetMessages = append(secretGetMessages, message)
			} else {
				if message == "" {
					message = degradedCond.Reason
				}
				otherDegradedMessages = append(otherDegradedMessages, message)
				if otherDegradedReason == "" {
					otherDegradedReason = degradedCond.Reason
				}
			}
		}

		progressingCond := apimeta.FindStatusCondition(client.Conditions, userFacingConditionTypeProgressing)
		if progressingCond != nil && progressingCond.Status == metav1.ConditionTrue {
			anyProgressing = true
			if progressingReason == "" {
				progressingReason = progressingCond.Reason
			}
			if msg := strings.TrimSpace(progressingCond.Message); msg != "" {
				progressingMessages = append(progressingMessages, msg)
			}
		}
	}

	if allAvailable {
		available.Status = metav1.ConditionTrue
		available.Reason = reasonOIDCConfigAvailable
		available.Message = "External auth is available."
		progressing.Status = metav1.ConditionFalse
		progressing.Reason = reasonAsExpected
		progressing.Message = ""
	} else if anyProgressing {
		progressing.Status = metav1.ConditionTrue
		if progressingReason != "" {
			progressing.Reason = progressingReason
		}
		progressing.Message = strings.Join(progressingMessages, "; ")
		if progressing.Message == "" {
			progressing.Message = "External auth is still installing."
		}
	}

	if anyDegraded {
		degraded.Status = metav1.ConditionTrue
		if len(secretGetMessages) > 0 {
			degraded.Reason = reasonOIDCClientSecretGet
			degraded.Message = strings.Join(secretGetMessages, "; ")
		} else {
			degraded.Reason = otherDegradedReason
			degraded.Message = strings.Join(otherDegradedMessages, "; ")
		}
	}

	apimeta.SetStatusCondition(&result, available)
	apimeta.SetStatusCondition(&result, degraded)
	apimeta.SetStatusCondition(&result, progressing)
	return result
}

func awaitingSecretMessage(externalAuth *coreapi.HCPOpenShiftClusterExternalAuth, client configv1.OIDCClientStatus) string {
	secretName := fmt.Sprintf("%s-%s-%s", externalAuth.Name, client.ComponentName, client.ComponentNamespace)
	return fmt.Sprintf("Create the client secret %q in the openshift-config namespace.", secretName)
}
