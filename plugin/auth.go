package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	hauth "github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/odata"
	"github.com/mitchellh/mapstructure"
)

type AuthorizationInfo struct {
	HamiltonConfig hauth.Config
	AuthParams     AuthParams
}

// The allowed attribute fields from the controller to this plugin
type Attributes struct {
	SubscriptionId            string `mapstructure:"subscription_id"`
	ClientId                  string `mapstructure:"client_id"`
	TenantId                  string `mapstructure:"tenant_id"`
	DisableCredentialRotation bool   `mapstructure:"disable_credential_rotation"`
}

// The allowed secret fields passed in from the controller to this plugin
type SecretData struct {
	SecretValue          string `mapstructure:"secret_value"`
	SecretId             string `mapstructure:"secret_id"`
	CredsLastRotatedTime string `mapstructure:"creds_last_rotated_time"`
}

type AuthParams struct {
	SubscriptionId string
	ClientId       string
	ClientObjectId string
	TenantId       string

	SecretValue          string
	SecretId             string
	CredsLastRotatedTime time.Time
}

func getAuthorizationInfo(hc *hostcatalogs.HostCatalog) (*AuthorizationInfo, error) {
	switch {
	case hc == nil:
		return nil, errors.New("host catalog is nil")
	case hc.GetAttributes() == nil:
		return nil, errors.New("host catalog attributes is nil")
	case hc.GetSecrets() == nil:
		return nil, errors.New("host catalog secret data is nil")
	}

	hcFields := hc.GetAttributes().AsMap()
	var attrs Attributes
	if err := mapstructure.Decode(hcFields, &attrs); err != nil {
		return nil, fmt.Errorf("error decoding host catalog attribute fields: %w", err)
	}
	if attrs.SubscriptionId == "" {
		return nil, errors.New("subscription id is empty")
	}
	if attrs.TenantId == "" {
		return nil, errors.New("tenant id is empty")
	}

	pdFields := hc.GetSecrets().AsMap()
	var secrets SecretData
	if err := mapstructure.Decode(pdFields, &secrets); err != nil {
		return nil, fmt.Errorf("error decoding host catalog persisted data fields: %w", err)
	}
	if secrets.SecretValue == "" {
		return nil, errors.New("secret value is empty")
	}
	var lastRotatedTime time.Time
	var err error
	if secrets.CredsLastRotatedTime != "" {
		lastRotatedTime, err = time.Parse(time.RFC3339Nano, secrets.CredsLastRotatedTime)
		if err != nil {
			return nil, fmt.Errorf("error parsing last rotated time: %w", err)
		}
	}

	return &AuthorizationInfo{
		HamiltonConfig: hauth.Config{
			Environment:            environments.Global,
			TenantID:               attrs.TenantId,
			ClientID:               attrs.ClientId,
			ClientSecret:           secrets.SecretValue,
			EnableClientSecretAuth: true,
		},
		AuthParams: AuthParams{
			SubscriptionId:       attrs.SubscriptionId,
			ClientId:             attrs.ClientId,
			TenantId:             attrs.TenantId,
			SecretId:             secrets.SecretId,
			SecretValue:          secrets.SecretValue,
			CredsLastRotatedTime: lastRotatedTime,
		},
	}, nil
}

func (a *AuthorizationInfo) autorestAuthorizer() (autorest.Authorizer, error) {
	credsConfig := auth.NewClientCredentialsConfig(
		a.AuthParams.ClientId,
		a.AuthParams.SecretValue,
		a.AuthParams.TenantId,
	)
	authorizer, err := credsConfig.Authorizer()
	if err != nil {
		return nil, fmt.Errorf("error authorizing to Azure: %w", err)
	}
	if authorizer == nil {
		return nil, errors.New("generated authorizer is nil")
	}
	return authorizer, nil
}

func (a *AuthorizationInfo) populateObjectId(ctx context.Context, _ ...Option) error {
	if a.AuthParams.ClientObjectId != "" {
		return nil
	}

	if a.AuthParams.ClientId == "" {
		return errors.New("client id not known at object id lookup time")
	}
	// First, find the appId
	aClient, err := getApplicationsClient(ctx, a)
	if err != nil {
		return fmt.Errorf("error getting application client: %w", err)
	}
	if aClient == nil {
		return errors.New("applications client is nil when getting object id")
	}
	apps, _, err := aClient.List(ctx, odata.Query{
		Filter: fmt.Sprintf("appId eq '%s'", a.AuthParams.ClientId),
	})
	if err != nil {
		return fmt.Errorf("error listing applications to find objId: %w", err)
	}
	if apps == nil {
		return errors.New("nil apps returned when listing to find objId")
	}
	if len(*apps) != 1 {
		return fmt.Errorf("unexpected number of apps found, expected 1, found %d", len(*apps))
	}
	a.AuthParams.ClientObjectId = *(*apps)[0].DirectoryObject.ID

	return nil
}
