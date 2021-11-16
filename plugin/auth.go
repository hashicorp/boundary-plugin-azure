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
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
	"github.com/mitchellh/mapstructure"
)

type AuthorizationInfo struct {
	HamiltonConfig hauth.Config
	AuthParams     AuthParams
}

type Attributes struct {
	SubscriptionId            string `mapstructure:"subscription_id"`
	ClientId                  string `mapstructure:"client_id"`
	TenantId                  string `mapstructure:"tenant_id"`
	DisableCredentialRotation bool   `mapstructure:"disable_credential_rotation"`
}

type SecretData struct {
	SecretValue          string `mapstructure:"secret_value"`
	SecretId             string `mapstructure:"secret_id"`
	CredsLastRotatedTime string `mapstructure:"creds_last_rotated_time"`
}

type AuthParams struct {
	SubscriptionId       string
	ClientId             string
	ClientObjectId       string
	TenantId             string
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

func (a *AuthorizationInfo) populateObjectId(ctx context.Context, opt ...Option) error {
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

// rotateCredentials creates a new password, then uses a client with that new
// password to revoke the old.
func rotateCredential(ctx context.Context, authzInfo *AuthorizationInfo, opt ...Option) (*msgraph.PasswordCredential, error) {
	if authzInfo == nil {
		return nil, errors.New("empty authz info")
	}
	if authzInfo.AuthParams.SecretId == "" {
		return nil, errors.New("missing original secret id")
	}

	// Ensure the object ID is set
	if err := authzInfo.populateObjectId(ctx); err != nil {
		return nil, fmt.Errorf("error fetching object id: %w", err)
	}

	newCred, err := addCredential(ctx, authzInfo)
	if err != nil {
		return nil, fmt.Errorf("error adding password: %w", err)
	}
	if newCred == nil {
		return nil, errors.New("new credential is nil after adding")
	}
	if newCred.SecretText == nil {
		return nil, errors.New("new credential secret text is nil after adding")
	}

	if err := removeCredential(ctx, authzInfo); err != nil {
		return nil, fmt.Errorf("error removing previous credential: %w", err)
	}
	return newCred, nil
}

func addCredential(ctx context.Context, authzInfo *AuthorizationInfo, opt ...Option) (*msgraph.PasswordCredential, error) {
	if authzInfo == nil {
		return nil, errors.New("empty authz info")
	}

	// Ensure the object ID is set
	if err := authzInfo.populateObjectId(ctx); err != nil {
		return nil, fmt.Errorf("error fetching object id: %w", err)
	}

	aClient, err := getApplicationsClient(ctx, authzInfo)
	if err != nil {
		return nil, fmt.Errorf("error getting application client: %w", err)
	}
	if aClient == nil {
		return nil, errors.New("applications client is nil when adding credential")
	}

	// Create the new password
	displayName := fmt.Sprintf("boundary-rotated-%s", time.Now().Format(time.RFC3339))
	newPass, _, err := aClient.AddPassword(ctx, authzInfo.AuthParams.ClientObjectId, msgraph.PasswordCredential{
		DisplayName: &displayName,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating new password: %w", err)
	}
	if newPass == nil {
		return nil, errors.New("nil new password returned")
	}
	if newPass.KeyId == nil {
		return nil, errors.New("nil key ID for new password")
	}
	if newPass.SecretText == nil {
		return nil, errors.New("nil secret text for new password")
	}

	return newPass, nil
}

func removeCredential(ctx context.Context, authzInfo *AuthorizationInfo, opt ...Option) error {
	// Ensure the object ID is set
	if err := authzInfo.populateObjectId(ctx); err != nil {
		return fmt.Errorf("error fetching object id: %w", err)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("error parsing ops: %w", err)
	}

	secretId := authzInfo.AuthParams.SecretId
	if opts.withSecretId != "" {
		secretId = opts.withSecretId
	}

	aClient, err := getApplicationsClient(ctx, authzInfo)
	if err != nil {
		return fmt.Errorf("error getting application client: %w", err)
	}
	if aClient == nil {
		return errors.New("applications client is nil when removing credential")
	}

	_, err = aClient.RemovePassword(ctx, authzInfo.AuthParams.ClientObjectId, secretId)
	if err != nil {
		return fmt.Errorf("error removing old password: %w", err)
	}

	return nil
}
