package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	hauth "github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/manicminer/hamilton/odata"
	"google.golang.org/protobuf/types/known/structpb"
)

type WrappedHamiltonConfig struct {
	hauth.Config
	SecretId string
}

func authParams(hc *hostcatalogs.HostCatalog, secrets *structpb.Struct) (map[string]string, error) {
	if hc == nil {
		return nil, errors.New("host catalog is nil")
	}
	if hc.GetAttributes() == nil {
		return nil, errors.New("host catalog attributes is nil")
	}
	hcFields := hc.GetAttributes().GetFields()
	if hcFields == nil {
		return nil, errors.New("host catalog attributes fields is nil")
	}

	if secrets == nil {
		return nil, errors.New("secrets is nil")
	}
	pdFields := secrets.GetFields()
	if pdFields == nil {
		return nil, errors.New("secrets data fields is nil")
	}

	var subscriptionId string
	if hcFields[constSubscriptionId] == nil {
		return nil, errors.New("subscription id not provided in incoming data")
	}
	if subscriptionId = hcFields[constSubscriptionId].GetStringValue(); subscriptionId == "" {
		return nil, errors.New("subscription id could not be read as a string value")
	}

	ret := map[string]string{
		constSubscriptionId: subscriptionId,
	}

	clientId := hcFields[constClientId]
	secretValue := pdFields[constSecretValue]
	secretId := pdFields[constSecretId]
	tenantId := hcFields[constTenantId]

	switch {
	case clientId != nil && clientId.GetStringValue() != "" &&
		secretValue != nil && secretValue.GetStringValue() != "" &&
		tenantId != nil && tenantId.GetStringValue() != "":
		ret[constClientId] = clientId.GetStringValue()
		ret[constSecretValue] = secretValue.GetStringValue()
		ret[constTenantId] = tenantId.GetStringValue()
		if secretId != nil {
			ret[constSecretId] = secretId.GetStringValue()
		}
	}

	return ret, nil
}

func fetchAuthorizer(hc *hostcatalogs.HostCatalog, secrets *structpb.Struct) (string, autorest.Authorizer, error) {
	aParams, err := authParams(hc, secrets)
	if err != nil {
		return "", nil, fmt.Errorf("error finding authentication params: %w", err)
	}

	var authorizer autorest.Authorizer
	// Switch between currently-understood authorization types
	{
		switch {
		case aParams[constClientId] != "" &&
			aParams[constSecretValue] != "" &&
			aParams[constTenantId] != "":
			credsConfig := auth.NewClientCredentialsConfig(
				aParams[constClientId],
				aParams[constSecretValue],
				aParams[constTenantId],
			)
			authorizer, err = credsConfig.Authorizer()
			if err != nil {
				return "", nil, fmt.Errorf("error authorizing to Azure: %w", err)
			}

		default:
			return "", nil, errors.New("no or incomplete authentication information available")
		}

		if authorizer == nil {
			return "", nil, fmt.Errorf("authorizer after authorizing to Azure is nil")
		}
	}

	return aParams[constSubscriptionId], authorizer, nil
}

func getWrappedHamiltonConfig(hc *hostcatalogs.HostCatalog, persisted *pb.HostCatalogPersisted) (*WrappedHamiltonConfig, error) {
	secrets := hc.GetSecrets()
	if secrets == nil && persisted != nil {
		secrets = persisted.GetSecrets()
	}
	aParams, err := authParams(hc, secrets)
	if err != nil {
		return nil, fmt.Errorf("error fetching authentication params when fetching: %w", err)
	}
	authConfig := &WrappedHamiltonConfig{}
	authConfig.Environment = environments.Global

	switch {
	case aParams[constClientId] != "" &&
		aParams[constSecretValue] != "" &&
		aParams[constTenantId] != "":
		authConfig.TenantID = aParams[constTenantId]
		authConfig.ClientID = aParams[constClientId]
		authConfig.ClientSecret = aParams[constSecretValue]
		if aParams[constSecretId] != "" {
			authConfig.SecretId = aParams[constSecretId]
		}
		authConfig.EnableClientSecretAuth = true

	default:
		return nil, errors.New("no or incomplete authentication information available")
	}

	return authConfig, nil
}

func getObjectId(ctx context.Context, hConfig *WrappedHamiltonConfig, opt ...Option) (string, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return "", fmt.Errorf("error parsing ops: %w", err)
	}

	objId := opts.withObjectId
	if objId == "" {
		clientId := opts.withClientId
		if clientId == "" && hConfig != nil {
			clientId = hConfig.ClientID
		}
		if clientId == "" {
			return "", fmt.Errorf("neither client id nor object id passed in, cannot continue")
		}
		// First, find the appId
		aClient, err := getApplicationsClient(ctx, hConfig)
		if err != nil {
			return "", fmt.Errorf("error getting application client: %w", err)
		}
		if aClient == nil {
			return "", errors.New("applications client is nil when getting object id")
		}
		apps, _, err := aClient.List(ctx, odata.Query{
			Filter: fmt.Sprintf("appId eq '%s'", clientId),
		})
		if err != nil {
			return "", fmt.Errorf("error listing applications to find objId: %w", err)
		}
		if apps == nil {
			return "", errors.New("nil apps returned when listing to find objId")
		}
		if len(*apps) != 1 {
			return "", fmt.Errorf("unexpected number of apps found, expected 1, found %d", len(*apps))
		}
		objId = *(*apps)[0].DirectoryObject.ID
	}
	return objId, nil
}

// rotateCredentials creates a new password, then uses a client with that new
// password to revoke the old.
//
// NOTE: the underlying auth config will be modified to use the new credentials!
func rotateCredential(ctx context.Context, hConfig *WrappedHamiltonConfig, opt ...Option) (*msgraph.PasswordCredential, error) {
	if hConfig == nil {
		return nil, errors.New("empty auth config id")
	}
	if hConfig.SecretId == "" {
		return nil, errors.New("missing original secret id")
	}

	// Get the object ID here so we don't have to look it up twice
	objId, err := getObjectId(ctx, hConfig)
	if err != nil {
		return nil, fmt.Errorf("error fetching object id: %w", err)
	}

	newCred, err := addCredential(ctx, hConfig, WithObjectId(objId))
	if err != nil {
		return nil, fmt.Errorf("error adding password: %w", err)
	}
	if newCred == nil {
		return nil, errors.New("new credential is nil after adding")
	}
	if newCred.SecretText == nil {
		return nil, errors.New("new credential secret text is nil after adding")
	}

	if err := removeCredential(ctx, hConfig, WithObjectId(objId)); err != nil {
		return nil, fmt.Errorf("error removing previous credential: %w", err)
	}
	return newCred, nil
}

func addCredential(ctx context.Context, hConfig *WrappedHamiltonConfig, opt ...Option) (*msgraph.PasswordCredential, error) {
	objId, err := getObjectId(ctx, hConfig, opt...)
	if err != nil {
		return nil, fmt.Errorf("error fetching object id: %w", err)
	}

	aClient, err := getApplicationsClient(ctx, hConfig)
	if err != nil {
		return nil, fmt.Errorf("error getting application client: %w", err)
	}
	if aClient == nil {
		return nil, errors.New("applications client is nil when adding credential")
	}

	// Create the new password
	displayName := fmt.Sprintf("boundary-rotated-%s", time.Now().Format(time.RFC3339))
	newPass, _, err := aClient.AddPassword(ctx, objId, msgraph.PasswordCredential{
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

func removeCredential(ctx context.Context, hConfig *WrappedHamiltonConfig, opt ...Option) error {
	objId, err := getObjectId(ctx, hConfig, opt...)
	if err != nil {
		return fmt.Errorf("error fetching object id: %w", err)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return fmt.Errorf("error parsing ops: %w", err)
	}

	secretId := hConfig.SecretId
	if opts.withSecretId != "" {
		secretId = opts.withSecretId
	}

	aClient, err := getApplicationsClient(ctx, hConfig)
	if err != nil {
		return fmt.Errorf("error getting application client: %w", err)
	}
	if aClient == nil {
		return errors.New("applications client is nil when removing credential")
	}

	_, err = aClient.RemovePassword(ctx, objId, secretId)
	if err != nil {
		return fmt.Errorf("error removing old password: %w", err)
	}

	return nil
}
