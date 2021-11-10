package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/kr/pretty"
	"github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/environments"
	"github.com/manicminer/hamilton/msgraph"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func wrapMap(t *testing.T, in map[string]interface{}) *structpb.Struct {
	t.Helper()
	out, err := structpb.NewStruct(in)
	require.NoError(t, err)
	return out
}

// TestListHosts tests the ListHosts function
func TestListHosts(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	p := &AzurePlugin{}
	hostCatalog, hostSets := testGetHostStructs(t)
	secrets := hostCatalog.Secrets
	lhResp, err := p.ListHosts(ctx, &pb.ListHostsRequest{
		Catalog: hostCatalog,
		Sets:    hostSets,
		Persisted: &pb.HostCatalogPersisted{
			Secrets: secrets,
		},
	})
	require.NoError(err)
	require.NotNil(lhResp)

	pretty.Println(lhResp.GetHosts())
}

func TestOnCreateOnDeleteCatalog(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()
	p := &AzurePlugin{}
	hostCatalog, _ := testGetHostStructs(t)
	initialAuthConfig, initialCred, cleanup := testCreateInitialSecret(t, hostCatalog)
	defer cleanup()

	// At this point, remove secrets corresponding to those read in by
	// testGetHostCatalog as they're our permanent ones
	hostCatalog.Secrets = nil

	// Give some time -- a lot -- for token to become active
	time.Sleep(10 * time.Minute)

	// Now, we'll use this credential to simulate creating a host catalog, which
	// will rotate it. First, ensure we don't error out if creds aren't provided
	// _yet_ (instead, on update)
	ccResp, err := p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{
		Catalog: hostCatalog,
	})
	require.NoError(err)
	require.Nil(ccResp)

	// Now run the same thing with rotation disabled, make sure we get the same
	// values back
	secrets := wrapMap(t, map[string]interface{}{
		constSecretValue: *initialCred.SecretText,
		constSecretId:    *initialCred.KeyId,
	})
	hostCatalog.Secrets = secrets
	hostCatalog.GetAttributes().GetFields()[constDisableCredentialRotation] = structpb.NewBoolValue(true)
	ccResp, err = p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{
		Catalog: hostCatalog,
	})
	require.NoError(err)
	require.NotNil(ccResp)
	require.NotNil(ccResp.GetPersisted())
	require.NotNil(ccResp.GetPersisted().GetSecrets())
	newPdFields := ccResp.GetPersisted().GetSecrets().GetFields()
	require.Equal(*initialCred.KeyId, newPdFields[constSecretId].GetStringValue())
	require.Equal(*initialCred.SecretText, newPdFields[constSecretValue].GetStringValue())

	// Now we'll try again, actually rotating the creds
	delete(hostCatalog.GetAttributes().GetFields(), constDisableCredentialRotation)
	ccResp, err = p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{
		Catalog: hostCatalog,
	})

	require.NoError(err)
	require.NotNil(ccResp)
	require.NotNil(ccResp.GetPersisted())
	require.NotNil(ccResp.GetPersisted().GetSecrets())
	newPdFields = ccResp.GetPersisted().GetSecrets().GetFields()
	// Use old creds for this removal to give it a high likelihood of success
	deferAuthConfig := *initialAuthConfig
	defer func() {
		_ = removeCredential(
			ctx,
			&deferAuthConfig,
		)
	}()

	// Best-effort ensure that this new cred is deleted if OnDelete doesn't work right
	require.NotEqual(*initialCred.KeyId, newPdFields[constSecretId].GetStringValue())
	require.NotEqual(*initialCred.SecretText, newPdFields[constSecretValue].GetStringValue())

	// Remove these now prior to OnDelete
	hostCatalog.Secrets = nil

	// Make sure old creds don't work
	waitForCredsAuthConfig := *initialAuthConfig
	// FIXME: Actually don't, because they can still be used for up to a day!??! later?!?!
	// waitForCreds(t, &waitForCredsAuthConfig, false)

	// Make sure the new creds work, then sleep
	waitForCredsAuthConfig.AuthParams.SecretId = newPdFields[constSecretId].GetStringValue()
	waitForCredsAuthConfig.AuthParams.SecretValue = newPdFields[constSecretValue].GetStringValue()
	waitForCredsAuthConfig.HamiltonConfig.ClientSecret = newPdFields[constSecretValue].GetStringValue()
	waitForCreds(t, &waitForCredsAuthConfig, true)
	time.Sleep(10 * time.Minute)

	// Now, let's test OnDelete. First, check the case where we never configured
	// a credential in the first place.
	cdResp, err := p.OnDeleteCatalog(ctx, &pb.OnDeleteCatalogRequest{
		Catalog:   hostCatalog,
		Persisted: &pb.HostCatalogPersisted{},
	})
	require.NoError(err)
	require.Nil(cdResp)

	// Now, use the credentials we got above to revoke this credential we got from OnCreate
	secrets = wrapMap(t, map[string]interface{}{
		constSecretValue: waitForCredsAuthConfig.HamiltonConfig.ClientSecret,
		constSecretId:    waitForCredsAuthConfig.AuthParams.SecretId,
	})
	cdResp, err = p.OnDeleteCatalog(ctx, &pb.OnDeleteCatalogRequest{
		Catalog: hostCatalog,
		Persisted: &pb.HostCatalogPersisted{
			Secrets: secrets,
		},
	})
	require.NoError(err)
	require.Nil(cdResp)
	// Make sure the creds no longer work
	// FIXME: Don't, for the same reason
	// waitForCreds(t, &waitForCredsAuthConfig, false)
}

func waitForCreds(t *testing.T, authzInfo *AuthorizationInfo, shouldWork bool) auth.Authorizer {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	auth, err := auth.NewClientSecretAuthorizer(
		ctx,
		environments.Global,
		auth.MsGraph,
		auth.TokenVersion2,
		authzInfo.AuthParams.TenantId,
		authzInfo.AuthParams.ClientId,
		authzInfo.AuthParams.SecretValue)
	require.NoError(err)

	for {
		_, err := auth.Token()
		switch {
		case shouldWork && err == nil:
			return auth
		case !shouldWork && err != nil:
			return nil
		default:
			time.Sleep(30 * time.Second)
		}
	}
}

func testGetHostStructs(t *testing.T) (*hostcatalogs.HostCatalog, []*hostsets.HostSet) {
	require := require.New(t)
	wd, err := os.Getwd()
	require.NoError(err)
	require.NotEmpty(wd)
	clientId, err := parseutil.ParsePath("file://" + filepath.Join(wd, "private", "clientid"))
	require.NoError(err)
	secretValue, err := parseutil.ParsePath("file://" + filepath.Join(wd, "private", "secretvalue"))
	require.NoError(err)
	tenantId, err := parseutil.ParsePath("file://" + filepath.Join(wd, "private", "tenantid"))
	require.NoError(err)
	subscriptionId, err := parseutil.ParsePath("file://" + filepath.Join(wd, "private", "subscriptionid"))
	require.NoError(err)

	// These values will not change througout the test
	hc := &hostcatalogs.HostCatalog{
		Attributes: wrapMap(t, map[string]interface{}{
			constSubscriptionId: subscriptionId,
			constTenantId:       tenantId,
			constClientId:       clientId,
		}),
		Secrets: wrapMap(t, map[string]interface{}{
			constSecretValue: secretValue,
		}),
	}

	hses := []*hostsets.HostSet{
		{
			Id: "set1",
			Attributes: wrapMap(t, map[string]interface{}{
				constFilter: constDefaultFilter,
			}),
		},
		{
			Id: "set2",
			Attributes: wrapMap(t, map[string]interface{}{
				constFilter: constDefaultFilter,
			}),
		},
	}

	return hc, hses
}

// This function creates a new secret so we don't revoke the original one
// leading into a test. This will serve as our "initial secret" for a test. We
// also return a few cached items. It is expected that the host catalog contains
// Secrets.
func testCreateInitialSecret(t *testing.T, hostCatalog *hostcatalogs.HostCatalog) (*AuthorizationInfo, *msgraph.PasswordCredential, func()) {
	require := require.New(t)
	ctx := context.Background()

	var initialCred *msgraph.PasswordCredential

	// Set up the data, get the config
	authzInfo, err := getAuthorizationInfo(hostCatalog)
	require.NoError(err)

	// Get the credential
	initialCred, err = addCredential(ctx, authzInfo)
	require.NoError(err)
	require.NotNil(initialCred)
	require.NotNil(initialCred.KeyId)
	require.NotNil(initialCred.SecretText)

	origAuthConfig := *authzInfo
	origAuthConfig.AuthParams.SecretId = *initialCred.KeyId
	cleanup := func() {
		if err := removeCredential(
			ctx,
			&origAuthConfig,
		); err != nil {
			// It may not exist because it's been rotated
			require.Contains(err.Error(), "No password credential found with keyId", err.Error())
		}
	}

	authzInfo.AuthParams.SecretId = *initialCred.KeyId
	authzInfo.AuthParams.SecretValue = *initialCred.SecretText
	authzInfo.HamiltonConfig.ClientSecret = *initialCred.SecretText
	waitForCreds(t, authzInfo, true)

	return authzInfo, initialCred, cleanup
}
