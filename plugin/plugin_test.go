// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	"github.com/stretchr/testify/assert"
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
	require.NotEmpty(lhResp.GetHosts())

	pretty.Println(lhResp.GetHosts())
}

func TestValidateCatalog(t *testing.T) {
	cases := []struct {
		name         string
		catalogAttrs *structpb.Struct
		wantError    bool
	}{
		{
			name: "success",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: true,
				constClientId:                  "client_id",
				constTenantId:                  "tenant_id",
				constSubscriptionId:            "sub_id",
			}),
		},
		{
			name: "bad type",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: "bad type",
				constClientId:                  "client_id",
				constTenantId:                  "tenant_id",
				constSubscriptionId:            "sub_id",
			}),
			wantError: true,
		},
		{
			name:         "nil",
			catalogAttrs: nil,
			wantError:    true,
		},
		{
			name: "rotation enabled",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: false,
				constClientId:                  "client_id",
				constTenantId:                  "tenant_id",
				constSubscriptionId:            "sub_id",
			}),
			wantError: true,
		},
		{
			name: "no client id",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: true,
				constTenantId:                  "tenant_id",
				constSubscriptionId:            "sub_id",
			}),
			wantError: true,
		},
		{
			name: "no tenant id",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: false,
				constClientId:                  "client_id",
				constSubscriptionId:            "sub_id",
			}),
			wantError: true,
		},
		{
			name: "no subscription id",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: false,
				constClientId:                  "client_id",
				constTenantId:                  "tenant_id",
			}),
			wantError: true,
		},
		{
			name: "unrecognized field",
			catalogAttrs: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: true,
				constClientId:                  "client_id",
				constTenantId:                  "tenant_id",
				constSubscriptionId:            "sub_id",
				"unrecognized":                 "unrecognized",
			}),
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateCatalog(&hostcatalogs.HostCatalog{
				Attrs: &hostcatalogs.HostCatalog_Attributes{
					Attributes: tc.catalogAttrs,
				},
			})
			if tc.wantError {
				assert.Error(t, got)
			} else {
				assert.NoError(t, got)
			}
		})
	}
}

func TestValidateSecrets(t *testing.T) {
	cases := []struct {
		name           string
		catalogSecrets *structpb.Struct
		wantError      bool
	}{
		{
			name: "success",
			catalogSecrets: wrapMap(t, map[string]interface{}{
				constSecretValue: "value",
				constSecretId:    "secret_id",
			}),
		},
		{
			name:           "nil secret value",
			catalogSecrets: nil,
			wantError:      true,
		},
		{
			name: "no secret value",
			catalogSecrets: wrapMap(t, map[string]interface{}{
				constSecretId: "secret_id",
			}),
			wantError: true,
		},
		{
			name: "secret with last rotated time",
			catalogSecrets: wrapMap(t, map[string]interface{}{
				constSecretValue:          "value",
				constCredsLastRotatedTime: "something",
			}),
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSecrets(tc.catalogSecrets)
			if tc.wantError {
				assert.Error(t, got)
			} else {
				assert.NoError(t, got)
			}
		})
	}
}

func TestValidateSet(t *testing.T) {
	cases := []struct {
		name      string
		setAttrs  *structpb.Struct
		wantError bool
	}{
		{
			name: "success",
			setAttrs: wrapMap(t, map[string]interface{}{
				constFilter: "filter value",
			}),
		},
		{
			name:     "nil",
			setAttrs: nil,
		},
		{
			name: "bad type",
			setAttrs: wrapMap(t, map[string]interface{}{
				constFilter: true,
			}),
			wantError: true,
		},
		{
			name: "empty",
			setAttrs: wrapMap(t, map[string]interface{}{
				constFilter: "",
			}),
			wantError: true,
		},
		{
			name: "unrecognized field",
			setAttrs: wrapMap(t, map[string]interface{}{
				constFilter:    "filter value",
				"unrecognized": "unrecognized",
			}),
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateSet(&hostsets.HostSet{
				Attrs: &hostsets.HostSet_Attributes{
					Attributes: tc.setAttrs,
				},
			})
			if tc.wantError {
				assert.Error(t, got)
			} else {
				assert.NoError(t, got)
			}
		})
	}
}

func TestCreateCatalog(t *testing.T) {
	ctx := context.Background()
	p := &AzurePlugin{}
	attrs := wrapMap(t, map[string]interface{}{
		constDisableCredentialRotation: true,
		constClientId:                  "client_id",
		constTenantId:                  "tenant_id",
		constSubscriptionId:            "sub_id",
	})
	secrets := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
	})

	res, err := p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{Catalog: &hostcatalogs.HostCatalog{
		Attrs: &hostcatalogs.HostCatalog_Attributes{
			Attributes: attrs,
		},
		Secrets: secrets,
	}})
	require.NoError(t, err)
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithExtra := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
		"extraField":     "extra_value",
	})
	res, err = p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{Catalog: &hostcatalogs.HostCatalog{
		Attrs: &hostcatalogs.HostCatalog_Attributes{
			Attributes: attrs,
		},
		Secrets: secretsWithExtra,
	}})
	require.NoError(t, err)
	// still only persist the fields we care about.
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithRotationTime := wrapMap(t, map[string]interface{}{
		constSecretValue:          "secret_value",
		constSecretId:             "secret_id",
		constCredsLastRotatedTime: "something",
	})
	res, err = p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{Catalog: &hostcatalogs.HostCatalog{
		Attrs: &hostcatalogs.HostCatalog_Attributes{
			Attributes: attrs,
		},
		Secrets: secretsWithRotationTime,
	}})
	assert.Error(t, err)
}

func TestUpdateCatalog(t *testing.T) {
	ctx := context.Background()
	p := &AzurePlugin{}

	oldCatalog := &hostcatalogs.HostCatalog{
		Attrs: &hostcatalogs.HostCatalog_Attributes{
			Attributes: wrapMap(t, map[string]interface{}{
				constDisableCredentialRotation: true,
				constClientId:                  "foo",
				constTenantId:                  "foo",
				constSubscriptionId:            "foo",
			}),
		},
	}

	attrs := wrapMap(t, map[string]interface{}{
		constDisableCredentialRotation: true,
		constClientId:                  "client_id",
		constTenantId:                  "tenant_id",
		constSubscriptionId:            "sub_id",
	})

	res, err := p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{
		CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: attrs,
			},
		},
	})
	require.NoError(t, err)
	assert.Nil(t, res.GetPersisted())

	secrets := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
	})

	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{
		CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: attrs,
			},
			Secrets: secrets,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithExtra := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
		"extraField":     "extra_value",
	})
	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{
		CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: attrs,
			},
			Secrets: secretsWithExtra,
		},
	})
	require.NoError(t, err)
	// still only persist the fields we care about.
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithRotationTime := wrapMap(t, map[string]interface{}{
		constSecretValue:          "secret_value",
		constSecretId:             "secret_id",
		constCredsLastRotatedTime: "something",
	})
	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{
		CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attrs: &hostcatalogs.HostCatalog_Attributes{
				Attributes: attrs,
			},
			Secrets: secretsWithRotationTime,
		},
	})
	assert.Error(t, err)
}

func waitForCreds(t *testing.T, authzInfo *AuthorizationInfo, shouldWork bool) auth.Authorizer {
	t.Helper()
	require := require.New(t)
	ctx := context.Background()
	auth, err := auth.NewClientSecretAuthorizer(
		ctx,
		environments.Global,
		environments.Global.MsGraph,
		auth.TokenVersion2,
		authzInfo.AuthParams.TenantId,
		nil,
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
		Attrs: &hostcatalogs.HostCatalog_Attributes{
			Attributes: wrapMap(t, map[string]interface{}{
				constSubscriptionId: subscriptionId,
				constTenantId:       tenantId,
				constClientId:       clientId,
			}),
		},
		Secrets: wrapMap(t, map[string]interface{}{
			constSecretValue: secretValue,
		}),
	}

	hses := []*hostsets.HostSet{
		{
			Id: "set1",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: wrapMap(t, map[string]interface{}{
					constFilter: "",
				}),
			},
		},
		{
			Id: "set2",
			Attrs: &hostsets.HostSet_Attributes{
				Attributes: wrapMap(t, map[string]interface{}{
					constFilter: "",
				}),
			},
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

func TestSplitId(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedService  string
		expectedResource string
		wantRG           string
		wantName         string
		wantErr          bool
	}{
		{
			name:             "valid resource id",
			input:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "rg1",
			wantName:         "vm1",
			wantErr:          false,
		},
		{
			name:             "valid with different case",
			input:            "/SUBSCRIPTIONS/sub1/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/vm1",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "rg1",
			wantName:         "vm1",
			wantErr:          false,
		},
		{
			name:             "invalid - trailing slash",
			input:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "",
			wantName:         "",
			wantErr:          true,
		},
		{
			name:             "invalid - wrong service",
			input:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/virtualMachines/vm1",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "",
			wantName:         "",
			wantErr:          true,
		},
		{
			name:             "invalid - wrong resource type",
			input:            "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/diskEncryptionSets/des1",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "",
			wantName:         "",
			wantErr:          true,
		},
		{
			name:             "invalid - missing segments",
			input:            "/subscriptions/sub1/resourceGroups/rg1",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "",
			wantName:         "",
			wantErr:          true,
		},
		{
			name:             "invalid - empty string",
			input:            "",
			expectedService:  "Microsoft.Compute",
			expectedResource: "virtualMachines",
			wantRG:           "",
			wantName:         "",
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRG, gotName, err := splitId(tt.input, tt.expectedService, tt.expectedResource)
			if (err != nil) != tt.wantErr {
				t.Errorf("splitId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotRG != tt.wantRG {
				t.Errorf("splitId() gotRG = %v, want %v", gotRG, tt.wantRG)
			}
			if gotName != tt.wantName {
				t.Errorf("splitId() gotName = %v, want %v", gotName, tt.wantName)
			}
		})
	}
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid compute resource",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
			want:    "virtualMachines",
			wantErr: false,
		},
		{
			name:    "valid compute resource different case",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/MICROSOFT.COMPUTE/virtualMachines/vm1",
			want:    "virtualMachines",
			wantErr: false,
		},
		{
			name:    "valid with trailing slash",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/",
			want:    "virtualMachines",
			wantErr: false,
		},
		{
			name:    "different compute resource type",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/diskEncryptionSets/des1",
			want:    "diskEncryptionSets",
			wantErr: false,
		},
		{
			name:    "non-compute resource",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
			want:    "",
			wantErr: false,
		},
		{
			name:    "malformed - missing provider",
			input:   "/subscriptions/sub1/resourceGroups/rg1/Microsoft.Compute/virtualMachines/vm1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "malformed - missing resource type",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "too short",
			input:   "/subscriptions/sub1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "malformed structure",
			input:   "/something/else/entirely",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractResourceType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractResourceType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractResourceType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateHostFromResource(t *testing.T) {
	// Setup common test data
	testNetwork := networkInfo{
		IpAddresses: []string{"192.168.1.1", "192.168.1.2"},
	}

	// Use full Azure resource paths as keys
	vmssPath := "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1"
	vmPath := "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-resource1"

	resourceToSetMap := map[string][]string{
		vmssPath: {"set1", "set2"},
		vmPath:   {"set3", "set4"},
	}

	tests := []struct {
		name       string
		resourceID string
		network    networkInfo
		setMap     map[string][]string
		want       *pb.ListHostsResponseHost
		wantErr    bool
		errMessage string
	}{
		{
			name:       "valid VMSS resource",
			resourceID: vmssPath + "/virtualMachines/vm1",
			network:    testNetwork,
			setMap:     resourceToSetMap,
			want: &pb.ListHostsResponseHost{
				ExternalId:   vmssPath + "/virtualMachines/vm1",
				ExternalName: "vmss1_vm1",
				IpAddresses:  []string{"192.168.1.1", "192.168.1.2"},
				SetIds:       []string{"set1", "set2"},
			},
			wantErr: false,
		},
		{
			name:       "valid VM resource",
			resourceID: vmPath,
			network:    testNetwork,
			setMap:     resourceToSetMap,
			want: &pb.ListHostsResponseHost{
				ExternalId:   vmPath,
				ExternalName: "vm-resource1",
				IpAddresses:  []string{"192.168.1.1", "192.168.1.2"},
				SetIds:       []string{"set3", "set4"},
			},
			wantErr: false,
		},
		{
			name:       "invalid resource ID",
			resourceID: "invalid-resource-id",
			network:    testNetwork,
			setMap:     resourceToSetMap,
			want:       nil,
			wantErr:    true,
			errMessage: "invalid resource ID",
		},
		{
			name:       "unsupported resource type",
			resourceID: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/unsupportedResource/resource1",
			network:    testNetwork,
			setMap:     resourceToSetMap,
			want:       nil,
			wantErr:    true,
			errMessage: "unsupported resource type",
		},
		{
			name:       "VMSS with valid resource type but invalid structure",
			resourceID: "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets", // Missing required segments after virtualMachineScaleSets
			network:    testNetwork,
			setMap:     resourceToSetMap,
			want:       nil,
			wantErr:    true,
			errMessage: "could not determine set for resource ID: not a valid VMSS resource ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createHostFromResource(tt.resourceID, tt.network, tt.setMap)

			// Check error cases
			if tt.wantErr {
				if err == nil {
					t.Errorf("createHostFromResource() expected error containing %q, got nil", tt.errMessage)
					return
				}
				if !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("createHostFromResource() error = %v, want error containing %q", err, tt.errMessage)
				}
				return
			}

			// Check non-error cases
			if err != nil {
				t.Errorf("createHostFromResource() unexpected error: %v", err)
				return
			}

			// Compare the results
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createHostFromResource() = %v, want %v", got, tt.want)
			}
		})
	}
}
