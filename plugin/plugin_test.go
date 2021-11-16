package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/kr/pretty"
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateCatalog(&hostcatalogs.HostCatalog{
				Attributes: tc.catalogAttrs,
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
		Attributes: attrs,
		Secrets:    secrets,
	}})
	require.NoError(t, err)
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithExtra := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
		"extraField":     "extra_value",
	})
	res, err = p.OnCreateCatalog(ctx, &pb.OnCreateCatalogRequest{Catalog: &hostcatalogs.HostCatalog{
		Attributes: attrs,
		Secrets:    secretsWithExtra,
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
		Attributes: attrs,
		Secrets:    secretsWithRotationTime,
	}})
	assert.Error(t, err)
}

func TestUpdateCatalog(t *testing.T) {
	ctx := context.Background()
	p := &AzurePlugin{}

	oldCatalog := &hostcatalogs.HostCatalog{
		Attributes: wrapMap(t, map[string]interface{}{
			constDisableCredentialRotation: true,
			constClientId:                  "foo",
			constTenantId:                  "foo",
			constSubscriptionId:            "foo",
		}),
	}

	attrs := wrapMap(t, map[string]interface{}{
		constDisableCredentialRotation: true,
		constClientId:                  "client_id",
		constTenantId:                  "tenant_id",
		constSubscriptionId:            "sub_id",
	})

	res, err := p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: attrs,
		}})
	require.NoError(t, err)
	assert.Nil(t, res.GetPersisted())

	secrets := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
	})

	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: attrs,
			Secrets:    secrets,
		}})
	require.NoError(t, err)
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithExtra := wrapMap(t, map[string]interface{}{
		constSecretValue: "secret_value",
		constSecretId:    "secret_id",
		"extraField":     "extra_value",
	})
	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: attrs,
			Secrets:    secretsWithExtra,
		}})
	require.NoError(t, err)
	// still only persist the fields we care about.
	assert.Equal(t, res.GetPersisted().GetSecrets().AsMap(), secrets.AsMap())

	secretsWithRotationTime := wrapMap(t, map[string]interface{}{
		constSecretValue:          "secret_value",
		constSecretId:             "secret_id",
		constCredsLastRotatedTime: "something",
	})
	res, err = p.OnUpdateCatalog(ctx, &pb.OnUpdateCatalogRequest{CurrentCatalog: oldCatalog,
		NewCatalog: &hostcatalogs.HostCatalog{
			Attributes: attrs,
			Secrets:    secretsWithRotationTime,
		}})
	assert.Error(t, err)
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
