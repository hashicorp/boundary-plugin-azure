package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// AzurePlugin implements the HostPluginServiceServer interface
type AzurePlugin struct {
	pb.UnimplementedHostPluginServiceServer
}

// Ensure that we are implementing HostPluginServiceServer
var (
	_ pb.HostPluginServiceServer = (*AzurePlugin)(nil)
)

type SetAttributes struct {
	Filter string `mapstructure:"filter"`
}

func rotateCredFromCallback(ctx context.Context, catalog *hostcatalogs.HostCatalog) (*pb.HostCatalogPersisted, error) {
	authzInfo, err := getAuthorizationInfo(catalog)
	if err != nil {
		return nil, fmt.Errorf("error getting hauth config when creating catalog: %w", err)
	}
	newPass, err := rotateCredential(ctx, authzInfo)
	if err != nil {
		return nil, fmt.Errorf("error rotating credentials when creating catalog: %w", err)
	}
	if newPass == nil {
		return nil, errors.New("new credential back from rotate is nil")
	}
	newSecrets, err := structpb.NewStruct(map[string]interface{}{
		constSecretId:             *newPass.KeyId,
		constSecretValue:          *newPass.SecretText,
		constCredsLastRotatedTime: time.Now().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, fmt.Errorf("error formatting new credential data as struct")
	}
	return &pb.HostCatalogPersisted{
		Secrets: newSecrets,
	}, err
}

func (p *AzurePlugin) OnCreateCatalog(_ context.Context, req *pb.OnCreateCatalogRequest) (*pb.OnCreateCatalogResponse, error) {
	if err := validateCatalog(req.GetCatalog()); err != nil {
		return nil, err
	}
	if err := validateSecrets(req.GetCatalog().GetSecrets()); err != nil {
		return nil, err
	}

	secrets := req.GetCatalog().GetSecrets().AsMap()
	persistedSecrets := map[string]interface{}{
		constSecretValue: secrets[constSecretValue],
	}
	if _, ok := secrets[constSecretId]; ok {
		persistedSecrets[constSecretId] = secrets[constSecretId]
	}
	persist, err := structpb.NewStruct(persistedSecrets)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed marshaling persisted secrets: %q", err.Error())
	}

	return &pb.OnCreateCatalogResponse{
		Persisted: &pb.HostCatalogPersisted{
			Secrets: persist,
		},
	}, nil
}

func (p *AzurePlugin) OnUpdateCatalog(_ context.Context, req *pb.OnUpdateCatalogRequest) (*pb.OnUpdateCatalogResponse, error) {
	if err := validateCatalog(req.GetNewCatalog()); err != nil {
		return nil, err
	}
	currentCatalog := req.GetCurrentCatalog()
	if currentCatalog == nil {
		// Should never happen
		return nil, status.Error(codes.FailedPrecondition, "current catalog is nil")
	}
	secrets := req.GetNewCatalog().GetSecrets()
	if secrets == nil {
		// If new secrets weren't passed in, don't rotate what we have on
		// update.
		return &pb.OnUpdateCatalogResponse{}, nil
	}
	if err := validateSecrets(secrets); err != nil {
		return nil, err
	}

	secretsMap := secrets.AsMap()
	persistedSecrets := map[string]interface{}{
		constSecretValue: secretsMap[constSecretValue],
	}
	if _, ok := secretsMap[constSecretId]; ok {
		persistedSecrets[constSecretId] = secretsMap[constSecretId]
	}
	persist, err := structpb.NewStruct(persistedSecrets)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed marshaling persisted secrets: %q", err.Error())
	}

	return &pb.OnUpdateCatalogResponse{
		Persisted: &pb.HostCatalogPersisted{
			Secrets: persist,
		},
	}, nil
}

func (p *AzurePlugin) OnCreateSet(_ context.Context, req *pb.OnCreateSetRequest) (*pb.OnCreateSetResponse, error) {
	if err := validateSet(req.GetSet()); err != nil {
		return nil, err
	}
	return &pb.OnCreateSetResponse{}, nil
}

func (p *AzurePlugin) OnUpdateSet(_ context.Context, req *pb.OnUpdateSetRequest) (*pb.OnUpdateSetResponse, error) {
	if err := validateSet(req.GetNewSet()); err != nil {
		return nil, err
	}
	return &pb.OnUpdateSetResponse{}, nil
}

func (p *AzurePlugin) ListHosts(ctx context.Context, req *pb.ListHostsRequest) (*pb.ListHostsResponse, error) {
	if len(req.GetSets()) == 0 {
		// Nothing to fetch
		return &pb.ListHostsResponse{}, nil
	}
	catalog := req.GetCatalog()
	if catalog == nil {
		return nil, status.Error(codes.FailedPrecondition, "catalog is nil")
	}
	catalogAttrs := catalog.GetAttributes()
	if catalogAttrs == nil {
		return nil, status.Error(codes.FailedPrecondition, "catalog has no attributes")
	}

	// Create an authorizer
	catalog.Secrets = req.GetPersisted().GetSecrets()
	authzInfo, err := getAuthorizationInfo(catalog)
	if err != nil {
		return nil, fmt.Errorf("error fetching authorizationInfo: %w", err)
	}
	if authzInfo == nil {
		return nil, status.Error(codes.FailedPrecondition, "authorization info is nil")
	}
	authorizer, err := authzInfo.autorestAuthorizer()
	if err != nil {
		return nil, fmt.Errorf("error fetching autorest authorizer: %w", err)
	}
	if authorizer == nil {
		return nil, errors.New("fetched authorizer is nil")
	}

	commonOpts := make([]Option, 0, 3)
	commonOpts = append(commonOpts,
		WithSubscriptionId(authzInfo.AuthParams.SubscriptionId),
		WithAuthorizer(authorizer),
	)

	// Getting authorizer will fail if the attr fields are not populated, so
	// it's safe to access directly at this point.
	//
	// TODO: plumb base URL everywhere, not just here
	catalogAttrFields := catalogAttrs.GetFields()
	if catalogAttrFields[constBaseUrl] != nil {
		if baseUrl := catalogAttrFields[constBaseUrl].GetStringValue(); baseUrl != "" {
			commonOpts = append(commonOpts, WithBaseUrl(baseUrl))
		}
	}

	// Create clients
	resClient, err := getResourcesClient(commonOpts...)
	if err != nil {
		return nil, fmt.Errorf("error fetching resources client: %w", err)
	}
	if resClient == nil {
		return nil, errors.New("resource client is nil")
	}
	vmClient, err := getVirtualMachinesClient(commonOpts...)
	if err != nil {
		return nil, fmt.Errorf("error fetching virtual machines client: %w", err)
	}
	if vmClient == nil {
		return nil, errors.New("virtual machines client is nil")
	}
	ifClient, err := getNetworkInterfacesClient(commonOpts...)
	if err != nil {
		return nil, fmt.Errorf("error fetching network interfaces client: %w", err)
	}
	if ifClient == nil {
		return nil, errors.New("network interfaces client is nil")
	}
	pipClient, err := getPublicIpAddressesClient(commonOpts...)
	if err != nil {
		return nil, fmt.Errorf("error fetching public ip address client: %w", err)
	}
	if pipClient == nil {
		return nil, errors.New("public ip address client is nil")
	}

	// This next section finds resource IDs that match to the filter in each
	// host set, and stores a mapping of, for each resource ID, which host sets
	// it belongs to
	resourceToSetMap := make(map[string][]string, len(req.GetSets())*10)
	var resourceInfos []resources.GenericResourceExpanded
	for _, set := range req.GetSets() {
		if set == nil {
			return nil, errors.New("set is nil")
		}
		setAttrs := set.GetAttributes()
		if setAttrs == nil {
			return nil, fmt.Errorf("set %s has no attributes", set.GetId())
		}
		setAttrFields := setAttrs.GetFields()
		if len(setAttrFields) == 0 {
			return nil, fmt.Errorf("set %s attributes has no filter", set.GetId())
		}

		filter := constDefaultFilter
		if setAttrFields[constFilter] != nil {
			if filter = setAttrFields[constFilter].GetStringValue(); filter == "" {
				return nil, fmt.Errorf("set %s filter is empty", set.GetId())
			}
		}

		// List values matching the filter; ask for provisioning state information
		// to ensure we are seeing only fully provisioned machines
		{
			iter, err := resClient.ListComplete(ctx, filter, "", nil)
			if err != nil {
				return nil, fmt.Errorf("error listing resources: %w", err)
			}
			for iter.NotDone() {
				val := iter.Value()
				if err := iter.NextWithContext(ctx); err != nil {
					return nil, fmt.Errorf("error iterating resources: %w", err)
				}
				if val.ID == nil { // something went wrong, likely iterator has advanced beyond the end
					continue
				}
				if val.Type == nil || *val.Type != "Microsoft.Compute/virtualMachines" {
					// no point continuing if we can't validate that it's a VM
					continue
				}
				resourceInfos = append(resourceInfos, val)
				resourceToSetMap[*val.ID] = append(resourceToSetMap[*val.ID], set.GetId())
			}
		}
	}

	// At this point we have a list of distinct resources and a mapping between
	// them and the set(s) they belong to. Iterate through them and fetch
	// information.
	//
	// Listing returns IDs which are basically URLs that have key-value
	// pairs but not the individual components. Get requires the individual
	// components, and won't accept the ID...
	//
	// Anyways, now we find VM details for those resources
	vmToIfaceMap := make(map[string][]network.Interface)
	{
		for _, res := range resourceInfos {
			resourceGroup, name, err := splitId(*res.ID, constMsComputeService, constVirtualMachinesResource)
			if err != nil {
				return nil, fmt.Errorf("error splitting vm id %q: %w", *res.ID, err)
			}
			vm, err := vmClient.Get(ctx, resourceGroup, name, "")
			if err != nil {
				return nil, fmt.Errorf("error fetching vm with id %q: %w", *res.ID, err)
			}

			iv, err := vmClient.InstanceView(ctx, resourceGroup, name)
			if err != nil {
				return nil, fmt.Errorf("error fetching instance view for vm with id %q: %w", *res.ID, err)
			}
			if iv.Statuses == nil {
				return nil, fmt.Errorf("instance view statuses returned for vm with id %q is null", *res.ID)
			}
			var running bool
			for _, s := range *iv.Statuses {
				if s.Code == nil {
					continue
				}
				state := strings.ToLower(*s.Code)
				prefix := "powerstate/"
				if !strings.HasPrefix(state, prefix) {
					continue
				}
				state = strings.TrimPrefix(state, prefix)
				if state == "running" {
					running = true
					break
				}
			}
			if !running {
				continue
			}

			props := vm.VirtualMachineProperties
			if props == nil {
				return nil, fmt.Errorf("error fetching properties for vm with id %q: %w", *res.ID, err)
			}
			if props.NetworkProfile == nil {
				return nil, fmt.Errorf("error fetching network profile for vm with id %q", *res.ID)
			}

			// Within the VM, catalog the various interfaces
			var ifaces []network.Interface
			for _, ifaceRef := range *props.NetworkProfile.NetworkInterfaces {
				if ifaceRef.ID == nil {
					return nil, fmt.Errorf("nil ID for network interface for vm with id %q", *res.ID)
				}
				ifResGroup, ifName, err := splitId(*ifaceRef.ID, constMsNetworkService, constNetworkInterfacesResource)
				if err != nil {
					return nil, fmt.Errorf("error splitting network interface id %q: %w", *ifaceRef.ID, err)
				}
				iface, err := ifClient.Get(ctx, ifResGroup, ifName, "")
				if err != nil {
					return nil, fmt.Errorf("error fetching network interface with id %q: %w", *ifaceRef.ID, err)
				}
				if iface.InterfacePropertiesFormat == nil || iface.InterfacePropertiesFormat.IPConfigurations == nil {
					continue
				}
				ifaces = append(ifaces, iface)
			}
			vmToIfaceMap[*res.ID] = ifaces
		}
	}

	// Now, fetch IP details for each of the interfaces for each VM
	type networkInfo struct {
		IpAddresses []string
	}
	vmToNetworkMap := make(map[string]networkInfo)
	{
		for vmId, ifaces := range vmToIfaceMap {
			var netInfo networkInfo
			for _, iface := range ifaces {
				for _, ipconf := range *iface.InterfacePropertiesFormat.IPConfigurations {
					if ipconf.PrivateIPAddress != nil {
						netInfo.IpAddresses = append(netInfo.IpAddresses, *ipconf.PrivateIPAddress)
					}
					if ipconf.PublicIPAddress != nil {
						if ipconf.PublicIPAddress.ID == nil {
							return nil, fmt.Errorf("ip configuration %q has public IP address info but nil id", *ipconf.ID)
						}
						ipResGroup, ipName, err := splitId(*ipconf.PublicIPAddress.ID, constMsNetworkService, constPublicIpAddressesResource)
						if err != nil {
							return nil, fmt.Errorf("error splitting public ip address id %q: %w", *ipconf.PublicIPAddress.ID, err)
						}
						pipInfo, err := pipClient.Get(ctx, ipResGroup, ipName, "")
						if err != nil {
							if err != nil {
								return nil, fmt.Errorf("error fetching public IP information with resource group %q and name %q: %w", ipResGroup, ipName, err)
							}
						}
						if pipInfo.PublicIPAddressPropertiesFormat == nil {
							return nil, fmt.Errorf("nil public ip address properties format for public ip %q", *ipconf.PublicIPAddress.ID)
						}
						if pipInfo.PublicIPAddressPropertiesFormat.IPAddress != nil {
							netInfo.IpAddresses = append(netInfo.IpAddresses, *pipInfo.PublicIPAddressPropertiesFormat.IPAddress)
						}
					}
				}
			}
			vmToNetworkMap[vmId] = netInfo
		}
	}

	ret := &pb.ListHostsResponse{}
	for k, v := range vmToNetworkMap {
		splitId := strings.Split(strings.TrimLeft(k, "/"), "/")
		host := &pb.ListHostsResponseHost{
			ExternalId:  k,
			IpAddresses: v.IpAddresses,
			SetIds:      resourceToSetMap[k],
			Name:        splitId[len(splitId)-1],
		}
		ret.Hosts = append(ret.Hosts, host)
	}
	return ret, nil
}

func splitId(in, expectedService, expectedResource string) (string, string, error) {
	// Note: this could be stolen from the helpers directory in the TF AzureRM
	// provider but I'm not at the moment because it does a bunch of trickery
	// for some Azure APIs and we have a much more limited scope. I may come to
	// regret this.
	splitId := strings.Split(strings.TrimLeft(in, "/"), "/")
	// Run through some sanity checks
	if len(splitId) != 8 ||
		splitId[0] != constSubscriptions ||
		splitId[2] != constResourceGroups ||
		splitId[4] != constProviders ||
		splitId[5] != expectedService ||
		splitId[6] != expectedResource {
		return "", "", fmt.Errorf("unexpected format of resource ID: %v", splitId)
	}
	return splitId[3], splitId[7], nil
}

// Returns an invalid argument error with the problematic fields included
// in the error message.
func invalidArgumentError(msg string, f map[string]string) error {
	var fieldMsgs []string
	for field, val := range f {
		fieldMsgs = append(fieldMsgs, fmt.Sprintf("%q: %q", field, val))
	}
	if len(fieldMsgs) > 0 {
		msg = fmt.Sprintf("%s: [%s]", msg, strings.Join(fieldMsgs, ", "))
	}
	return status.Error(codes.InvalidArgument, msg)
}

func validateSecrets(s *structpb.Struct) error {
	if s == nil {
		return status.Error(codes.InvalidArgument, "Secrets not provided but are required")
	}
	var secrets SecretData
	if err := mapstructure.Decode(s.AsMap(), &secrets); err != nil {
		return status.Errorf(codes.InvalidArgument, "error decoding catalog secrets: %s", err)
	}
	badFields := make(map[string]string)
	if len(secrets.SecretValue) == 0 {
		badFields["secrets.secret_value"] = "This field is required."
	}
	if len(secrets.CredsLastRotatedTime) != 0 {
		badFields["secrets.creds_last_rotated_time"] = "This field is reserved and cannot be set."
	}
	if len(badFields) > 0 {
		return invalidArgumentError("Error in the secrets provided", badFields)
	}
	return nil
}

var allowedCatalogFields = map[string]struct{}{
	constDisableCredentialRotation: {},
	constSubscriptionId:            {},
	constTenantId:                  {},
	constClientId:                  {},
}

func validateCatalog(c *hostcatalogs.HostCatalog) error {
	if c == nil {
		return status.Error(codes.InvalidArgument, "catalog is nil")
	}
	var attrs CatalogAttributes
	attrMap := c.GetAttributes().AsMap()
	if err := mapstructure.Decode(attrMap, &attrs); err != nil {
		return status.Errorf(codes.InvalidArgument, "error decoding catalog attributes: %s", err)
	}
	badFields := make(map[string]string)
	if !attrs.DisableCredentialRotation {
		badFields["attributes.disable_credential_rotation"] = "This field must be set to true."
	}
	if len(attrs.SubscriptionId) == 0 {
		badFields["attributes.subscription_id"] = "This is a required field."
	}
	if len(attrs.ClientId) == 0 {
		badFields["attributes.client_id"] = "This is a required field."
	}
	if len(attrs.TenantId) == 0 {
		badFields["attributes.tenant_id"] = "This is a required field."
	}

	for f := range attrMap {
		if _, ok := allowedCatalogFields[f]; !ok {
			badFields[fmt.Sprintf("attributes.%s", f)] = "Unrecognized field."
		}
	}

	if len(badFields) > 0 {
		return invalidArgumentError("Invalid arguments in the new catalog", badFields)
	}
	return nil
}

var allowedSetFields = map[string]struct{}{
	constFilter: {},
}

func validateSet(s *hostsets.HostSet) error {
	if s == nil {
		return status.Error(codes.InvalidArgument, "set is nil")
	}
	var attrs SetAttributes
	attrMap := s.GetAttributes().AsMap()
	if err := mapstructure.Decode(attrMap, &attrs); err != nil {
		return status.Errorf(codes.InvalidArgument, "error decoding set attributes: %s", err)
	}
	badFields := make(map[string]string)
	if _, ok := attrMap[constFilter]; ok && len(attrs.Filter) == 0 {
		badFields["attributes.filter"] = "This field must be not empty."
	}

	for f := range attrMap {
		if _, ok := allowedSetFields[f]; !ok {
			badFields[fmt.Sprintf("attributes.%s", f)] = "Unrecognized field."
		}
	}

	if len(badFields) > 0 {
		return invalidArgumentError("Invalid arguments in the new set", badFields)
	}
	return nil
}
