// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package plugin implements the Azure host plugin for Boundary,
// providing functionality to manage and list Azure hosts.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostcatalogs"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/hostsets"
	pb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

// AzurePlugin implements the HostPluginServiceServer interface
type AzurePlugin struct {
	pb.UnimplementedHostPluginServiceServer
}

// Ensure that we are implementing HostPluginServiceServer
var _ pb.HostPluginServiceServer = (*AzurePlugin)(nil)

type SetAttributes struct {
	Filter string `mapstructure:"filter"`
}

type azureClients struct {
	resClient    *resources.Client
	vmClient     *compute.VirtualMachinesClient
	vmssClient   *compute.VirtualMachineScaleSetsClient
	vmssvmClient *compute.VirtualMachineScaleSetVMsClient
	ifClient     *network.InterfacesClient
	pipClient    *network.PublicIPAddressesClient
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
		return nil, status.Error(codes.FailedPrecondition, "current catalog is nil")
	}
	secrets := req.GetNewCatalog().GetSecrets()
	if secrets == nil {
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
	startTime := time.Now()
	defer func() {
		fmt.Printf("ListHosts completed in %v\n", time.Since(startTime))
	}()

	if len(req.GetSets()) == 0 {
		return &pb.ListHostsResponse{}, nil
	}

	// Initialize Azure clients and authorization
	clientStart := time.Now()
	clients, err := p.initializeAzureResources(req.GetCatalog(), req.GetPersisted().GetSecrets())
	if err != nil {
		return nil, err
	}
	fmt.Printf("Azure clients initialized in %v\n", time.Since(clientStart))

	// Find matching resources and map them to sets
	findStart := time.Now()
	vmResources, vmssResources, resourceToSetMap, err := p.findMatchingResources(ctx, req.GetSets(), clients.resClient)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Resources discovered in %v (Found %d VMs, %d VMSS)\n",
		time.Since(findStart),
		len(vmResources),
		len(vmssResources))

	// Create mutex and errgroup for parallel processing
	mu := &sync.Mutex{}
	vmToNetworkMap := make(map[string]networkInfo)
	g, ctx := errgroup.WithContext(ctx)

	processingStart := time.Now()
	// Process standard VMs in parallel if they exist
	if len(vmResources) > 0 {
		g.Go(func() error {
			vmStart := time.Now()
			vmNetworkMap, err := p.processStandardVMs(ctx, vmResources, clients)
			if err != nil {
				return fmt.Errorf("processing VMs: %w", err)
			}

			mu.Lock()
			defer mu.Unlock()
			for k, v := range vmNetworkMap {
				vmToNetworkMap[k] = v
			}

			fmt.Printf("Processed %d VMs in %v\n", len(vmResources), time.Since(vmStart))
			return nil
		})
	}

	// Process VMSS in parallel if they exist
	if len(vmssResources) > 0 {
		g.Go(func() error {
			vmssStart := time.Now()
			vmssNetworkMap, err := p.processVMScaleSets(ctx, vmssResources, clients)
			if err != nil {
				return fmt.Errorf("processing VMSS: %w", err)
			}

			mu.Lock()
			defer mu.Unlock()
			for k, v := range vmssNetworkMap {
				vmToNetworkMap[k] = v
			}

			fmt.Printf("Processed %d VMSS in %v\n", len(vmssResources), time.Since(vmssStart))
			return nil
		})
	}

	// Wait for all goroutines to complete and check for errors
	if err := g.Wait(); err != nil {
		return nil, err
	}
	fmt.Printf("Total processing time: %v\n", time.Since(processingStart))

	responseStart := time.Now()
	response := buildHostsResponse(vmToNetworkMap, resourceToSetMap)
	fmt.Printf("Built response in %v (Total hosts: %d)\n",
		time.Since(responseStart),
		len(vmToNetworkMap))

	return response, nil
}

func rotateCredFromCallback(ctx context.Context, catalog *hostcatalogs.HostCatalog) (*pb.HostCatalogPersisted, error) {
	authzInfo, err := getAuthorizationInfo(catalog)
	if err != nil {
		return nil, fmt.Errorf("error getting auth config when creating catalog: %w", err)
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

func buildHostsResponse(
	vmToNetworkMap map[string]networkInfo,
	resourceToSetMap map[string][]string) *pb.ListHostsResponse {

	ret := &pb.ListHostsResponse{}

	for resourceID, networkInfo := range vmToNetworkMap {
		host, err := createHostFromResource(resourceID, networkInfo, resourceToSetMap)
		if err != nil {
			fmt.Printf("Error creating host from resource: %v\n", err)
			continue
		}
		ret.Hosts = append(ret.Hosts, host)
	}

	return ret
}

func createHostFromResource(resourceID string, networkInfo networkInfo,
	resourceToSetMap map[string][]string) (*pb.ListHostsResponseHost, error) {

	// Extract the resource type from the ID
	resourceType, err := extractResourceType(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID: %w", err)
	}

	switch resourceType {
	case constVirtualMachineScaleSetsResource:
		externalName, err := getExternalNameforVMSSInstance(resourceID)
		if err != nil {
			externalName = "" // Use empty name if there's an error
		}

		setId, err := getSetForVMSSInstance(resourceID)
		if err != nil {
			return nil, fmt.Errorf("could not determine set for resource ID: %w", err)
		}
		return &pb.ListHostsResponseHost{
			ExternalId:   resourceID,
			ExternalName: externalName,
			IpAddresses:  networkInfo.IpAddresses,
			SetIds:       resourceToSetMap[setId],
		}, nil

	case constVirtualMachinesResource:
		_, externalName, err := splitId(resourceID, constMsComputeService, constVirtualMachinesResource)
		if err != nil {
			externalName = "" // Use empty name if there's an error
		}

		return &pb.ListHostsResponseHost{
			ExternalId:   resourceID,
			ExternalName: externalName,
			IpAddresses:  networkInfo.IpAddresses,
			SetIds:       resourceToSetMap[resourceID],
		}, nil

	default:
		return nil, fmt.Errorf("unsupported resource type: %s", resourceType) // Return explicit error
	}
}

func (p *AzurePlugin) initializeAzureResources(
	catalog *hostcatalogs.HostCatalog,
	secrets *structpb.Struct) (*azureClients, error) {

	if catalog == nil {
		return nil, status.Error(codes.FailedPrecondition, "catalog is nil")
	}
	catalogAttrs := catalog.GetAttributes()
	if catalogAttrs == nil {
		return nil, status.Error(codes.FailedPrecondition, "catalog has no attributes")
	}

	// Create authorizer
	catalog.Secrets = secrets
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

	// Set up common client options
	commonOpts := []Option{
		WithSubscriptionId(authzInfo.AuthParams.SubscriptionId),
		WithAuthorizer(authorizer),
	}

	// Add base URL if specified
	catalogAttrFields := catalogAttrs.GetFields()
	if catalogAttrFields[constBaseUrl] != nil {
		if baseUrl := catalogAttrFields[constBaseUrl].GetStringValue(); baseUrl != "" {
			commonOpts = append(commonOpts, WithBaseUrl(baseUrl))
		}
	}

	// Initialize clients
	clients := &azureClients{}
	var initErr error

	// Initialize individual clients with error handling
	if clients.resClient, initErr = getResourcesClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching resources client: %w", initErr)
	}

	if clients.vmClient, initErr = getVirtualMachinesClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching virtual machines client: %w", initErr)
	}

	if clients.vmssClient, initErr = getVirtualMachineScaleSetsClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching virtual machine scale set client: %w", initErr)
	}

	if clients.vmssvmClient, initErr = getVirtualMachineScaleSetVMsClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching virtual machine scale set vms client: %w", initErr)
	}

	if clients.ifClient, initErr = getNetworkInterfacesClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching network interfaces client: %w", initErr)
	}

	if clients.pipClient, initErr = getPublicIpAddressesClient(commonOpts...); initErr != nil {
		return nil, fmt.Errorf("error fetching public ip address client: %w", initErr)
	}

	return clients, nil
}

func (p *AzurePlugin) findMatchingResources(ctx context.Context,
	sets []*hostsets.HostSet,
	resClient *resources.Client) (
	vmResources []resources.GenericResourceExpanded,
	vmssResources []resources.GenericResourceExpanded,
	resourceToSetMap map[string][]string,
	_ error) {

	resourceToSetMap = make(map[string][]string, len(sets)*10) // Pre-allocate map size

	for _, set := range sets {
		if err := validateHostSet(set); err != nil {
			return nil, nil, nil, err
		}

		filter := getSetFilter(set)
		setVMResources, setVMSSResources, setResourceToSetMap, err := listAndFilterResources(ctx, resClient, filter, set.GetId())
		if err != nil {
			return nil, nil, nil, err
		}
		vmResources = append(vmResources, setVMResources...)
		vmssResources = append(vmssResources, setVMSSResources...)
		for k, v := range setResourceToSetMap {
			resourceToSetMap[k] = append(resourceToSetMap[k], v...)
		}
	}

	return vmResources, vmssResources, resourceToSetMap, nil
}

func listAndFilterResources(ctx context.Context,
	resClient *resources.Client,
	filter, setID string) (
	vmResources []resources.GenericResourceExpanded,
	vmssResources []resources.GenericResourceExpanded,
	resourceToSetMap map[string][]string,
	_ error) {

	resourceToSetMap = make(map[string][]string)
	iter, err := resClient.ListComplete(ctx, filter, "", nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error listing resources: %w", err)
	}

	for iter.NotDone() {
		val := iter.Value()
		if err := iter.NextWithContext(ctx); err != nil {
			return nil, nil, nil, fmt.Errorf("error iterating resources: %w", err)
		}

		if val.ID == nil || val.Type == nil {
			continue
		}
		virtualMachineType := constMsComputeService + "/" + constVirtualMachinesResource
		virtualMachineScaleSetType := constMsComputeService + "/" + constVirtualMachineScaleSetsResource
		if strings.EqualFold(*val.Type, virtualMachineType) {
			vmResources = append(vmResources, val)
			resourceToSetMap[*val.ID] = append(resourceToSetMap[*val.ID], setID)
		} else if strings.EqualFold(*val.Type, virtualMachineScaleSetType) {
			vmssResources = append(vmssResources, val)
			resourceToSetMap[*val.ID] = append(resourceToSetMap[*val.ID], setID)
		}
	}

	return vmResources, vmssResources, resourceToSetMap, nil
}

// Resource Filter Management
func getSetFilter(set *hostsets.HostSet) string {
	setAttrFields := set.GetAttributes().GetFields()
	if setAttrFields[constFilter] != nil {
		if filter := setAttrFields[constFilter].GetStringValue(); filter != "" {
			return filter
		}
	}
	return ""
}

func validateHostSet(set *hostsets.HostSet) error {
	if set == nil {
		return errors.New("set is nil")
	}
	setAttrs := set.GetAttributes()
	if setAttrs == nil {
		return fmt.Errorf("set %s has no attributes", set.GetId())
	}
	if len(setAttrs.GetFields()) == 0 {
		return fmt.Errorf("set %s attributes has no filter", set.GetId())
	}
	return nil
}

// ID Parsing Functions
func splitId(in, expectedService, expectedResource string) (string, string, error) {
	// Note: this could be stolen from the helpers directory in the TF AzureRM
	// provider but I'm not at the moment because it does a bunch of trickery
	// for some Azure APIs and we have a much more limited scope.
	splitId := strings.Split(strings.TrimLeft(in, "/"), "/")

	// Run through some sanity checks
	if len(splitId) != 8 ||
		!strings.EqualFold(splitId[0], constSubscriptions) ||
		!strings.EqualFold(splitId[2], constResourceGroups) ||
		!strings.EqualFold(splitId[4], constProviders) ||
		!strings.EqualFold(splitId[5], expectedService) ||
		!strings.EqualFold(splitId[6], expectedResource) {
		return "", "", fmt.Errorf("unexpected format of resource ID: %v", splitId)
	}
	return splitId[3], splitId[7], nil
}

func extractResourceType(resourceID string) (string, error) {
	if resourceID == "" {
		return "", fmt.Errorf("empty resource ID provided")
	}

	parts := strings.Split(strings.TrimLeft(resourceID, "/"), "/")

	// Validate minimum length and basic structure
	if len(parts) < 6 {
		return "", fmt.Errorf("resource ID too short: %s", resourceID)
	}

	// Check for required segments in correct positions
	if !strings.EqualFold(parts[0], constSubscriptions) ||
		!strings.EqualFold(parts[2], constResourceGroups) ||
		!strings.EqualFold(parts[4], constProviders) {
		return "", fmt.Errorf("malformed resource ID, missing required segments: %s", resourceID)
	}

	// Check for Microsoft.Compute in correct position
	if !strings.EqualFold(parts[5], constMsComputeService) {
		return "", nil // Not a compute resource, return empty string without error
	}

	// Ensure there's a resource type after Microsoft.Compute
	if len(parts) < 7 {
		return "", fmt.Errorf("no resource type found after Microsoft.Compute: %s", resourceID)
	}

	return parts[6], nil
}

// Validation Functions
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

// Error Handling Functions
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

// Map Definitions for Allowed Fields
var allowedCatalogFields = map[string]struct{}{
	constDisableCredentialRotation: {},
	constSubscriptionId:            {},
	constTenantId:                  {},
	constClientId:                  {},
}

var allowedSetFields = map[string]struct{}{
	constFilter: {},
}
