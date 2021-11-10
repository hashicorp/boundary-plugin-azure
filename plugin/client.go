package plugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	hauth "github.com/manicminer/hamilton/auth"
	"github.com/manicminer/hamilton/msgraph"
)

func getResourcesClient(opt ...Option) (*resources.Client, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing ops: %w", err)
	}
	if opts.withSubscriptionId == "" {
		return nil, errors.New("subscription id is empty")
	}
	if opts.withAuthorizer == nil {
		return nil, errors.New("authorizer is nil")
	}
	var client resources.Client
	switch opts.withBaseUrl {
	case "":
		client = resources.NewClient(opts.withSubscriptionId)
	default:
		client = resources.NewClientWithBaseURI(opts.withBaseUrl, opts.withSubscriptionId)
	}
	client.Authorizer = opts.withAuthorizer
	if err := client.AddToUserAgent(opts.withUserAgent); err != nil {
		return nil, fmt.Errorf("error adding identifier to user-agent: %w", err)
	}
	return &client, nil
}

func getVirtualMachinesClient(opt ...Option) (*compute.VirtualMachinesClient, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing ops: %w", err)
	}
	if opts.withSubscriptionId == "" {
		return nil, errors.New("subscription id is empty")
	}
	if opts.withAuthorizer == nil {
		return nil, errors.New("authorizer is nil")
	}
	var client compute.VirtualMachinesClient
	switch opts.withBaseUrl {
	case "":
		client = compute.NewVirtualMachinesClient(opts.withSubscriptionId)
	default:
		client = compute.NewVirtualMachinesClientWithBaseURI(opts.withBaseUrl, opts.withSubscriptionId)
	}
	client.Authorizer = opts.withAuthorizer
	if err := client.AddToUserAgent(opts.withUserAgent); err != nil {
		return nil, fmt.Errorf("error adding identifier to user-agent: %w", err)
	}
	return &client, nil
}

func getNetworkInterfacesClient(opt ...Option) (*network.InterfacesClient, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing ops: %w", err)
	}
	if opts.withSubscriptionId == "" {
		return nil, errors.New("subscription id is empty")
	}
	if opts.withAuthorizer == nil {
		return nil, errors.New("authorizer is nil")
	}
	var client network.InterfacesClient
	switch opts.withBaseUrl {
	case "":
		client = network.NewInterfacesClient(opts.withSubscriptionId)
	default:
		client = network.NewInterfacesClientWithBaseURI(opts.withBaseUrl, opts.withSubscriptionId)
	}
	client.Authorizer = opts.withAuthorizer
	if err := client.AddToUserAgent(opts.withUserAgent); err != nil {
		return nil, fmt.Errorf("error adding identifier to user-agent: %w", err)
	}
	return &client, nil
}

func getPublicIpAddressesClient(opt ...Option) (*network.PublicIPAddressesClient, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error parsing ops: %w", err)
	}
	if opts.withSubscriptionId == "" {
		return nil, errors.New("subscription id is empty")
	}
	if opts.withAuthorizer == nil {
		return nil, errors.New("authorizer is nil")
	}
	var client network.PublicIPAddressesClient
	switch opts.withBaseUrl {
	case "":
		client = network.NewPublicIPAddressesClient(opts.withSubscriptionId)
	default:
		client = network.NewPublicIPAddressesClientWithBaseURI(opts.withBaseUrl, opts.withSubscriptionId)
	}
	client.Authorizer = opts.withAuthorizer
	if err := client.AddToUserAgent(opts.withUserAgent); err != nil {
		return nil, fmt.Errorf("error adding identifier to user-agent: %w", err)
	}
	return &client, nil
}

func getApplicationsClient(ctx context.Context, authzInfo *AuthorizationInfo) (*msgraph.ApplicationsClient, error) {
	if authzInfo == nil {
		return nil, errors.New("empty auth config id when fetching service principals client")
	}

	authorizer, err := authzInfo.HamiltonConfig.NewAuthorizer(ctx, hauth.MsGraph)
	if err != nil {
		return nil, fmt.Errorf("error fetching hauth authorizer when fetching service principals client: %w", err)
	}

	client := msgraph.NewApplicationsClient(authzInfo.AuthParams.TenantId)
	client.BaseClient.Authorizer = authorizer

	return client, nil
}
