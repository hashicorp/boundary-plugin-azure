// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

const (
	// Azure service constants
	constMsComputeService = "Microsoft.Compute"
	constMsNetworkService = "Microsoft.Network"
	constSubscriptions    = "subscriptions"
	constResourceGroups   = "resourceGroups"
	constProviders        = "providers"

	// Resource type constants
	constVirtualMachinesResource         = "virtualMachines"
	constVirtualMachineScaleSetsResource = "virtualMachineScaleSets"
	constNetworkInterfacesResource       = "networkInterfaces"
	constPublicIpAddressesResource       = "publicIPAddresses"

	// Field constants
	constFilter                    = "filter"
	constSecretId                  = "secret_id"
	constSecretValue               = "secret_value"
	constCredsLastRotatedTime      = "creds_last_rotated_time"
	constDisableCredentialRotation = "disable_credential_rotation"
	constSubscriptionId            = "subscription_id"
	constTenantId                  = "tenant_id"
	constClientId                  = "client_id"
	constBaseUrl                   = "base_url"

	// Worker pool configuration
	constDefaultWorkers = 1000
)
