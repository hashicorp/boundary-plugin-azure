// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

const (
	constBaseUrl                           = "base_url"
	constFilter                            = "filter"
	constSubscriptionId                    = "subscription_id"
	constClientId                          = "client_id"
	constSecretValue                       = "secret_value"
	constCredsLastRotatedTime              = "creds_last_rotated_time"
	constSecretId                          = "secret_id"
	constTenantId                          = "tenant_id"
	constDefaultFilter                     = "resourceType eq 'Microsoft.Compute/virtualMachines' or resourceType eq 'Microsoft.Compute/virtualMachineScaleSets'"
	constMsComputeService                  = "Microsoft.Compute"
	constVirtualMachineScaleSetsResource   = "virtualMachineScaleSets"
	constVirtualMachineScaleSetsVMResource = "virtualMachineScaleSets/virtualMachines"
	constVirtualMachinesResource           = "virtualMachines"
	constMsNetworkService                  = "Microsoft.Network"
	constNetworkInterfacesResource         = "networkInterfaces"
	constPublicIpAddressesResource         = "publicIPAddresses"
	constSubscriptions                     = "subscriptions"
	constResourceGroups                    = "resourceGroups"
	constProviders                         = "providers"
	constDisableCredentialRotation         = "disable_credential_rotation"
)
