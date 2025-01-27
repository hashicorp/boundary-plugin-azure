// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/network/mgmt/network"
)

type networkInfo struct {
	IpAddresses []string
}

// Common interface for IP configuration processing
type networkProcessor interface {
	processIPConfigurations(ctx context.Context, ipConfigs []network.InterfaceIPConfiguration, ifName string) (*networkInfo, error)
	getPublicIPAddress(ctx context.Context, publicIPRef *network.PublicIPAddress, ipConf *network.InterfaceIPConfiguration, ifName string) (string, error)
	getNetworkInterface(ctx context.Context, interfaceID string) (*network.Interface, string, error)
}

// Standard VM network processor
type vmNetworkProcessor struct {
	clients       *azureClients
	resourceGroup string
}

// VMSS network processor
type vmssNetworkProcessor struct {
	clients       *azureClients
	resourceGroup string
	vmssName      string
	instanceID    string
}

func processNetworkProfile(
	ctx context.Context,
	interfaces []compute.NetworkInterfaceReference,
	processor networkProcessor,
	targetInfo *networkInfo,
) error {

	for _, ifaceRef := range interfaces {
		if ifaceRef.ID == nil {
			return fmt.Errorf("nil ID for network interface")
		}

		iface, ifName, err := processor.getNetworkInterface(ctx, *ifaceRef.ID)
		if err != nil {
			return err
		}

		if iface.InterfacePropertiesFormat == nil || iface.InterfacePropertiesFormat.IPConfigurations == nil {
			continue
		}

		networkInfo, err := processor.processIPConfigurations(ctx, *iface.InterfacePropertiesFormat.IPConfigurations, ifName)
		if err != nil {
			return err
		}
		targetInfo.IpAddresses = append(targetInfo.IpAddresses, networkInfo.IpAddresses...)
	}
	return nil
}

func (p *vmNetworkProcessor) getNetworkInterface(ctx context.Context, interfaceID string) (*network.Interface, string, error) {
	ifResGroup, ifName, err := splitId(interfaceID, constMsNetworkService, constNetworkInterfacesResource)
	if err != nil {
		return nil, "", fmt.Errorf("error splitting network interface id %q: %w", interfaceID, err)
	}

	iface, err := p.clients.ifClient.Get(ctx, ifResGroup, ifName, "")
	if err != nil {
		return nil, "", fmt.Errorf("error fetching network interface: %w", err)
	}

	return &iface, ifName, nil
}

func (p *vmNetworkProcessor) processIPConfigurations(
	ctx context.Context,
	ipConfigs []network.InterfaceIPConfiguration,
	ifName string,
) (
	*networkInfo,
	error,
) {
	tempInfo := &networkInfo{}
	for _, ipconf := range ipConfigs {
		// Process private IP
		if ipconf.PrivateIPAddress != nil {
			tempInfo.IpAddresses = append(tempInfo.IpAddresses, *ipconf.PrivateIPAddress)
		}

		// Process public IP if available
		if ipconf.PublicIPAddress != nil {
			ipAddress, err := p.getPublicIPAddress(ctx, ipconf.PublicIPAddress, &ipconf, ifName)
			if err != nil {
				return nil, err
			}
			tempInfo.IpAddresses = append(tempInfo.IpAddresses, ipAddress)
		}
	}
	return tempInfo, nil
}

func (p *vmNetworkProcessor) getPublicIPAddress(
	ctx context.Context,
	publicIP *network.PublicIPAddress,
	ipConf *network.InterfaceIPConfiguration,
	ifName string,
) (
	string,
	error,
) {
	if publicIP.ID == nil {
		return "", fmt.Errorf("ip configuration has public IP address info but nil id")
	}

	ipResGroup, ipName, err := splitId(*publicIP.ID, constMsNetworkService, constPublicIpAddressesResource)
	if err != nil {
		return "", fmt.Errorf("error splitting public ip address id: %w", err)
	}

	pipInfo, err := p.clients.pipClient.Get(ctx, ipResGroup, ipName, "")
	if err != nil {
		return "", fmt.Errorf("error fetching public IP information: %w", err)
	}

	if pipInfo.PublicIPAddressPropertiesFormat == nil {
		return "", fmt.Errorf("nil public ip address properties format for public ip %q", *publicIP.ID)
	}

	if pipInfo.PublicIPAddressPropertiesFormat.IPAddress == nil {
		return "", fmt.Errorf("nil IP address for public ip %q", *publicIP.ID)
	}

	return *pipInfo.PublicIPAddressPropertiesFormat.IPAddress, nil
}

func (p *vmssNetworkProcessor) getNetworkInterface(ctx context.Context, interfaceID string) (*network.Interface, string, error) {
	ifName := extractResourceSuffix(interfaceID)

	iface, err := p.clients.ifClient.GetVirtualMachineScaleSetNetworkInterface(
		ctx,
		p.resourceGroup,
		p.vmssName,
		p.instanceID,
		ifName,
		"")
	if err != nil {
		return nil, "", fmt.Errorf("error fetching VMSS network interface: %w", err)
	}

	return &iface, ifName, nil
}

func (p *vmssNetworkProcessor) processIPConfigurations(
	ctx context.Context,
	ipConfigs []network.InterfaceIPConfiguration,
	ifName string,
) (
	*networkInfo,
	error,
) {
	tempInfo := &networkInfo{}
	for _, ipconf := range ipConfigs {
		if ipconf.PrivateIPAddress != nil {
			tempInfo.IpAddresses = append(tempInfo.IpAddresses, *ipconf.PrivateIPAddress)
		}

		if ipconf.PublicIPAddress != nil {
			ipAddress, err := p.getPublicIPAddress(ctx, ipconf.PublicIPAddress, &ipconf, ifName)
			if err != nil {
				return nil, err
			}
			tempInfo.IpAddresses = append(tempInfo.IpAddresses, ipAddress)
		}
	}
	return tempInfo, nil
}

func (p *vmssNetworkProcessor) getPublicIPAddress(
	ctx context.Context,
	publicIP *network.PublicIPAddress,
	ipConf *network.InterfaceIPConfiguration,
	ifName string,
) (
	string,
	error,
) {
	if publicIP == nil || publicIP.ID == nil || ipConf.Name == nil {
		return "", fmt.Errorf("invalid public IP configuration")
	}

	pipName := extractResourceSuffix(*publicIP.ID)
	pipInfo, err := p.clients.pipClient.GetVirtualMachineScaleSetPublicIPAddress(
		ctx,
		p.resourceGroup,
		p.vmssName,
		p.instanceID,
		ifName,
		*ipConf.Name,
		pipName,
		"")
	if err != nil {
		return "", fmt.Errorf("error fetching public IP information: %w", err)
	}

	if pipInfo.PublicIPAddressPropertiesFormat == nil {
		return "", fmt.Errorf("nil public ip address properties format")
	}

	if pipInfo.PublicIPAddressPropertiesFormat.IPAddress == nil {
		return "", fmt.Errorf("nil IP address for public ip %q", *publicIP.ID)
	}

	return *pipInfo.PublicIPAddressPropertiesFormat.IPAddress, nil
}

func processVMNetworkInterfaces(
	ctx context.Context,
	vm compute.VirtualMachine,
	clients *azureClients,
	resourceGroup string,
	netInfo *networkInfo,
) error {

	if vm.VirtualMachineProperties == nil || vm.VirtualMachineProperties.NetworkProfile == nil {
		return fmt.Errorf("error fetching network profile")
	}

	processor := &vmNetworkProcessor{
		clients:       clients,
		resourceGroup: resourceGroup,
	}

	return processNetworkProfile(ctx, *vm.VirtualMachineProperties.NetworkProfile.NetworkInterfaces, processor, netInfo)
}

func processVMSSNetworkInterfaces(
	ctx context.Context,
	vmssvm compute.VirtualMachineScaleSetVM,
	resourceGroup, vmssName string,
	clients *azureClients,
	netInfo *networkInfo,
) error {

	if vmssvm.VirtualMachineScaleSetVMProperties == nil ||
		vmssvm.VirtualMachineScaleSetVMProperties.NetworkProfile == nil {
		return fmt.Errorf("error fetching network profile")
	}

	if vmssvm.InstanceID == nil {
		return fmt.Errorf("instance ID is nil")
	}

	processor := &vmssNetworkProcessor{
		clients:       clients,
		resourceGroup: resourceGroup,
		vmssName:      vmssName,
		instanceID:    *vmssvm.InstanceID,
	}

	return processNetworkProfile(ctx,
		*vmssvm.VirtualMachineScaleSetVMProperties.NetworkProfile.NetworkInterfaces, processor, netInfo)
}

// extractResourceSuffix extracts the resource name from the end of an Azure resource ID
func extractResourceSuffix(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
