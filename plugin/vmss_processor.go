package plugin

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/compute/mgmt/compute"
	"github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"golang.org/x/sync/errgroup"
)

// vmssJob represents a single VMSS processing job
type vmssJob struct {
	resource      resources.GenericResourceExpanded
	resourceGroup string
	name          string
}

// vmssInstanceJob represents a single VMSS instance processing job
type vmssInstanceJob struct {
	vmssvm        compute.VirtualMachineScaleSetVM
	resourceGroup string
	vmssName      string
}

func (p *AzurePlugin) processVMScaleSets(ctx context.Context, resourceInfos []resources.GenericResourceExpanded,
	clients *azureClients, vmToNetworkMap map[string]networkInfo) error {

	// Create error group for worker management
	g, ctx := errgroup.WithContext(ctx)

	// Create job channel
	jobs := make(chan vmssJob)

	// Start workers
	workerCount := constDefaultWorkers
	if len(resourceInfos) < workerCount {
		workerCount = len(resourceInfos)
	}

	// Start worker pool
	for i := 0; i < workerCount; i++ {
		g.Go(func() error {
			for job := range jobs {
				vmss, err := clients.vmssClient.Get(ctx, job.resourceGroup, job.name, "")
				if err != nil {
					return fmt.Errorf("error fetching vmss with id %q: %w", *job.resource.ID, err)
				}

				vmssProperties := vmss.VirtualMachineScaleSetProperties
				// Skip Flexible orchestration mode VMSS
				if vmssProperties.OrchestrationMode == compute.OrchestrationModeFlexible {
					continue
				}

				if err := processVMSSInstancesParallel(ctx, vmss, job.resourceGroup, clients, vmToNetworkMap); err != nil {
					return fmt.Errorf("error processing uniform vmss instances: %w", err)
				}
			}
			return nil
		})
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, res := range resourceInfos {
			select {
			case <-ctx.Done():
				return
			default:
			}

			resourceGroup, name, err := splitId(*res.ID, constMsComputeService, constVirtualMachineScaleSetsResource)
			if err != nil {
				fmt.Printf("Warning: error splitting vmss id %q: %v\n", *res.ID, err)
				continue
			}

			jobs <- vmssJob{
				resource:      res,
				resourceGroup: resourceGroup,
				name:          name,
			}
		}
	}()

	return g.Wait()
}

func processVMSSInstancesParallel(ctx context.Context, vmss compute.VirtualMachineScaleSet,
	resourceGroup string, clients *azureClients, vmToNetworkMap map[string]networkInfo) error {

	if vmss.Name == nil {
		return fmt.Errorf("vmss name is nil")
	}

	vmssvms, err := clients.vmssvmClient.List(ctx, resourceGroup, *vmss.Name, "", "", "")
	if err != nil {
		return fmt.Errorf("error fetching vms for vmss %s: %w", *vmss.Name, err)
	}

	// Create new error group for instance processing
	g, ctx := errgroup.WithContext(ctx)
	instanceJobs := make(chan vmssInstanceJob)

	// Start instance workers
	instanceWorkerCount := constDefaultWorkers
	if len(vmssvms.Values()) < instanceWorkerCount {
		instanceWorkerCount = len(vmssvms.Values())
	}

	var mu sync.Mutex

	// Start instance worker pool
	for i := 0; i < instanceWorkerCount; i++ {
		g.Go(func() error {
			for job := range instanceJobs {
				if job.vmssvm.ID == nil {
					return fmt.Errorf("nil ID for vmss vm in scale set %s", *vmss.Name)
				}

				if err := processVMSSInstanceParallel(ctx, job.vmssvm, job.resourceGroup,
					job.vmssName, clients, vmToNetworkMap, &mu); err != nil {
					return fmt.Errorf("error processing vmss instance %s: %w", *job.vmssvm.ID, err)
				}
			}
			return nil
		})
	}

	// Send instance jobs
	go func() {
		defer close(instanceJobs)
		for _, vmssvm := range vmssvms.Values() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			instanceJobs <- vmssInstanceJob{
				vmssvm:        vmssvm,
				resourceGroup: resourceGroup,
				vmssName:      *vmss.Name,
			}
		}
	}()

	return g.Wait()
}

func processVMSSInstanceParallel(ctx context.Context, vmssvm compute.VirtualMachineScaleSetVM,
	resourceGroup, vmssName string, clients *azureClients,
	vmToNetworkMap map[string]networkInfo, mu *sync.Mutex) error {

	if vmssvm.InstanceID == nil {
		return fmt.Errorf("instance ID is nil")
	}

	// Check if instance is running
	if running, err := isVMSSInstanceRunning(ctx, clients.vmssvmClient, resourceGroup,
		vmssName, vmssvm.InstanceID); err != nil {
		return err
	} else if !running {
		return nil
	}

	// Process network interfaces for the instance
	var netInfo networkInfo
	if err := processVMSSNetworkInterfaces(ctx, vmssvm, resourceGroup, vmssName, clients, &netInfo); err != nil {
		return err
	}

	func() {
		mu.Lock()
		defer mu.Unlock()
		vmToNetworkMap[*vmssvm.ID] = netInfo
	}()

	return nil
}

// VMSS Instance Status Check
func isVMSSInstanceRunning(ctx context.Context, vmssvmClient *compute.VirtualMachineScaleSetVMsClient,
	resourceGroup, vmssName string, instanceID *string) (bool, error) {

	if instanceID == nil {
		return false, fmt.Errorf("instance ID is nil")
	}

	iv, err := vmssvmClient.GetInstanceView(ctx, resourceGroup, vmssName, *instanceID)
	if err != nil {
		return false, fmt.Errorf("error fetching instance view for instance %s: %w", *instanceID, err)
	}
	if iv.Statuses == nil {
		return false, fmt.Errorf("instance view statuses returned for instance %s is null", *instanceID)
	}

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
			return true, nil
		}
	}
	return false, nil
}

// Helper Functions
func getSetForVMSSInstance(in string) string {
	trimmed := strings.Split(in, "/"+constVirtualMachinesResource)[0]
	return trimmed
}

func getExternalNameforVMSSInstance(in string) (string, error) {
	splitId := strings.Split(strings.TrimLeft(in, "/"), "/")
	if len(splitId) != 10 ||
		!strings.EqualFold(splitId[0], constSubscriptions) ||
		!strings.EqualFold(splitId[2], constResourceGroups) ||
		!strings.EqualFold(splitId[4], constProviders) ||
		!strings.EqualFold(splitId[5], constMsComputeService) ||
		!strings.EqualFold(splitId[6], constVirtualMachineScaleSetsResource) ||
		!strings.EqualFold(splitId[8], constVirtualMachinesResource) {
		return "", fmt.Errorf("unexpected format of virtual machine stateful set ID: %v", splitId)
	}
	return splitId[7] + "_" + splitId[9], nil
}
