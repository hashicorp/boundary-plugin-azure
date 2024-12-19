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

// vmJob represents a single VM processing job
type vmJob struct {
	resource      resources.GenericResourceExpanded
	resourceGroup string
	name          string
}

func (p *AzurePlugin) processStandardVMs(ctx context.Context, resourceInfos []resources.GenericResourceExpanded,
	clients *azureClients, vmToNetworkMap map[string]networkInfo) error {

	// Create error group for worker management
	g, ctx := errgroup.WithContext(ctx)

	// Create job channel
	jobs := make(chan vmJob)

	// Start workers
	workerCount := constDefaultWorkers
	if len(resourceInfos) < workerCount {
		workerCount = len(resourceInfos)
	}

	// Result handling
	var mu sync.Mutex

	// Start worker pool
	for i := 0; i < workerCount; i++ {
		g.Go(func() error {
			for job := range jobs {
				// Process single VM
				vm, err := clients.vmClient.Get(ctx, job.resourceGroup, job.name, "")
				if err != nil {
					return fmt.Errorf("error fetching vm with id %q: %w", *job.resource.ID, err)
				}

				// Only process running VMs
				running, err := isVMRunning(ctx, clients.vmClient, job.resourceGroup, job.name)
				if err != nil {
					return err
				}
				if !running {
					continue
				}

				var netInfo networkInfo
				if err := processVMNetworkInterfaces(ctx, vm, clients, job.resourceGroup, &netInfo); err != nil {
					return err
				}

				// Thread-safe map update - scope the lock to just the map update
				func() {
					mu.Lock()
					defer mu.Unlock()
					vmToNetworkMap[*job.resource.ID] = netInfo
				}()
			}
			return nil
		})
	}

	// Send jobs to workers
	go func() {
		defer close(jobs)
		for _, res := range resourceInfos {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			resourceGroup, name, err := splitId(*res.ID, constMsComputeService, constVirtualMachinesResource)
			if err != nil {
				// Can't send error through channel, so we'll skip this item
				fmt.Printf("Warning: error splitting vm id %q: %v\n", *res.ID, err)
				continue
			}

			job := vmJob{
				resource:      res,
				resourceGroup: resourceGroup,
				name:          name,
			}

			jobs <- job
		}
	}()

	// Wait for all workers to complete
	return g.Wait()
}

// VM Status Check
func isVMRunning(ctx context.Context, vmClient *compute.VirtualMachinesClient,
	resourceGroup, name string) (bool, error) {

	iv, err := vmClient.InstanceView(ctx, resourceGroup, name)
	if err != nil {
		return false, fmt.Errorf("error fetching instance view for vm %s: %w", name, err)
	}
	if iv.Statuses == nil {
		return false, fmt.Errorf("instance view statuses is null for vm %s", name)
	}

	for _, s := range *iv.Statuses {
		if s.Code == nil {
			continue
		}
		state := strings.ToLower(*s.Code)
		if strings.HasPrefix(state, "powerstate/") && strings.TrimPrefix(state, "powerstate/") == "running" {
			return true, nil
		}
	}
	return false, nil
}
