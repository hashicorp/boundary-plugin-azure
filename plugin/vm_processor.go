// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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
	clients *azureClients) (map[string]networkInfo, error) {

	// Initialize the map that we'll return
	vmToNetworkMap := make(map[string]networkInfo)

	// Pre-validate all resource IDs and create jobs slice
	jobs := make([]vmJob, 0, len(resourceInfos))
	for _, res := range resourceInfos {
		resourceGroup, name, err := splitId(*res.ID, constMsComputeService, constVirtualMachinesResource)
		if err != nil {
			return nil, fmt.Errorf("invalid vm id %q: %w", *res.ID, err)
		}
		jobs = append(jobs, vmJob{
			resource:      res,
			resourceGroup: resourceGroup,
			name:          name,
		})
	}

	// Create error group for worker management
	g, ctx := errgroup.WithContext(ctx)

	// Create job channel
	jobsChan := make(chan vmJob)

	// Result handling
	mu := &sync.Mutex{}

	// Start worker pool
	for i := 0; i < constDefaultWorkers; i++ {
		g.Go(func() error {
			for job := range jobsChan {
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

				mu.Lock()
				vmToNetworkMap[*job.resource.ID] = netInfo
				mu.Unlock()
			}
			return nil
		})
	}

	// Send jobs to workers
	go func() {
		defer close(jobsChan)
		for _, job := range jobs {
			// Check context cancellation
			if ctx.Err() != nil {
				return
			}
			jobsChan <- job
		}
	}()

	// Wait for all workers to complete
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return vmToNetworkMap, nil
}

// VM Status Check
func isVMRunning(
	ctx context.Context,
	vmClient *compute.VirtualMachinesClient,
	resourceGroup,
	name string,
) (
	bool,
	error,
) {

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
