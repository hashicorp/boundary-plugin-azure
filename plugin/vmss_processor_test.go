// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"testing"
)

func TestGetExternalNameforVMSSInstance(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid vmss instance id",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/instance1",
			want:    "vmss1_instance1",
			wantErr: false,
		},
		{
			name:    "invalid - vmss instance id with trailing slash",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/instance1/",
			want:    "",
			wantErr: true,
		},
		{
			name:    "case insensitive segment validation",
			input:   "/SUBSCRIPTIONS/sub1/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/vmss1/VIRTUALMACHINES/instance1",
			want:    "vmss1_instance1",
			wantErr: false,
		},
		{
			name:    "invalid - missing segment",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - wrong resource type",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - malformed id",
			input:   "invalid/format/string",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getExternalNameforVMSSInstance(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("getExternalNameforVMSSInstance() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getExternalNameforVMSSInstance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetSetForVMSSInstance(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid vmss instance id",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/instance1",
			want:    "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			wantErr: false,
		},
		{
			name:    "valid vmss path without instance",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			want:    "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			wantErr: false,
		},
		{
			name:    "case insensitive validation",
			input:   "/SUBSCRIPTIONS/sub1/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/vmss1",
			want:    "/SUBSCRIPTIONS/sub1/RESOURCEGROUPS/rg1/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/vmss1",
			wantErr: false,
		},
		{
			name:    "path with trailing slash",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/instance1/",
			want:    "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - flexible orchestration mode VM path",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vmss1_instance1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - wrong provider",
			input:   "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Storage/virtualMachineScaleSets/vmss1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - malformed path missing segments",
			input:   "/subscriptions/sub1/resourceGroups",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - malformed with virtualMachines in wrong position",
			input:   "/subscriptions/sub1/resourceGroups/rg1/virtualMachines/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid - random string",
			input:   "not/a/valid/path",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSetForVMSSInstance(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSetForVMSSInstance() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSetForVMSSInstance() = %v, want %v", got, tt.want)
			}
		})
	}
}
