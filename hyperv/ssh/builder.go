//Heavily borrowed from the built in packer hyperv plugin
package ssh

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/packer/common"
	"github.com/hashicorp/packer/packer"
	"github.com/hashicorp/packer/helper/config"
	"github.com/hashicorp/packer/helper/multistep"
	"github.com/hashicorp/packer/template/interpolate"
	pssh "github.com/mletterle/packer-builder-hyperv-ssh/powershell/ssh"
	hypervcommon "github.com/hashicorp/packer/builder/hyperv/common"
)

const (
	DefaultDiskSize = 40 * 1024        // ~40GB
	MinDiskSize     = 256              // 256MB
	MaxDiskSize     = 64 * 1024 * 1024 // 64TB

	DefaultRamSize                 = 1 * 1024  // 1GB
	MinRamSize                     = 32        // 32MB
	MaxRamSize                     = 32 * 1024 // 32GB
	MinNestedVirtualizationRamSize = 4 * 1024  // 4GB

	LowRam = 256 // 256MB

	DefaultUsername = ""
	DefaultPassword = ""
)

// Builder implements packer.Builder and builds the actual Hyperv
// images.
type Builder struct {
	config Config
	runner multistep.Runner
	ps *pssh.PowershellSession
}

type Config struct {
	common.PackerConfig         `mapstructure:",squash"`
	common.HTTPConfig           `mapstructure:",squash"`
	common.ISOConfig            `mapstructure:",squash"`
	common.FloppyConfig         `mapstructure:",squash"`
	hypervcommon.OutputConfig   `mapstructure:",squash"`
	hypervcommon.SSHConfig      `mapstructure:",squash"`
	hypervcommon.RunConfig      `mapstructure:",squash"`
	hypervcommon.ShutdownConfig `mapstructure:",squash"`

	DiskSize uint `mapstructure:"disk_size"`

	// The size, in megabytes, of the computer memory in the VM.
	// By default, this is 1024 (about 1 GB).
	RamSize uint `mapstructure:"ram_size"`

	//
	SecondaryDvdImages []string `mapstructure:"secondary_iso_images"`

	// Should integration services iso be mounted
	GuestAdditionsMode string `mapstructure:"guest_additions_mode"`

	// The path to the integration services iso
	GuestAdditionsPath string `mapstructure:"guest_additions_path"`

	// This is the name of the new virtual machine.
	// By default this is "packer-BUILDNAME", where "BUILDNAME" is the name of the build.
	VMName string `mapstructure:"vm_name"`

	// Use differencing disk
	DifferencingDisk bool `mapstructure:"differencing_disk"`

	BootCommand                    []string `mapstructure:"boot_command"`
	SwitchName                     string   `mapstructure:"switch_name"`
	SwitchVlanId                   string   `mapstructure:"switch_vlan_id"`
	MacAddress                     string   `mapstructure:"mac_address"`
	VlanId                         string   `mapstructure:"vlan_id"`
	Cpu                            uint     `mapstructure:"cpu"`
	Generation                     uint     `mapstrucutre:"generation"`
	EnableMacSpoofing              bool `mapstructure:"enable_mac_spoofing"`
	EnableDynamicMemory            bool `mapstructure:"enable_dynamic_memory"`
	EnableSecureBoot               bool `mapstructure:"enable_secure_boot"`
	EnableVirtualizationExtensions bool `mapstructure:"enable_virtualization_extensions"`
	// New Configs
	HyperVServer                   string `mapstructure:"hyperv_server"`
	HyperVUsername                 string `mapstructure:"hyperv_username"`
	HyperVPassword                 string `mapstructure:"hyperv_password"`

	Communicator string `mapstructure:"communicator"`

	SkipCompaction bool `mapstructure:"skip_compaction"`

	SkipExport bool `mapstructure:"skip_export"`

	ctx interpolate.Context
}

func (b *Builder) Prepare(raws ...interface{}) ([]string, error) {
	err := config.Decode(&b.config, &config.DecodeOpts{
		Interpolate:        true,
		InterpolateContext: &b.config.ctx,
		InterpolateFilter: &interpolate.RenderFilter{
			Exclude: []string{
				"boot_command",
			},
		},
	}, raws...)
	if err != nil {
		return nil, err
	}

	// Accumulate any errors and warnings
	var errs *packer.MultiError
	warnings := make([]string, 0)

	isoWarnings, isoErrs := b.config.ISOConfig.Prepare(&b.config.ctx)
	warnings = append(warnings, isoWarnings...)
	errs = packer.MultiErrorAppend(errs, isoErrs...)

	errs = packer.MultiErrorAppend(errs, b.config.FloppyConfig.Prepare(&b.config.ctx)...)
	errs = packer.MultiErrorAppend(errs, b.config.HTTPConfig.Prepare(&b.config.ctx)...)
	errs = packer.MultiErrorAppend(errs, b.config.RunConfig.Prepare(&b.config.ctx)...)
	errs = packer.MultiErrorAppend(errs, b.config.OutputConfig.Prepare(&b.config.ctx, &b.config.PackerConfig)...)
	errs = packer.MultiErrorAppend(errs, b.config.SSHConfig.Prepare(&b.config.ctx)...)
	errs = packer.MultiErrorAppend(errs, b.config.ShutdownConfig.Prepare(&b.config.ctx)...)

	if len(b.config.ISOConfig.ISOUrls) < 1 || (strings.ToLower(filepath.Ext(b.config.ISOConfig.ISOUrls[0])) != ".vhd" && strings.ToLower(filepath.Ext(b.config.ISOConfig.ISOUrls[0])) != ".vhdx") {
		//We only create a new hard drive if an existing one to copy from does not exist
/*		err = b.checkDiskSize()
		if err != nil {
			errs = packer.MultiErrorAppend(errs, err)
		} */
	}

/*	err = b.checkRamSize()
	if err != nil {
		errs = packer.MultiErrorAppend(errs, err)
	} */

	if b.config.VMName == "" {
		b.config.VMName = fmt.Sprintf("packer-%s", b.config.PackerBuildName)
	}

	log.Println(fmt.Sprintf("%s: %v", "VMName", b.config.VMName))

/*	if b.config.SwitchName == "" {
		b.config.SwitchName = b.detectSwitchName()
	} */

	if b.config.Cpu < 1 {
		b.config.Cpu = 1
	}

	if b.config.Generation < 1 || b.config.Generation > 2 {
		b.config.Generation = 1
	}

	if b.config.Generation == 2 {
		if len(b.config.FloppyFiles) > 0 || len(b.config.FloppyDirectories) > 0 {
			err = errors.New("Generation 2 vms don't support floppy drives. Use ISO image instead.")
			errs = packer.MultiErrorAppend(errs, err)
		}
	}

/*	if len(b.config.AdditionalDiskSize) > 64 {
		err = errors.New("VM's currently support a maximun of 64 additional SCSI attached disks.")
		errs = packer.MultiErrorAppend(errs, err)
	} */

	log.Println(fmt.Sprintf("Using switch %s", b.config.SwitchName))
	log.Println(fmt.Sprintf("%s: %v", "SwitchName", b.config.SwitchName))

	// Errors

	if b.config.GuestAdditionsMode == "" {
		if b.config.GuestAdditionsPath != "" {
			b.config.GuestAdditionsMode = "attach"
		} else {
			b.config.GuestAdditionsPath = os.Getenv("WINDIR") + "\\system32\\vmguest.iso"

			if _, err := os.Stat(b.config.GuestAdditionsPath); os.IsNotExist(err) {
				if err != nil {
					b.config.GuestAdditionsPath = ""
					b.config.GuestAdditionsMode = "none"
				} else {
					b.config.GuestAdditionsMode = "attach"
				}
			}
		}
	}

	if b.config.GuestAdditionsPath == "" && b.config.GuestAdditionsMode == "attach" {
		b.config.GuestAdditionsPath = os.Getenv("WINDIR") + "\\system32\\vmguest.iso"

		if _, err := os.Stat(b.config.GuestAdditionsPath); os.IsNotExist(err) {
			if err != nil {
				b.config.GuestAdditionsPath = ""
			}
		}
	}

	for _, isoPath := range b.config.SecondaryDvdImages {
		if _, err := os.Stat(isoPath); os.IsNotExist(err) {
			if err != nil {
				errs = packer.MultiErrorAppend(
					errs, fmt.Errorf("Secondary Dvd image does not exist: %s", err))
			}
		}
	}

	numberOfIsos := len(b.config.SecondaryDvdImages)

	if b.config.GuestAdditionsMode == "attach" {
		if _, err := os.Stat(b.config.GuestAdditionsPath); os.IsNotExist(err) {
			if err != nil {
				errs = packer.MultiErrorAppend(
					errs, fmt.Errorf("Guest additions iso does not exist: %s", err))
			}
		}

		numberOfIsos = numberOfIsos + 1
	}

	if b.config.Generation < 2 && numberOfIsos > 2 {
		if b.config.GuestAdditionsMode == "attach" {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("There are only 2 ide controllers available, so we can't support guest additions and these secondary dvds: %s", strings.Join(b.config.SecondaryDvdImages, ", ")))
		} else {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("There are only 2 ide controllers available, so we can't support these secondary dvds: %s", strings.Join(b.config.SecondaryDvdImages, ", ")))
		}
	} else if b.config.Generation > 1 && len(b.config.SecondaryDvdImages) > 16 {
		if b.config.GuestAdditionsMode == "attach" {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("There are not enough drive letters available for scsi (limited to 16), so we can't support guest additions and these secondary dvds: %s", strings.Join(b.config.SecondaryDvdImages, ", ")))
		} else {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("There are not enough drive letters available for scsi (limited to 16), so we can't support these secondary dvds: %s", strings.Join(b.config.SecondaryDvdImages, ", ")))
		}
	}
/*
	if b.config.EnableVirtualizationExtensions {
		hasVirtualMachineVirtualizationExtensions, err := powershell.HasVirtualMachineVirtualizationExtensions()
		if err != nil {
			errs = packer.MultiErrorAppend(errs, fmt.Errorf("Failed detecting virtual machine virtualization extensions support: %s", err))
		} else {
			if !hasVirtualMachineVirtualizationExtensions {
				errs = packer.MultiErrorAppend(errs, fmt.Errorf("This version of Hyper-V does not support virtual machine virtualization extension. Please use Windows 10 or Windows Server 2016 or newer."))
			}
		}
	}
*/
	// Warnings

	if b.config.ShutdownCommand == "" {
		warnings = append(warnings,
			"A shutdown_command was not specified. Without a shutdown command, Packer\n"+
				"will forcibly halt the virtual machine, which may result in data loss.")
	}
	warning := ""
/*	warning := b.checkHostAvailableMemory()
	if warning != "" {
		warnings = appendWarnings(warnings, warning)
	}
*/
	if b.config.EnableVirtualizationExtensions {
		if b.config.EnableDynamicMemory {
			warning = fmt.Sprintf("For nested virtualization, when virtualization extension is enabled, dynamic memory should not be allowed.")
			warnings = appendWarnings(warnings, warning)
		}

		if !b.config.EnableMacSpoofing {
			warning = fmt.Sprintf("For nested virtualization, when virtualization extension is enabled, mac spoofing should be allowed.")
			warnings = appendWarnings(warnings, warning)
		}

		if b.config.RamSize < MinNestedVirtualizationRamSize {
			warning = fmt.Sprintf("For nested virtualization, when virtualization extension is enabled, there should be 4GB or more memory set for the vm, otherwise Hyper-V may fail to start any nested VMs.")
			warnings = appendWarnings(warnings, warning)
		}
	}

	if b.config.SwitchVlanId != "" {
		if b.config.SwitchVlanId != b.config.VlanId {
			warning = fmt.Sprintf("Switch network adaptor vlan should match virtual machine network adaptor vlan. The switch will not be able to see traffic from the VM.")
			warnings = appendWarnings(warnings, warning)
		}
	}

	if errs != nil && len(errs.Errors) > 0 {
		return warnings, errs
	}

	return warnings, nil

}

func (b *Builder) Run(ui packer.Ui, hook packer.Hook, cache packer.Cache) (packer.Artifact, error) {
	ui.Say(fmt.Sprintf("Connecting to %s as %s...", b.config.HyperVServer, b.config.HyperVUsername))
	b.ps = pssh.Connect(b.config.HyperVServer, b.config.HyperVUsername, b.config.HyperVPassword)
	output, err := b.ps.Output("$env:COMPUTERNAME")
	o, err := b.ps.Output("$env:USERNAME")
	output += o
	if err != nil {
		panic(err)
	}
	ui.Say(output)
	return nil, nil
}

func (b *Builder) Cancel() {

}

func appendWarnings(slice []string, data ...string) []string {
	m := len(slice)
	n := m + len(data)
	if n > cap(slice) { // if necessary, reallocate
		// allocate double what's needed, for future growth.
		newSlice := make([]string, (n+1)*2)
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0:n]
	copy(slice[m:n], data)
	return slice
}
