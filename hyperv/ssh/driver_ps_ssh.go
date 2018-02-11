package ssh

import (
	"errors"
	"fmt"
	hypervcommon "github.com/hashicorp/packer/builder/hyperv/common"
	powershell "github.com/hashicorp/packer/common/powershell"
	pssh "github.com/mletterle/packer-builder-hyperv-ssh/powershell/ssh"
	"strconv"
	"strings"
)

type HypervSSHDriver struct {
	session *pssh.PowershellSession
}

func NewHypervPSSHDriver(pss *pssh.PowershellSession) (hypervcommon.Driver, error) {
	sshDriver := new(HypervSSHDriver)
	sshDriver.session = pss
	if err := sshDriver.Verify(); err != nil {
		return nil, err
	}
	return sshDriver, nil
}

// Checks if the VM named is running.
func (d *HypervSSHDriver) IsRunning(vmName string) (bool, error) {
	str, err := d.runScript(`function IsRunning {
param([string]$vmName)
$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
return $vm.State -eq [Microsoft.HyperV.PowerShell.VMState]::Running
} IsRunning "%s"`, vmName)
	running := powershell.IsTrue(str)
	return running, err
}

// Checks if the VM named is off.
func (d *HypervSSHDriver) IsOff(vmName string) (bool, error) {
	str, err := d.runScript(`function IsOff {
param([string]$vmName)
$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
$vm.State -eq [Microsoft.HyperV.PowerShell.VMState]::Off
} IsOff "%s"`, vmName)
	off := powershell.IsTrue(str)
	return off, err
}

//How long has VM been on
func (d *HypervSSHDriver) Uptime(vmName string) (uint64, error) {
	uptimeStr, _ := d.runScript(`function Uptime {
param([string]$vmName)
$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
return $vm.Uptime.TotalSeconds
} Update "%s"`, vmName)
	return strconv.ParseUint(uptimeStr, 10, 64)

}

// Start starts a VM specified by the name given.
func (d *HypervSSHDriver) Start(vmName string) error {
	return d.session.Run(fmt.Sprintf(`function StartAVM {
param([string]$vmName)
$vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
if ($vm.State -eq [Microsoft.HyperV.PowerShell.VMState]::Off) {
  Start-VM -Name $vmName -Confirm:$false
} } StartAVM "%s"`, vmName))
}

// Stop stops a VM specified by the name given.
func (d *HypervSSHDriver) Stop(vmName string) error {
	return d.session.Run(fmt.Sprintf(`function Stop {
param([string]$vmName)
$vm = Get-VM -Name $vmName
if ($vm.State -eq [Microsoft.HyperV.PowerShell.VMState]::Running) {
    Stop-VM -VM $vm -Force -Confirm:$false
} } Stop "%s"`, vmName))
}

// Verify checks to make sure that this driver should function
// properly. If there is any indication the driver can't function,
// this will return an error.
func (d *HypervSSHDriver) Verify() error {
	cmdOut, _ := d.session.Output("$PSVersionTable.PSVersion.Major")
	majorVer, _ := strconv.ParseInt(strings.TrimSpace(cmdOut), 10, 32)
	if majorVer < 4 {
		return fmt.Errorf("%s", "Windows PowerShell version 4.0 or higher is expected")
	}
	hasHyperV, _ := d.session.Output("function foo(){try{ $commands = Get-Command -Module Hyper-V;if($commands.Length -eq 0){return $false} }catch{return $false}; return $true} foo")
	if !powershell.IsTrue(hasHyperV) {
		return fmt.Errorf("%s", "PS Hyper-V module is not loaded. Make sure Hyper-V feature is on.")
	}

	return nil
}

func (d *HypervSSHDriver) runScript(script string, args ...interface{}) (string, error) {
	return d.session.Output(fmt.Sprintf(script, args...))
}

// Finds the MAC address of the NIC nic0
func (d *HypervSSHDriver) Mac(vmName string) (string, error) {
	return d.runScript(`function Get-Mac {
	param([string]$vmName, [int]$adapterIndex)
try {
  $adapter = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue
  $mac = $adapter[$adapterIndex].MacAddress
  if($mac -eq $null) {
    return ""
  }
} catch {
  return ""
}
return $mac
}; Get-Mac "%s" %d
`, vmName, 0)
}

// Finds the IP address of a VM connected that uses DHCP by its MAC address
func (d *HypervSSHDriver) IpAddress(macAddr string) (string, error) {
	return d.runScript(`function IpAddress {
param([string]$mac, [int]$addressIndex)
try {
  $ip = Get-Vm | %%{$_.NetworkAdapters} | ?{$_.MacAddress -eq $mac} | %%{$_.IpAddresses[$addressIndex]}
  if($ip -eq $null) {
    return ""
  }
} catch {
  return ""
}
return $ip
}; IpAddress "%s"`, macAddr)
}

// Finds the hostname for the ip address
func (d *HypervSSHDriver) GetHostName(ipAddr string) (string, error) {
	return d.runScript(`function HostName {
param([string]$ip)
try {
  $HostName = [System.Net.Dns]::GetHostEntry($ip).HostName
  if ($HostName -ne $null) {
    $HostName = $HostName.Split('.')[0]
  }
  return $HostName
} catch { }}; HostName "%s"`, ipAddr)
}

// Finds the IP address of a host adapter connected to switch
func (d *HypervSSHDriver) GetHostAdapterIpAddressForSwitch(switchName string) (string, error) {
	return d.runScript(`function GetHostAdapter {
param([string]$switchName, [int]$addressIndex)
$HostVMAdapter = Get-VMNetworkAdapter -ManagementOS -SwitchName $switchName
if ($HostVMAdapter){
    $HostNetAdapter = Get-NetAdapter | ?{ $_.DeviceID -eq $HostVMAdapter.DeviceId }
    if ($HostNetAdapter){
        $HostNetAdapterConfiguration =  @(get-wmiobject win32_networkadapterconfiguration -filter "IPEnabled = 'TRUE' AND InterfaceIndex=$($HostNetAdapter.ifIndex)")
        if ($HostNetAdapterConfiguration){
            return @($HostNetAdapterConfiguration.IpAddress)[$addressIndex]
        }
    }
}
return $false
	} GetHostAdapter "%s" %d`, switchName, 0)
}

// Type scan codes to virtual keyboard of vm
func (d *HypervSSHDriver) TypeScanCodes(vmName string, scanCodes string) error {
	return d.session.Run(fmt.Sprintf(`function TypeScanCodes {
		param([string]$vmName, [string]$scanCodes)
	#Requires -Version 3
	function Get-VMConsole
	{
	    [CmdletBinding()]
	    param (
	        [Parameter(Mandatory)]
	        [string] $VMName
	    )
	    $ErrorActionPreference = "Stop"
	    $vm = Get-CimInstance -Namespace "root\virtualization\v2" -ClassName Msvm_ComputerSystem -ErrorAction Ignore -Verbose:$false | where ElementName -eq $VMName | select -first 1
	    if ($vm -eq $null){
	        Write-Host ("VirtualMachine({0}) is not found!" -f $VMName)
	    }
	    $vmKeyboard = $vm | Get-CimAssociatedInstance -ResultClassName "Msvm_Keyboard" -ErrorAction Ignore -Verbose:$false
		if ($vmKeyboard -eq $null) {
			$vmKeyboard = Get-CimInstance -Namespace "root\virtualization\v2" -ClassName Msvm_Keyboard -ErrorAction Ignore -Verbose:$false | where SystemName -eq $vm.Name | select -first 1
		}
		if ($vmKeyboard -eq $null) {
			$vmKeyboard = Get-CimInstance -Namespace "root\virtualization" -ClassName Msvm_Keyboard -ErrorAction Ignore -Verbose:$false | where SystemName -eq $vm.Name | select -first 1
		}
	    if ($vmKeyboard -eq $null){
	        Write-Host ("VirtualMachine({0}) keyboard class is not found!" -f $VMName)
	    }
	    #TODO: It may be better using New-Module -AsCustomObject to return console object?
	    #Console object to return
	    $console = [pscustomobject] @{
	        Msvm_ComputerSystem = $vm
	        Msvm_Keyboard = $vmKeyboard
	    }
	    #Need to import assembly to use System.Windows.Input.Key
	    Add-Type -AssemblyName WindowsBase
	    #region Add Console Members
	    $console | Add-Member -MemberType ScriptMethod -Name TypeText -Value {
	        [OutputType([bool])]
	        param (
	            [ValidateNotNullOrEmpty()]
	            [Parameter(Mandatory)]
	            [string] $AsciiText
	        )
	        $result = $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "TypeText" -Arguments @{ asciiText = $AsciiText }
	        return (0 -eq $result.ReturnValue)
	    }
	    #Define method:TypeCtrlAltDel
	    $console | Add-Member -MemberType ScriptMethod -Name TypeCtrlAltDel -Value {
	        $result = $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "TypeCtrlAltDel"
	        return (0 -eq $result.ReturnValue)
	    }
	    #Define method:TypeKey
	    $console | Add-Member -MemberType ScriptMethod -Name TypeKey -Value {
	        [OutputType([bool])]
	        param (
	            [Parameter(Mandatory)]
	            [Windows.Input.Key] $Key,
	            [Windows.Input.ModifierKeys] $ModifierKey = [Windows.Input.ModifierKeys]::None
	        )
	        $keyCode = [Windows.Input.KeyInterop]::VirtualKeyFromKey($Key)
	        switch ($ModifierKey)
	        {
	            ([Windows.Input.ModifierKeys]::Control){ $modifierKeyCode = [Windows.Input.KeyInterop]::VirtualKeyFromKey([Windows.Input.Key]::LeftCtrl)}
	            ([Windows.Input.ModifierKeys]::Alt){ $modifierKeyCode = [Windows.Input.KeyInterop]::VirtualKeyFromKey([Windows.Input.Key]::LeftAlt)}
	            ([Windows.Input.ModifierKeys]::Shift){ $modifierKeyCode = [Windows.Input.KeyInterop]::VirtualKeyFromKey([Windows.Input.Key]::LeftShift)}
	            ([Windows.Input.ModifierKeys]::Windows){ $modifierKeyCode = [Windows.Input.KeyInterop]::VirtualKeyFromKey([Windows.Input.Key]::LWin)}
	        }
	        if ($ModifierKey -eq [Windows.Input.ModifierKeys]::None)
	        {
	            $result = $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "TypeKey" -Arguments @{ keyCode = $keyCode }
	        }
	        else
	        {
	            $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "PressKey" -Arguments @{ keyCode = $modifierKeyCode }
	            $result = $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "TypeKey" -Arguments @{ keyCode = $keyCode }
	            $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "ReleaseKey" -Arguments @{ keyCode = $modifierKeyCode }
	        }
	        $result = return (0 -eq $result.ReturnValue)
	    }
	    #Define method:Scancodes
	    $console | Add-Member -MemberType ScriptMethod -Name TypeScancodes -Value {
	        [OutputType([bool])]
	        param (
	            [Parameter(Mandatory)]
	            [byte[]] $ScanCodes
	        )
	        $result = $this.Msvm_Keyboard | Invoke-CimMethod -MethodName "TypeScancodes" -Arguments @{ ScanCodes = $ScanCodes }
	        return (0 -eq $result.ReturnValue)
	    }
	    #Define method:ExecCommand
	    $console | Add-Member -MemberType ScriptMethod -Name ExecCommand -Value {
	        param (
	            [Parameter(Mandatory)]
	            [string] $Command
	        )
	        if ([String]::IsNullOrEmpty($Command)){
	            return
	        }
	        $console.TypeText($Command) > $null
	        $console.TypeKey([Windows.Input.Key]::Enter) > $null
	        #sleep -Milliseconds 100
	    }
	    #Define method:Dispose
	    $console | Add-Member -MemberType ScriptMethod -Name Dispose -Value {
	        $this.Msvm_ComputerSystem.Dispose()
	        $this.Msvm_Keyboard.Dispose()
	    }
	    #endregion
	    return $console
	}
	$vmConsole = Get-VMConsole -VMName $vmName
	$scanCodesToSend = ''
	$scanCodes.Split(' ') | %%{
		$scanCode = $_
		if ($scanCode.StartsWith('wait')){
			$timeToWait = $scanCode.Substring(4)
			if (!$timeToWait){
				$timeToWait = "1"
			}
			if ($scanCodesToSend){
				$scanCodesToSendByteArray = [byte[]]@($scanCodesToSend.Split(' ') | %%{"0x$_"})
                $scanCodesToSendByteArray | %%{
				    $vmConsole.TypeScancodes($_)
                }
			}
			write-host "Special code <wait> found, will sleep $timeToWait second(s) at this point."
			Start-Sleep -s $timeToWait
			$scanCodesToSend = ''
		} else {
			if ($scanCodesToSend){
				write-host "Sending special code '$scanCodesToSend' '$scanCode'"
				$scanCodesToSend = "$scanCodesToSend $scanCode"
			} else {
				write-host "Sending char '$scanCode'"
				$scanCodesToSend = "$scanCode"
			}
		}
	}
	if ($scanCodesToSend){
		$scanCodesToSendByteArray = [byte[]]@($scanCodesToSend.Split(' ') | %%{"0x$_"})
        $scanCodesToSendByteArray | %%{
			$vmConsole.TypeScancodes($_)
        }
	} } TypeScanCodes "%s" "%s"`, vmName, scanCodes))

}

//Get the ip address for network adaptor
func (d *HypervSSHDriver) GetVirtualMachineNetworkAdapterAddress(vmName string) (string, error) {
	return d.runScript(`function GetVMNetworkAdapterAddr {
param([string]$vmName, [int]$addressIndex)
try {
  $adapter = Get-VMNetworkAdapter -VMName $vmName -ErrorAction SilentlyContinue
  $ip = $adapter.IPAddresses[$addressIndex]
  if($ip -eq $null) {
    return $false
  }
} catch {
  return $false
}
return $ip } "%s" %d`, vmName, 0)
}

//Set the vlan to use for switch
func (d *HypervSSHDriver) SetNetworkAdapterVlanId(switchName string, vlanId string) error {
	return d.session.Run(fmt.Sprintf(`function SetNetworkAdapterVlanId {
param([string]$networkAdapterName,[string]$vlanId)
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $networkAdapterName -Access -VlanId $vlanId
} SetNetworkAdapterVlanId "%s" "%s"`, switchName, vlanId))
}

//Set the vlan to use for machine
func (d *HypervSSHDriver) SetVirtualMachineVlanId(vmName string, vlanId string) error {
	return d.session.Run(fmt.Sprintf(`Set-VMNetworkAdapterVlan -VMName "%s" -Access -VlanId "%s"`, vmName, vlanId))
}

func (d *HypervSSHDriver) SetVmNetworkAdapterMacAddress(vmName string, macAddr string) error {
	return d.session.Run(fmt.Sprintf(`Set-VMNetworkAdapter "%s" -staticmacaddress "%s"`, vmName, macAddr))
}

func (d *HypervSSHDriver) UntagVirtualMachineNetworkAdapterVlan(vmName string, switchName string) error {
	return d.session.Run(fmt.Sprintf(`UntagVMNetAdapterVlan {
		param([string]$vmName,[string]$switchName)
Set-VMNetworkAdapterVlan -VMName $vmName -Untagged
Set-VMNetworkAdapterVlan -ManagementOS -VMNetworkAdapterName $switchName -Untagged
} UntagVMNetAdapterVlan "%s" "%s"`, vmName, switchName))
}

func (d *HypervSSHDriver) CreateExternalVirtualSwitch(vmName string, switchName string) error {
	return d.session.Run(fmt.Sprintf(`CreateExtVirtSwitch {
param([string]$vmName,[string]$switchName)
$switch = $null
$names = @('ethernet','wi-fi','lan')
$adapters = foreach ($name in $names) {
  Get-NetAdapter -Physical -Name $name -ErrorAction SilentlyContinue | where status -eq 'up'
}
foreach ($adapter in $adapters) {
  $switch = Get-VMSwitch -SwitchType External | where { $_.NetAdapterInterfaceDescription -eq $adapter.InterfaceDescription }
  if ($switch -eq $null) {
    $switch = New-VMSwitch -Name $switchName -NetAdapterName $adapter.Name -AllowManagementOS $true -Notes 'Parent OS, VMs, WiFi'
  }
  if ($switch -ne $null) {
    break
  }
}
if($switch -ne $null) {
  Get-VMNetworkAdapter -VMName $vmName | Connect-VMNetworkAdapter -VMSwitch $switch
} else {
  Write-Host 'No internet adapters found'
} } CreateExtVirtSwitch "%s" "%s"`, vmName, switchName))
}

func (d *HypervSSHDriver) GetVirtualMachineSwitchName(vmName string) (string, error) {
	return d.runScript(`(Get-VMNetworkAdapter -VMName "%s").SwitchName`, vmName)
}

func (d *HypervSSHDriver) ConnectVirtualMachineNetworkAdapterToSwitch(vmName string, switchName string) error {
	return d.session.Run(fmt.Sprintf(`ConnectVMNetToSwitch {
param([string]$vmName,[string]$switchName)
Get-VMNetworkAdapter -VMName $vmName | Connect-VMNetworkAdapter -SwitchName $switchName
	} ConnectVMNetToSwitch "%s" "%s"`, vmName, switchName))
}

func (d *HypervSSHDriver) CreateVirtualSwitch(switchName string, switchType string) (bool, error) {
	cmdOut, _ := d.runScript(`function CreateVSwitch {
param([string]$switchName,[string]$switchType)
$switches = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($switches.Count -eq 0) {
  New-VMSwitch -Name $switchName -SwitchType $switchType
  return $true
}
return $false } CreateVSwitch "%s" "%s"`, switchName, switchType)
	return strconv.ParseBool(cmdOut)
}

func (d *HypervSSHDriver) DeleteVirtualSwitch(switchName string) error {
	return d.session.Run(fmt.Sprintf(`function DeleteVSwitch {
param([string]$switchName)
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if ($switch -ne $null) {
    $switch | Remove-VMSwitch -Force -Confirm:$false
} }`, switchName))
}

func (d *HypervSSHDriver) CreateVirtualMachine(vmName string, path string, harddrivePath string, vhdRoot string, ram int64, diskSize int64, switchName string, generation uint, diffDisks bool) error {
	if generation == 2 {
		err := d.session.Run(fmt.Sprintf(`function CreateVMachine {
param([string]$vmName, [string]$path, [string]$harddrivePath, [string]$vhdRoot, [long]$memoryStartupBytes, [long]$newVHDSizeBytes, [string]$switchName, [int]$generation, [string]$diffDisks)
$vhdx = $vmName + '.vhdx'
$vhdPath = Join-Path -Path $vhdRoot -ChildPath $vhdx
if ($harddrivePath){
	if($diffDisks -eq "true"){
		New-VHD -Path $vhdPath -ParentPath $harddrivePath -Differencing
	} else {
		Copy-Item -Path $harddrivePath -Destination $vhdPath
	}
	New-VM -Name $vmName -Path $path -MemoryStartupBytes $memoryStartupBytes -VHDPath $vhdPath -SwitchName $switchName -Generation $generation
} else {
	New-VM -Name $vmName -Path $path -MemoryStartupBytes $memoryStartupBytes -NewVHDPath $vhdPath -NewVHDSizeBytes $newVHDSizeBytes -SwitchName $switchName -Generation $generation
} } CreateVMachine "%s" "%s" "%s" "%s" %d %d "%s" %d "%s"`, vmName, path, harddrivePath, vhdRoot, ram, diskSize, switchName, generation, strings.Title(strconv.FormatBool(diffDisks))))
		if err != nil {
			return err
		}

		return d.DisableAutomaticCheckpoints(vmName)
	} else {
		err := d.session.Run(fmt.Sprintf(`function CreateVMachine {
param([string]$vmName, [string]$path, [string]$harddrivePath, [string]$vhdRoot, [long]$memoryStartupBytes, [long]$newVHDSizeBytes, [string]$switchName, [string]$diffDisks)
$vhdx = $vmName + '.vhdx'
$vhdPath = Join-Path -Path $vhdRoot -ChildPath $vhdx
if ($harddrivePath){
	if($diffDisks -eq "true"){
		New-VHD -Path $vhdPath -ParentPath $harddrivePath -Differencing
	}
	else{
		Copy-Item -Path $harddrivePath -Destination $vhdPath
	}
	New-VM -Name $vmName -Path $path -MemoryStartupBytes $memoryStartupBytes -VHDPath $vhdPath -SwitchName $switchName
} else {
	New-VM -Name $vmName -Path $path -MemoryStartupBytes $memoryStartupBytes -NewVHDPath $vhdPath -NewVHDSizeBytes $newVHDSizeBytes -SwitchName $switchName
} } "%s" "%s" "%s" "%s" %d %d "%s" "%s"`, vmName, path, harddrivePath, vhdRoot, ram, diskSize, switchName, strconv.FormatBool(diffDisks)))
		if err != nil {
			return err
		}

		if err := d.DisableAutomaticCheckpoints(vmName); err != nil {
			return err
		}

		return d.DeleteAllDvdDrives(vmName)
	}
}

func (d *HypervSSHDriver) AddVirtualMachineHardDrive(vmName string, vhdRoot string, vhdName string, vhdSizeBytes int64, controllerType string) error {
	return d.session.Run(fmt.Sprintf(`function AddVMHD {
param([string]$vmName,[string]$vhdRoot, [string]$vhdName, [string]$vhdSizeInBytes, [string]$controllerType)
$vhdPath = Join-Path -Path $vhdRoot -ChildPath $vhdName
New-VHD $vhdPath -SizeBytes $vhdSizeInBytes
??? from here until ???END lines may have been inserted/deleted
Add-VMHardDiskDrive -VMName $vmName -path $vhdPath -controllerType $controllerType
	} AddVMHD "%s" "%s" "%s" %d %`, vmName, vhdRoot, vhdName, vhdSizeBytes, controllerType))

}

func (d *HypervSSHDriver) CloneVirtualMachine(fromPath string, fromName string, fromSnapshot string, cloneAllSnapshots bool, vmName string, path string, hdPath string, ram int64, switchName string) error {
	if fromName != "" {
		if err := d.ExportVmxcVirtualMachine(path, fromName, fromSnapshot, cloneAllSnapshots); err != nil {
			return err
		}
	}

	if fromPath != "" {
		if err := d.CopyVmxcVirtualMachine(path, fromPath); err != nil {
			return err
		}
	}

	if err := d.ImportVmxcVirtualMachine(path, vmName, hdPath, ram, switchName); err != nil {
		return err
	}

	return d.DeleteAllDvdDrives(vmName)
}

func (d *HypervSSHDriver) DeleteVirtualMachine(vmName string) error {
	return d.session.Run(fmt.Sprintf(`function DeleteVM {
param([string]$vmName)

$vm = Get-VM -Name $vmName
if (($vm.State -ne [Microsoft.HyperV.PowerShell.VMState]::Off) -and ($vm.State -ne [Microsoft.HyperV.PowerShell.VMState]::OffCritical)) {
    Stop-VM -VM $vm -TurnOff -Force -Confirm:$false
}

Remove-VM -Name $vmName -Force -Confirm:$false
	} DeleteVM "%s"`, vmName))
}

func (d *HypervSSHDriver) GetVirtualMachineGeneration(vmName string) (uint, error) {
	genStr, err := d.runScript(`function GetVMGen {
param([string]$vmName)
$generation = Get-Vm -Name $vmName | %%{$_.Generation}
if (!$generation){
    $generation = 1
}
return $generation
	} GetVMGen "%s"`, vmName)

	if err != nil {
		return 0, err
	}

	genUint32, err := strconv.ParseUint(strings.TrimSpace(genStr), 10, 32)

	if err != nil {
		return 0, err
	}

	return uint(genUint32), err

}

func (d *HypervSSHDriver) SetVirtualMachineCpuCount(vmName string, cpu uint) error {
	return d.session.Run(fmt.Sprintf(`function SetVMCpu {
param([string]$vmName, [int]$cpu)
Set-VMProcessor -VMName $vmName -Count $cpu } SetVMCpu "%s" %d`, vmName, cpu))
}

func (d *HypervSSHDriver) SetVirtualMachineMacSpoofing(vmName string, enableMacSpoofing bool) error {
	enableMacSpoofArg := "Off"
	if enableMacSpoofing {
		enableMacSpoofArg = "On"
	}
	return d.session.Run(fmt.Sprintf(`function SetVMMacSpoof {
param([string]$vmName, $enableMacSpoofing)
Set-VMNetworkAdapter -VMName $vmName -MacAddressSpoofing $enableMacSpoofing } SetVMMacSpoof "%s" "%s"`, vmName, enableMacSpoofArg))
}

func (d *HypervSSHDriver) SetVirtualMachineDynamicMemory(vmName string, enableDynamicMemory bool) error {
	return d.session.Run(fmt.Sprintf(`function SetVMDynMem {
param([string]$vmName, [string]$enableDynamicMemoryString)
$enableDynamicMemory = [System.Boolean]::Parse($enableDynamicMemoryString)
Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $enableDynamicMemory
	} SetVMDynMem "%s" "%s"`, vmName, strings.Title(strconv.FormatBool(enableDynamicMemory))))
}

func (d *HypervSSHDriver) SetVirtualMachineSecureBoot(vmName string, enable bool) error {
	secureBoot := "Off"
	if enable {
		secureBoot = "On"
	}
	return d.session.Run(fmt.Sprintf(`function SetVMSecureBoot {
	} SetVMSecureBoot "%s" "%s"`, vmName, secureBoot))
}

func (d *HypervSSHDriver) SetVirtualMachineVirtualizationExtensions(vmName string, enableVirtExt bool) error {
	return d.session.Run(fmt.Sprintf(`function SetVMVirtExt {
param([string]$vmName, [string]$exposeVirtualizationExtensionsString)
$exposeVirtualizationExtensions = [System.Boolean]::Parse($exposeVirtualizationExtensionsString)
Set-VMProcessor -VMName $vmName -ExposeVirtualizationExtensions $exposeVirtualizationExtensions
	} SetVMVirtExt "%s" "%s"`, vmName, strings.Title(strconv.FormatBool(enableVirtExt))))
}

func (d *HypervSSHDriver) EnableVirtualMachineIntegrationService(vmName string, integrationServiceName string) error {
	integrationServiceId := ""
	switch integrationServiceName {
	case "Time Synchronization":
		integrationServiceId = "2497F4DE-E9FA-4204-80E4-4B75C46419C0"
	case "Heartbeat":
		integrationServiceId = "84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47"
	case "Key-Value Pair Exchange":
		integrationServiceId = "2A34B1C2-FD73-4043-8A5B-DD2159BC743F"
	case "Shutdown":
		integrationServiceId = "9F8233AC-BE49-4C79-8EE3-E7E1985B2077"
	case "VSS":
		integrationServiceId = "5CED1297-4598-4915-A5FC-AD21BB4D02A4"
	case "Guest Service Interface":
		integrationServiceId = "6C09BB55-D683-4DA0-8931-C9BF705F6480"
	default:
		panic("unrecognized Integration Service Name")
	}

	return d.session.Run(fmt.Sprintf(`function EnableVMIntServ {
param([string]$vmName,[string]$integrationServiceId)
Get-VMIntegrationService -VmName $vmName | ?{$_.Id -match $integrationServiceId} | Enable-VMIntegrationService
	} EnableVMIntServ "%s" "%s"`, vmName, integrationServiceId))
}

func (d *HypervSSHDriver) ExportVirtualMachine(vmName string, path string) error {
	return d.session.Run(fmt.Sprintf(`function ExportVM {
param([string]$vmName, [string]$path)
Export-VM -Name $vmName -Path $path

if (Test-Path -Path ([IO.Path]::Combine($path, $vmName, 'Virtual Machines', '*.VMCX')))
{
  $vm = Get-VM -Name $vmName
  $vm_adapter = Get-VMNetworkAdapter -VM $vm | Select -First 1

  $config = [xml]@"
<?xml version="1.0" ?>
<configuration>
  <properties>
    <subtype type="integer">$($vm.Generation - 1)</subtype>
    <name type="string">$($vm.Name)</name>
  </properties>
  <settings>
    <processors>
      <count type="integer">$($vm.ProcessorCount)</count>
    </processors>
    <memory>
      <bank>
        <dynamic_memory_enabled type="bool">$($vm.DynamicMemoryEnabled)</dynamic_memory_enabled>
        <limit type="integer">$($vm.MemoryMaximum / 1MB)</limit>
        <reservation type="integer">$($vm.MemoryMinimum / 1MB)</reservation>
        <size type="integer">$($vm.MemoryStartup / 1MB)</size>
      </bank>
    </memory>
  </settings>
  <AltSwitchName type="string">$($vm_adapter.SwitchName)</AltSwitchName>
  <boot>
    <device0 type="string">Optical</device0>
  </boot>
  <secure_boot_enabled type="bool">False</secure_boot_enabled>
  <notes type="string">$($vm.Notes)</notes>
  <vm-controllers/>
</configuration>
"@

  if ($vm.Generation -eq 1)
  {
    $vm_controllers  = Get-VMIdeController -VM $vm
    $controller_type = $config.SelectSingleNode('/configuration/vm-controllers')
    # IDE controllers are not stored in a special XML container
  }
  else
  {
    $vm_controllers  = Get-VMScsiController -VM $vm
    $controller_type = $config.CreateElement('scsi')
    $controller_type.SetAttribute('ChannelInstanceGuid', 'x')
    # SCSI controllers are stored in the scsi XML container
    if ((Get-VMFirmware -VM $vm).SecureBoot -eq [Microsoft.HyperV.PowerShell.OnOffState]::On)
    {
      $config.configuration.secure_boot_enabled.'#text' = 'True'
    }
    else
    {
      $config.configuration.secure_boot_enabled.'#text' = 'False'
    }
  }

  $vm_controllers | ForEach {
    $controller = $config.CreateElement('controller' + $_.ControllerNumber)
    $_.Drives | ForEach {
      $drive = $config.CreateElement('drive' + ($_.DiskNumber + 0))
      $drive_path = $config.CreateElement('pathname')
      $drive_path.SetAttribute('type', 'string')
      $drive_path.AppendChild($config.CreateTextNode($_.Path))
      $drive_type = $config.CreateElement('type')
      $drive_type.SetAttribute('type', 'string')
      if ($_ -is [Microsoft.HyperV.PowerShell.HardDiskDrive])
      {
        $drive_type.AppendChild($config.CreateTextNode('VHD'))
      }
      elseif ($_ -is [Microsoft.HyperV.PowerShell.DvdDrive])
      {
        $drive_type.AppendChild($config.CreateTextNode('ISO'))
      }
      else
      {
        $drive_type.AppendChild($config.CreateTextNode('NONE'))
      }
      $drive.AppendChild($drive_path)
      $drive.AppendChild($drive_type)
      $controller.AppendChild($drive)
    }
    $controller_type.AppendChild($controller)
  }
  if ($controller_type.Name -ne 'vm-controllers')
  {
    $config.SelectSingleNode('/configuration/vm-controllers').AppendChild($controller_type)
  }

  $config.Save([IO.Path]::Combine($path, $vm.Name, 'Virtual Machines', 'box.xml'))
}
	} ExportVM "%s" "%s"`, vmName, path))
}

func (d *HypervSSHDriver) CompactDisks(expPath string, vhdDir string) error {
	return d.session.Run(fmt.Sprintf(`function CompactDisks {
param([string]$srcPath, [string]$vhdDirName)
Get-ChildItem "$srcPath/$vhdDirName" -Filter *.vhd* | %%{
    Optimize-VHD -Path $_.FullName -Mode Full
} } CompactDisks "%s" "%s"`, expPath, vhdDir))
}

func (d *HypervSSHDriver) CopyExportedVirtualMachine(expPath string, outputPath string, vhdDir string, vmDir string) error {
	return d.session.Run(fmt.Sprintf(`function CopyExpVM {
param([string]$srcPath, [string]$dstPath, [string]$vhdDirName, [string]$vmDir)
Move-Item -Path $srcPath/*.* -Destination $dstPath
Move-Item -Path $srcPath/$vhdDirName -Destination $dstPath
Move-Item -Path $srcPath/$vmDir -Destination $dstPath
	} CopyExpVM "%s" "%s" "%s" "%s"`, expPath, outputPath, vhdDir, vmDir))

}

func (d *HypervSSHDriver) RestartVirtualMachine(vmName string) error {
	return d.session.Run(fmt.Sprintf(`Restart-VM "%s" -Force -Confirm:$false`, vmName))
}

func (d *HypervSSHDriver) CreateDvdDrive(vmName string, isoPath string, generation uint) (uint, uint, error) {
	cmdOut, err := d.runScript(`function CreateDvdDrive {
param([string]$vmName, [string]$isoPath)
$dvdController = Add-VMDvdDrive -VMName $vmName -path $isoPath -Passthru
$dvdController | Set-VMDvdDrive -path $null
return "$($dvdController.ControllerNumber),$($dvdController.ControllerLocation)"
	} CreateDvdDrive "%s" "%s"`, vmName, isoPath)

	if err != nil {
		return 0, 0, err
	}

	cmdOutArray := strings.Split(cmdOut, ",")
	if len(cmdOutArray) != 2 {
		return 0, 0, errors.New("Did not return controller number and controller location")
	}

	controllerNumberTemp, err := strconv.ParseUint(strings.TrimSpace(cmdOutArray[0]), 10, 64)
	if err != nil {
		return 0, 0, err
	}
	controllerNumber := uint(controllerNumberTemp)

	controllerLocationTemp, err := strconv.ParseUint(strings.TrimSpace(cmdOutArray[1]), 10, 64)
	if err != nil {
		return controllerNumber, 0, err
	}
	controllerLocation := uint(controllerLocationTemp)

	return controllerNumber, controllerLocation, err
}

func (d *HypervSSHDriver) MountDvdDrive(vmName string, path string, controllerNumber uint, controllerLocation uint) error {
	return d.session.Run(fmt.Sprintf(`function MountDvd {
param([string]$vmName,[string]$path,[string]$controllerNumber,[string]$controllerLocation)
$vmDvdDrive = Get-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation
if (!$vmDvdDrive) {throw 'unable to find dvd drive'}
Set-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation -Path $path
} MountDvd "%s" "%s" %d %d`, vmName, path, controllerNumber, controllerLocation))
}

func (d *HypervSSHDriver) SetBootDvdDrive(vmName string, controllerNumber uint, controllerLocation uint, generation uint) error {
	if generation < 2 {
		return d.session.Run(fmt.Sprintf(`Set-VMBios -VMName "%s" -StartupOrder @("CD", "IDE","LegacyNetworkAdapter","Floppy")`, vmName))
	} else {
		return d.session.Run(fmt.Sprintf(`function SetBootDvd {
param([string]$vmName,[int]$controllerNumber,[int]$controllerLocation)
$vmDvdDrive = Get-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation
if (!$vmDvdDrive) {throw 'unable to find dvd drive'}
Set-VMFirmware -VMName $vmName -FirstBootDevice $vmDvdDrive -ErrorAction SilentlyContinue
} SetBootDvd "%s" %d %d`, vmName, controllerNumber, controllerLocation))
	}
}

func (d *HypervSSHDriver) UnmountDvdDrive(vmName string, controllerNumber uint, controllerLocation uint) error {
	return d.session.Run(fmt.Sprintf(`function UnmountDvd {
param([string]$vmName,[int]$controllerNumber,[int]$controllerLocation)
$vmDvdDrive = Get-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation
if (!$vmDvdDrive) {throw 'unable to find dvd drive'}
Set-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation -Path $null
	} UnmountDvd "%s" %d %d`, vmName, controllerNumber, controllerLocation))
}

func (d *HypervSSHDriver) DeleteDvdDrive(vmName string, controllerNumber uint, controllerLocation uint) error {
	return d.session.Run(fmt.Sprintf(`function DeleteDvd {
param([string]$vmName,[int]$controllerNumber,[int]$controllerLocation)
$vmDvdDrive = Get-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation
if (!$vmDvdDrive) {throw 'unable to find dvd drive'}
Remove-VMDvdDrive -VMName $vmName -ControllerNumber $controllerNumber -ControllerLocation $controllerLocation
	} DeleteDvd "%s" %d %d`, vmName, controllerNumber, controllerLocation))
}

func (d *HypervSSHDriver) MountFloppyDrive(vmName string, path string) error {
	return d.session.Run(fmt.Sprintf(`Set-VMFloppyDiskDrive -VMName "%s" -Path "%s"`, vmName, path))
}

func (d *HypervSSHDriver) UnmountFloppyDrive(vmName string) error {
	return d.session.Run(fmt.Sprintf(`Set-VMFloppyDiskDrive -VMName "%s" -Path $null`, vmName))
}

func (d *HypervSSHDriver) DisableAutomaticCheckpoints(vmName string) error {
	return d.session.Run(fmt.Sprintf(`function DisableAutomaticCheckpoints {
param([string]$vmName)
if ((Get-Command Set-Vm).Parameters["AutomaticCheckpointsEnabled"]) {
	Set-Vm -Name $vmName -AutomaticCheckpointsEnabled $false }
	} DisableAutomaticCheckpoints "%s"`, vmName))
}

func (d *HypervSSHDriver) DeleteAllDvdDrives(vmName string) error {
	return d.session.Run(fmt.Sprintf(`Get-VMDvdDrive -VMName "%s" | Remove-VMDvdDrive`, vmName))
}

func (d *HypervSSHDriver) ExportVmxcVirtualMachine(exportPath string, vmName string, snapshotName string, allSnapshots bool) error {
	return d.session.Run(fmt.Sprintf(`function ExportVmxcVM {
param([string]$exportPath, [string]$vmName, [string]$snapshotName, [string]$allSnapshotsString)

$WorkingPath = Join-Path $exportPath $vmName

if (Test-Path $WorkingPath) {
	throw "Export path working directory: $WorkingPath already exists!"
}

$allSnapshots = [System.Boolean]::Parse($allSnapshotsString)

if ($snapshotName) {
    $snapshot = Get-VMSnapshot -VMName $vmName -Name $snapshotName
    Export-VMSnapshot -VMSnapshot $snapshot -Path $exportPath -ErrorAction Stop
} else {
    if (!$allSnapshots) {
        #Use last snapshot if one was not specified
        $snapshot = Get-VMSnapshot -VMName $vmName | Select -Last 1
    } else {
        $snapshot = $null
    }

    if (!$snapshot) {
        #No snapshot clone
        Export-VM -Name $vmName -Path $exportPath -ErrorAction Stop
    } else {
        #Snapshot clone
        Export-VMSnapshot -VMSnapshot $snapshot -Path $exportPath -ErrorAction Stop
    }
}

$result = Get-ChildItem -Path $WorkingPath | Move-Item -Destination $exportPath -Force
$result = Remove-Item -Path $WorkingPath
return $result } ExportVmxcVM "%s" "%s" "%s" "%s"`, exportPath, vmName, snapshotName, strings.Title(strconv.FormatBool(allSnapshots))))
}

func (d *HypervSSHDriver) CopyVmxcVirtualMachine(exportPath string, cloneFromPath string) error {
	return d.session.Run(fmt.Sprintf(`function CopyVmxcVM {
param([string]$exportPath, [string]$cloneFromVmxcPath)
if (!(Test-Path $cloneFromVmxcPath)){
	throw "Clone from vmxc directory: $cloneFromVmxcPath does not exist!"
}

if (!(Test-Path $exportPath)){
	New-Item -ItemType Directory -Force -Path $exportPath
}
$cloneFromVmxcPath = Join-Path $cloneFromVmxcPath '\*'
Copy-Item $cloneFromVmxcPath $exportPath -Recurse -Force
	} CopyVmxcVM "%s" "%s"`, exportPath, cloneFromPath))
}

func (d *HypervSSHDriver) ImportVmxcVirtualMachine(importPath string, vmName string, harddrivePath string, ram int64, switchName string) error {
	return d.session.Run(fmt.Sprintf(`function ImportVmxcVM {
param([string]$importPath, [string]$vmName, [string]$harddrivePath, [long]$memoryStartupBytes, [string]$switchName)

$VirtualHarddisksPath = Join-Path -Path $importPath -ChildPath 'Virtual Hard Disks'
if (!(Test-Path $VirtualHarddisksPath)) {
	New-Item -ItemType Directory -Force -Path $VirtualHarddisksPath
}

$vhdPath = ""
if ($harddrivePath){
	$vhdx = $vmName + '.vhdx'
	$vhdPath = Join-Path -Path $VirtualHarddisksPath -ChildPath $vhdx
}

$VirtualMachinesPath = Join-Path $importPath 'Virtual Machines'
if (!(Test-Path $VirtualMachinesPath)) {
	New-Item -ItemType Directory -Force -Path $VirtualMachinesPath
}

$VirtualMachinePath = Get-ChildItem -Path $VirtualMachinesPath -Filter *.vmcx -Recurse -ErrorAction SilentlyContinue | select -First 1 | %%{$_.FullName}
if (!$VirtualMachinePath){
    $VirtualMachinePath = Get-ChildItem -Path $VirtualMachinesPath -Filter *.xml -Recurse -ErrorAction SilentlyContinue | select -First 1 | %%{$_.FullName}
}
if (!$VirtualMachinePath){
    $VirtualMachinePath = Get-ChildItem -Path $importPath -Filter *.xml -Recurse -ErrorAction SilentlyContinue | select -First 1 | %%{$_.FullName}
}

$compatibilityReport = Compare-VM -Path $VirtualMachinePath -VirtualMachinePath $importPath -SmartPagingFilePath $importPath -SnapshotFilePath $importPath -VhdDestinationPath $VirtualHarddisksPath -GenerateNewId -Copy:$false
if ($vhdPath){
	Copy-Item -Path $harddrivePath -Destination $vhdPath
	$existingFirstHarddrive = $compatibilityReport.VM.HardDrives | Select -First 1
	if ($existingFirstHarddrive) {
		$existingFirstHarddrive | Set-VMHardDiskDrive -Path $vhdPath
	} else {
		Add-VMHardDiskDrive -VM $compatibilityReport.VM -Path $vhdPath
	}
}
Set-VMMemory -VM $compatibilityReport.VM -StartupBytes $memoryStartupBytes
$networkAdaptor = $compatibilityReport.VM.NetworkAdapters | Select -First 1
Disconnect-VMNetworkAdapter -VMNetworkAdapter $networkAdaptor
Connect-VMNetworkAdapter -VMNetworkAdapter $networkAdaptor -SwitchName $switchName
$vm = Import-VM -CompatibilityReport $compatibilityReport

if ($vm) {
    $result = Rename-VM -VM $vm -NewName $VMName
}
return $result } ImportVmxcVM "%s" "%s" "%s" %d "%s"`, importPath, vmName, harddrivePath, ram, switchName))
}
