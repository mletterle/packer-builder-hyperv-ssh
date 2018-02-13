# Packer Plugin for Hyper-V over SSH

## Quick Setup

On HyperV Server Run:

`choco install -y openssh -params "/SSHServerFeature /PathSpecsToProbeForShellEXEString:$env:WINDIR\system32\windowspowershell\v1.0\powershell.exe"`

In your packer template add:

`hyperv_server`: hostname of the server running hyper-v

`hyperv_username`: username to authenticate to the server as

`hyperv_password`: password for the user authenticating

## Notes

Currently only supports iso builds, EVERYTHING is relative to the server

Very rough at the moment and suited to my personal needs, but updates coming.

## Thanks

To the writers of the packer built-in hyperv plugin, of which much of this is based off of


