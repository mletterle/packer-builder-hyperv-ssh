package main

import (
	"github.com/hashicorp/packer/packer/plugin"
	"github.com/mletterle/packer-builder-hyperv-ssh/hyperv/ssh"
)

func main() {
	server, err := plugin.Server()
	if err != nil {
		panic(err)
	}
	server.RegisterBuilder(new(ssh.Builder))
	server.Serve()
}
