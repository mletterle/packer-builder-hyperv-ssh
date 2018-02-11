package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type PowershellSession struct {
	client *gossh.Client
}


func Connect(address string, username string, password string) *PowershellSession {
	hostKey, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if(err != nil) {
		panic(err)
	}
	config := &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.Password(password),
		},
		HostKeyCallback: hostKey,
	}
	fmt.Println("Connecting to %s", address)
	client, err := gossh.Dial("tcp", fmt.Sprintf("%s:22", address), config)
	if err != nil {
		panic(fmt.Sprintf("Failed to dial: ", err))
	}

	ps := new(PowershellSession)
	ps.client = client
	return ps
}


func (ps *PowershellSession) Output(script string) (string, error) {
	session, err := ps.client.NewSession()
	if err != nil {
		panic(err)
	}
	output, err := session.Output(script)
	if err != nil {
		panic(err)
	}
	str := string(output[:])
	return str, err
}

