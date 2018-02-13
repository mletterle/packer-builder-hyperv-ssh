package ssh

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"log"
	"os"
	"path/filepath"
	"unicode/utf16"
)

type PowershellSession struct {
	client *gossh.Client
}

func Connect(address string, username string, password string) *PowershellSession {
	hostKey, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		panic(err)
	}
	config := &gossh.ClientConfig{
		User: username,
		Auth: []gossh.AuthMethod{
			gossh.Password(password),
		},
		HostKeyCallback: hostKey,
	}
	log.Printf("Connecting to %s", address)
	client, err := gossh.Dial("tcp", fmt.Sprintf("%s:22", address), config)
	if err != nil {
		panic(fmt.Sprintf("Failed to dial: ", err))
	}

	ps := new(PowershellSession)
	ps.client = client
	return ps
}

func (ps *PowershellSession) Disconnect() {
	ps.client.Close()
}

func (ps *PowershellSession) Run(script string) error {
	_, err := ps.Output(script)
	return err
}

func (ps *PowershellSession) Output(script string) (string, error) {
	log.Printf("ps-script: %s", script)
	session, err := ps.client.NewSession()
	if err != nil {
		panic(err)
	}
	output, err := session.Output(encodedCommand(script))
	str := string(output[:])
	log.Printf("ps-output: %s", str)
	defer session.Close()
	return str, err
}

func encodedCommand(script string) string {
	wrappedScript := fmt.Sprintf(`function RunScript {
		[CmdletBinding()]
		param()
		%s
	} RunScript -ErrorAction Stop `, script)
	return fmt.Sprintf(`powershell -encodedcommand %s`, base64Utf16Encode(wrappedScript))
}

func base64Utf16Encode(str string) string {
	return base64.StdEncoding.EncodeToString(toByteSlice(utf16.Encode([]rune(str))))
}

func toByteSlice(vals []uint16) []byte {
	buf := make([]byte, len(vals)*2)
	for i, v := range vals {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(v))
	}
	return buf
}

func toUint16Slice(buf []byte) []uint16 {
	if len(buf)%2 != 0 {
		return nil
	}
	vals := make([]uint16, len(buf)/2)
	for i := 0; i < len(vals); i++ {
		val := binary.LittleEndian.Uint16(buf[i*2:])
		vals[i] = uint16(val)
	}
	return vals
}
