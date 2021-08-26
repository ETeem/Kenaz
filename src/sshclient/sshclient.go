package sshclient 

import (
	"bytes"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"time"
)


func RunOneCommand(host string, command string, timeout int, key ssh.Signer) (string, error) {

	cuser := "root" 
	config := &ssh.ClientConfig{
		User:            cuser,
		Timeout:         time.Duration(timeout) * time.Second,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host+":22", config)

	if err != nil {
		return "Failed to dial: " + err.Error(), err
	}

	session, err := client.NewSession()
	if err != nil {
		return "Failed to create session", err
	}
	defer session.Close()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	if err = session.Run(command); err != nil {
		return stderrBuf.String(), err 
	}

	return stdoutBuf.String(), nil
}

func GetKeyFile(encfile string) (key ssh.Signer, err error) {

//	file := "/root/.ssh/" + encfile //id_rsa"
	file := encfile 
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return
	}

	return
}
