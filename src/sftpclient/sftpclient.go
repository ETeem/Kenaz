package sftpclient 

import (
	"golang.org/x/crypto/ssh"
	"github.com/pkg/sftp"
	"io/ioutil"
	"os"
	"time"
)


func CopyFile(srcfile string, host string, dstfile string, timeout int, key ssh.Signer) (string, error) {

//	cuser, err := user.Current()
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
	defer client.Close()


	sftp, err := sftp.NewClient(client)
	if err != nil {
		return "Failed to dial: " + err.Error(), err
	}
	defer sftp.Close()
	

	srcFile, err := os.Open(srcfile)
	if err != nil {
		return "Failed To Open Source File: " + err.Error(), err
	}
	defer srcFile.Close()



	dstFile, err := sftp.Create(dstfile)
	if err != nil {
		return "Failed To Create Destination File: " + err.Error(), err
	}
	defer dstFile.Close()

	buf := make([]byte, 1)//024) 
	for {
		n, _ := srcFile.Read(buf)
		if n == 0 {
			break
		}

		dstFile.Write(buf)
	}

	sftp.Chmod(dstfile, 0755)

	return "", nil
}

func GetKeyFile(encfile string) (key ssh.Signer, err error) {

	file := "/root/.ssh/" + encfile //id_rsa"
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
