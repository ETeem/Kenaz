package main

import(
	"os"
	"fmt"
	"bytes"
	"errors"
	"strings"
	"sshclient"
	"time"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"crypto/tls"
	"encoding/xml"
	"encoding/json"
	"math/rand"
	"gopkg.in/yaml.v2"
	"github.com/hashicorp/vault/api"
)

type VirtualMachineCollection struct { 
	VirtualMachines []struct { 
		DisplayName string `xml:"displayName"`
		Name string `xml:"name"`
		DNSName string `xml:"dnsName"`
	} `xml:"VirtualMachines"`
} 

type VaultStatus struct {
	Type        string `json:"type"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Nonce       string `json:"nonce"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	ClusterID   string `json:"cluster_id"`
}

type HostPassData struct {
	Username string
	Password string
	Hostname string
}

type Config struct {
	VaultAddress string `yaml:"vault_address"`
	VaultToken string `yaml:"vault_token"`
	AccessMethod string `yaml:"serverlist_access_method"`
	Path string `yaml:"serverlist_path"`
	Username string `yaml:"serverlist_username"`
	Password string `yaml:"serverlist_password"`
	SSHKeyFile string `yaml:"ssh_key_file_path"`
	UserToChange string `yaml:"user_to_change"`
	LogFileLocation string `yaml:"log_file_location"`
	SMTPServer string `yaml:"smtp_server"`
	EmailAddress string `yaml:"email_address"`
	FromAddress string `yaml:"from_address"`
	UseLogFile bool `yaml:"use_log_file"`
}

var cfg Config
var vaultfailed map[string]string

func RandomString(length int) string {
//	var list = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~")

	rand.Seed(time.Now().UnixNano())

	var list = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*")

	chars := make([]rune, length)
	for i := range chars {
		chars[i] = list[rand.Intn(len(list))]
	}

	return string(chars)
}

func ChangePassword(user string, host string, length int) (string, error) {

	npassword := RandomString(length)
	keyrsa, _ := sshclient.GetKeyFile(cfg.SSHKeyFile)
	output, err := sshclient.RunOneCommand(host, "usermod --password `perl -e \"print crypt('" + npassword + "','sa');\"` " + user, 5, keyrsa)
	if err != nil {
		return "", err
	}

	if output != "" {
		return "", errors.New(output)
	}

	return npassword, nil
}

func GetVMList() []string {
	var vmlist []string

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("GET", cfg.Path, nil)
	if err != nil {
		Log("Couldn't Get Serverlist: " + err.Error())
		fmt.Println(err.Error())
	}
	req.SetBasicAuth(cfg.Username, cfg.Password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Log("Couldn't Make Vcommander Call: " + err.Error())
		fmt.Println(err.Error())
	}
	defer resp.Body.Close()

	ret, _ := ioutil.ReadAll(resp.Body)

	doc := VirtualMachineCollection{}
	xml.Unmarshal(ret, &doc)

	for _, vm := range doc.VirtualMachines {
		if strings.Contains(vm.DisplayName, "u-") {
			if vm.DNSName == "" || vm.DNSName == "localhost.localdomain" || strings.Contains(vm.DNSName, "template") {
				if strings.Contains(vm.DisplayName, "<") || strings.Contains(vm.DisplayName, ">") {
					vm.DisplayName = strings.Replace(vm.DisplayName, "<", "", -1)
					vm.DisplayName = strings.Replace(vm.DisplayName, ">", "", -1)
				}

				vmlist = append(vmlist, vm.DisplayName)
			} else {
				if strings.Contains(vm.DNSName, "<") || strings.Contains(vm.DNSName, ">") {
					vm.DNSName = strings.Replace(vm.DNSName, "<", "", -1)
					vm.DNSName = strings.Replace(vm.DNSName, ">", "", -1)
				}

				vmlist = append(vmlist, vm.DNSName)
			}
		}
	}

	return vmlist
}

func GetListFromURL(url string) []string {
	var vmlist []string

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("GET", cfg.Path, nil)
	if err != nil {
		Log("Couldn't get server list: " + err.Error())
		fmt.Println(err.Error())
	}

	if cfg.Username != "" {
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer resp.Body.Close()

	ret, _ := ioutil.ReadAll(resp.Body)
	parts := strings.Split(string(ret), "\n")
	for _, vm := range parts {
		vmlist = append(vmlist, vm)
	}

	return vmlist
}

func GetListFromFile(path string) []string {
	var vmlist []string

	if _, err := os.Stat(path); os.IsNotExist(err) {
		Log("Couldn't get server list: " + err.Error())
		fmt.Println("Couldn't File File (" + path + "): " + err.Error())
		return vmlist
	}

        b, err := ioutil.ReadFile(path)
        if err != nil {
		Log("Couldn't Read server list: " + err.Error())
                fmt.Println("Error Reading File " + path + ": " + err.Error())
                return vmlist
        }

	parts := strings.Split(string(b), "\n")
	for _, vm := range parts {
		vmlist = append(vmlist, vm)
	}

	return vmlist
}

func WriteToVault(hlist []HostPassData) error {
	client, err := api.NewClient(&api.Config{
		Address: cfg.VaultAddress,
	})

	client.SetToken(cfg.VaultToken)


	for _, host := range hlist { 
		secretData := map[string]interface{} {
			"host": host.Hostname, 
			"user": host.Username,
			"pass": host.Password, 
		}

		_, err = client.Logical().Write("secret/hosts/" + host.Hostname, secretData)
		if err != nil {
			vaultfailed[host.Hostname] = host.Password
			Log("Failed To Write New Password (" + host.Password + ") To Vault: " + err.Error()) 
			return err
		}
	}

	return nil
}

func Log(message string) error {

	if cfg.UseLogFile == false {
		return nil
	}

	file, err := os.OpenFile(cfg.LogFileLocation, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("failed to open log file: " + err.Error())
		return err
	}
	defer file.Close()

        current_time := time.Now().Local()
        t := current_time.Format("Jan 02 2006 03:04:05")
	_, err = file.WriteString(t + " - Kenaz: " + message + "\n")

	if err != nil {
		fmt.Println("failed to write to log file: " + err.Error())
		return err
	}

	return nil
}

func CheckVaultStatus() bool {
	addr := cfg.VaultAddress + "/v1/sys/seal-status"

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		Log("Couldn't Check Vault Status: " + err.Error())
		fmt.Println(err.Error())
		return false
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		Log("Couldn't Execute HTTP Request: " + err.Error())
		fmt.Println(err.Error())
		return false
	}
	defer resp.Body.Close()

	ret, _ := ioutil.ReadAll(resp.Body)

	vs := VaultStatus{}
	json.Unmarshal(ret, &vs)

	if vs.Sealed == true {
		return false
	}

	return true
}

func SendSMTPMessage(mailserver string, from string, to string, subject string, body string) error {
        connection, err := smtp.Dial(mailserver)
        if err != nil {
                return err
        }
        defer connection.Close()

        connection.Mail(from)
        connection.Rcpt(to)

        wc, err := connection.Data()
        if err != nil {
                return err
        }
        defer wc.Close()

        body = "To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\n\r\n" + body

        buf := bytes.NewBufferString(body)
        _, err = buf.WriteTo(wc)
        if err != nil {
                return err
        }

        return nil
}

func main() {

	var failed map[string]string
	failed = make(map[string]string)
	vaultfailed = make(map[string]string)

	hpd := []HostPassData{}

	configpath := "/etc/kenaz.yaml"
	if _, err := os.Stat(configpath); os.IsNotExist(err) {
		configpath = "./kenaz.yaml"
	}

	b, err := ioutil.ReadFile(configpath)
	if err != nil {
		fmt.Println("Error Opening File " + configpath + ": " + err.Error())
		return
	}

	yml := string(b)
	err = yaml.Unmarshal([]byte(yml), &cfg)

	if err != nil {
		fmt.Println("Couldn't Parse YAML File " + configpath + ": " + err.Error())
		return
	}

	retval := CheckVaultStatus()
	if retval == false {
		SendSMTPMessage(cfg.SMTPServer, cfg.FromAddress, cfg.EmailAddress, "Not Changing Passwords", "The Vault Is Sealed Or Unresponsive!")
		Log("Vault Is Sealed.  Not Proceeding")
		fmt.Println("Vault Is Sealed")
		return
	}

	Log("Starting Kenaz")
	vmlist := []string{}

	switch cfg.AccessMethod {
	case "vcommander":
		Log("Using Vcommander")
		vmlist = GetVMList()
	case "url":
		Log("Using URL")
		vmlist = GetListFromURL(cfg.Path)
	case "file":
		Log("Using File")
		vmlist = GetListFromFile(cfg.Path)
	default:
		vmlist = nil
		vmlist = append(vmlist, "tu-autotest-01")
	}

	Log("Looping Through All Hosts In The List")
	for _, vm := range vmlist {

		passwd, err := ChangePassword(cfg.UserToChange, vm, 8) 
		if err != nil {
			Log("Failed to change password for " + vm + ": " + err.Error())
			failed[vm] = err.Error()
			continue	
		}

		Log("Changed Password For: " + vm)
		tmphpd := HostPassData{}
		tmphpd.Username = cfg.UserToChange
		tmphpd.Password = passwd
		tmphpd.Hostname = vm

		hpd = append(hpd, tmphpd)
	}

	err = WriteToVault(hpd)
	if err != nil {
		fmt.Println("Error writing to vault: " + err.Error())
		return
	}

	body := ""
	if len(vaultfailed) > 0 {
		body += "Passwords Changed But Were Not Recorded To Vault:\n\n"
		for host, pass := range vaultfailed {
			body += host + ": " + pass + "\n"
		}
		body += "\n"
	}

	if len(failed) > 0 { 
		body += "List Of Servers That Failed Password Change:\n\n"
		for host, errmsg := range failed {
			body += host + ": " + errmsg + "\n"
		}
		body += "\n"
	}

	if len(failed) > 0 || len(vaultfailed) > 0 {
		SendSMTPMessage(cfg.SMTPServer, cfg.FromAddress, cfg.EmailAddress, "Password Change Failed", body)
	}

	Log("Complete")
	fmt.Println("Success!")
}

