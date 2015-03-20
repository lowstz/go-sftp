package main

import (
	"bufio"
	"github.com/magicshui/goutils/files"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
)

const (
	sshhost = "192.168.102.2:22"
	sshuser = "root"
	keyfile = "./id_rsa.unsafe"
)

func main() {
	fileList, err := GetSFTPAllFilesName("/var/log", sshhost, sshuser, keyfile)
	if err != nil {
		log.Fatalln(err)
	}
	for _, v := range fileList {
		log.Println(v)
	}

	contents, err := ReadSFTPFileToString("/var/log/syslog", sshhost, sshuser, keyfile)
	if err != nil {
		log.Fatalln(err)
	}
	for _, v := range contents {
		log.Println(v)
	}
}

func GetSFTPClient(domain string, user string, keyPath string) (*sftp.Client, error) {
	key, err := getKeyFromFile(keyPath)
	if err != nil {
		return nil, err
	}
	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
	}
	ssh_client, err := ssh.Dial("tcp", domain, clientConfig)
	if err != nil {
		log.Println("ssh create client: ", err)
		return nil, err
	}

	client, err := sftp.NewClient(ssh_client)
	if err != nil {
		log.Println("sftp create client: ", err)
		return nil, err
	}
	return client, nil
}

func GetSFTPAllFilesName(path string, domain string, user string, keyPath string) ([]string, error) {
	client, err := GetSFTPClient(domain, user, keyPath)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var results []string
	walker := client.Walk(path)
	for walker.Step() {
		if err := walker.Err(); err != nil {
			continue
		}
		results = append(results, walker.Path())
	}
	return results, nil
}
func ReadSFTPFile(path string, domain string, user string, keyPath string) (*sftp.File, error) {
	client, err := GetSFTPClient(domain, user, keyPath)
	if err != nil {
		return nil, err
	}

	sftpFile, err := client.Open(path)
	if err != nil {
		return nil, err
	}

	return sftpFile, err

}

func SaveSFTPFilesToLocal(sftpPath string, localPath string, domain string, user string, keyPath string) (bool, error) {
	sftpFile, err := ReadSFTPFile(sftpPath, domain, user, keyPath)
	if err != nil {
		return false, err
	}
	defer sftpFile.Close()

	localFile, err := os.Create(localPath)
	if err != nil {
		return false, err
	}

	buf := make([]byte, 1024)
	for {
		// read a chunk
		n, err := sftpFile.Read(buf)
		if err != nil && err != io.EOF {
			return false, err
		}
		if n == 0 {
			break
		}

		// write a chunk
		if _, err := localFile.Write(buf[:n]); err != nil {
			return false, err
		}
	}
	defer localFile.Close()
	return true, nil
}

func ReadSFTPFileToString(path string, domain string, user string, keyPath string) ([]string, error) {
	sftpFile, err := ReadSFTPFile(path, domain, user, keyPath)
	if err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(sftpFile)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	defer sftpFile.Close()
	return lines, scanner.Err()
}

func LeaveSFTPAFile(path string, content string, domain string, user string, keyPath string) error {
	client, err := GetSFTPClient(domain, user, keyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	f, err := client.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(content)); err != nil {
		return err
	}
	defer f.Close()
	return nil
}
func LeaveSFTPAFileWithByte(path string, content []byte, domain string, user string, keyPath string) error {
	client, err := GetSFTPClient(domain, user, keyPath)
	if err != nil {
		return err
	}
	defer client.Close()

	f, err := client.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		return err
	}
	defer f.Close()
	return nil
}

func getKeyFromFile(path string) (ssh.Signer, error) {
	file := files.AbsPath(path)
	log.Println(file)
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		log.Println("io read error: ", err)
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buf)
	//	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		log.Println("parse private key error: ", err)
		return nil, err
	}
	return key, nil
}
