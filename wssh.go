package wssh

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"

	"github.com/davecgh/go-spew/spew"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// MakeConfig Comment
type MakeConfig struct {
	User     string
	Server   string
	Key      string
	Port     string
	Password string
}

func (ssh_conf *MakeConfig) connect() (*ssh.Session, error) {
	// auths holds the detected ssh auth methods
	auths := []ssh.AuthMethod{}

	// figure out what auths are requested, what is supported
	if ssh_conf.Password != "" {
		auths = append(auths, ssh.Password(ssh_conf.Password))
	}

	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
		defer sshAgent.Close()
	}

	if pubkey, err := getKeyFile(ssh_conf.Key); err == nil {
		auths = append(auths, ssh.PublicKeys(pubkey))
	}

	config := &ssh.ClientConfig{
		User: ssh_conf.User,
		Auth: auths,
	}

	client, err := ssh.Dial("tcp", ssh_conf.Server+":"+ssh_conf.Port, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session, nil
}

func getKeyFile(keypath string) (ssh.Signer, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	file := usr.HomeDir + keypath
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	pubkey, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

func (ssh_conf *MakeConfig) Run(command string) (outStr string, err error) {
	outChan, doneChan, err := ssh_conf.Stream(command)
	if err != nil {
		return outStr, err
	}
	// read from the output channel until the done signal is passed
	stillGoing := true
	for stillGoing {
		select {
		case <-doneChan:
			stillGoing = false
		case line := <-outChan:
			outStr += line + "\n"
		}
	}
	// return the concatenation of all signals from the output channel
	return outStr, err
}

// -------------------------------

func (ssh_conf *MakeConfig) StreamToFile(command string, target string) {
	// connect to remote host
	session, err := ssh_conf.connect()
	if err != nil {
		fmt.Println(err)
	}

	// open the out file for writing
	outfile, err := os.Create(target)
	if err != nil {
		panic(err)
	}

	defer outfile.Close()
	session.Stdout = outfile

	err = session.Start(command)
	if err != nil {
		panic(err)
	}

	session.Wait()
	defer session.Close()
	spew.Dump(session)
}

// -------------------------------

func (ssh_conf *MakeConfig) Stream(command string) (output chan string, done chan bool, err error) {
	// connect to remote host
	session, err := ssh_conf.connect()
	if err != nil {
		return output, done, err
	}
	// connect to both outputs (they are of type io.Reader)
	outReader, err := session.StdoutPipe()
	if err != nil {
		return output, done, err
	}
	errReader, err := session.StderrPipe()
	if err != nil {
		return output, done, err
	}
	// combine outputs, create a line-by-line scanner
	outputReader := io.MultiReader(outReader, errReader)
	err = session.Start(command)
	scanner := bufio.NewScanner(outputReader)
	// continuously send the command's output over the channel
	outputChan := make(chan string)
	done = make(chan bool)
	go func(scanner *bufio.Scanner, out chan string, done chan bool) {
		defer close(outputChan)
		defer close(done)
		for scanner.Scan() {
			outputChan <- scanner.Text()
		}
		// close all of our open resources
		done <- true
		session.Close()
	}(scanner, outputChan, done)
	return outputChan, done, err
}
