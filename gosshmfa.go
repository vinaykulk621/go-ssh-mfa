package gosshmfa

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// user should provide all these details to make the ssh connection
type SSHConfig struct {
	User       string // username through which ssh connection is made
	Protocol   string // takes one of the two values "tcp" or "udp"
	RemoteAddr string // IP address or machine/server name(FQDN)
	Port       int    // port to which ssh connection should be made
}

// SSH client
//
// to start the first connection this is used
type client struct {
	sshClient *ssh.Client // ssh session client
}

// SSH session
//
// sshClient is used to make new sessions from this package when
// running multiple commands at the same time based on the
// same client that was used to create the first session.
type session struct {
	sshSession *ssh.Session // ssh session client
	sshClient  *ssh.Client  // ssh client
}

// creates a new client of type client
func newClient(sshClient *ssh.Client) *client {
	return &client{
		sshClient: sshClient,
	}
}

// creates a new session for client of type session
func newSession(sshClient *ssh.Client, sshSession *ssh.Session) *session {
	return &session{
		sshClient:  sshClient,
		sshSession: sshSession,
	}
}

// close the SSH client
func (conn *client) Close() error {
	err := conn.sshClient.Close()
	return err
}

// creates a new ssh session from scratch
func (conn *client) MakeNewSession() (*session, error) {
	session, err := conn.sshClient.NewSession()
	if err != nil {
		return nil, err
	}
	newSession := newSession(conn.sshClient, session)
	return newSession, err
}

// creates a new ssh session from an existing client.
// Used when multiple commands is to be run at once or
// dynamic number of sessions is to be created
func (conn *session) makeNewSessionFromExistingSession() (*session, error) {
	session, err := conn.sshClient.NewSession()
	if err != nil {
		return nil, err
	}
	newSession := newSession(conn.sshClient, session)
	return newSession, err
}

// runs a single command and returns output as
//
//	stdOutput, stdError
//
// there might be delay between execution of the command and
// getting the output depending on the latency and output length,
// checkout RunCmds if you want to run multiple commands at once
//
// Note: this only works on linux based servers/machines which has
// /bin/bash enabled as the command is run something like this:
//
//	/bin/bash; <yourCmd>; exit
func (conn *session) Run(cmd string) (*bytes.Buffer, *bytes.Buffer) {
	defer conn.sshSession.Close()

	// appending exit to the command so that the program
	// knows that the command execution is complete,
	// else the program will be halted forever.
	cmd += " ;exit"

	// ssh output and error
	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)

	// ssh output
	sshOut, err := conn.sshSession.StdoutPipe()
	if err != nil {
		log.Fatalf("failed to initiate standard output pipe\n\t\terr: %s", err.Error())
	}

	// ssh error
	sshErr, err := conn.sshSession.StderrPipe()
	if err != nil {
		log.Fatalf("failed to initiate error pipe\n\t\terr: %s", err.Error())
	}

	// start bash [it is important to before running any command] and
	// execution of the command
	if err := conn.sshSession.Start("/bin/bash; " + cmd); err != nil {
		log.Fatalf("failed to start bash or execute the command: %s\n\t\terr: %s", cmd, err.Error())
	}

	// writing output to buffer
	go io.Copy(stdOut, sshOut)
	go io.Copy(stdErr, sshErr)

	// wait for process to finish
	if err := conn.sshSession.Wait(); err != nil {
		log.Fatalf("failed to wait till the command execution finish, err: %s", err)
	}
	return stdOut, stdErr
}

// RunCmds takes a slice of string as input,
// every command is an entity of the slice
// each command need to be run with a new session.
//
// returns two maps. one for standard output of the commands executed and one if any errors occured
//   - key -- commad name
//   - val -- output/error
//
// there might be delay between execution of the command and
// getting the output depending on the latency and output length
//
// Note: this only works on servers/machines which has /bin/bash as shell, the code starts the bash shell and passes the commad to shell for execution
func (conn *session) RunCmds(cmds []string) (map[string]string, map[string]string) {
	defer conn.sshSession.Close()

	// the output and error map
	stdOutMap, stdErrMap := make(map[string]string), make(map[string]string)

	for i, cmd := range cmds {

		// exiting from the shell after executing the last command
		if i == len(cmds)-1 {
			cmd += ";exit"
		}

		// making a new client through which new sessions will be made
		currClient, err := conn.makeNewSessionFromExistingSession()
		if err != nil {
			log.Fatalf("problem in creating a new session from an existing session\n\t\terr: %s", err.Error())
		}

		// ssh output
		sshOut, err := currClient.sshSession.StdoutPipe()
		if err != nil {
			log.Fatalf("failed to initiate standard output pipe\n\t\terr: %s", err.Error())
		}

		// ssh error
		sshErr, err := currClient.sshSession.StderrPipe()
		if err != nil {
			log.Fatalf("failed to initiate error pipe\n\t\terr: %s", err.Error())
		}

		// start bash [it is important to run any command]
		// and execute the command
		if err := currClient.sshSession.Start("/bin/bash; " + cmd); err != nil {
			log.Printf("failed to execute /bin/bash or command: %s\n\t\terr: %s", cmd, err.Error())
		}

		// making a buffer where you can write the data to
		stdOutBuff, stdErrBuff := new(bytes.Buffer), new(bytes.Buffer)
		go io.Copy(stdOutBuff, sshOut)
		go io.Copy(stdErrBuff, sshErr)

		// wait for process to finish
		if err := currClient.sshSession.Wait(); err != nil {
			log.Printf("there was an error while executing a command\n\t\t last executed command: %s\n\t\terr: %s", cmd, err.Error())
		}

		// map
		stdOutMap[strings.Replace(cmd, ";exit", "", 1)] = stdOutBuff.String()
		stdErrMap[strings.Replace(cmd, ";exit", "", 1)] = stdErrBuff.String()
	}
	return stdOutMap, stdErrMap
}

// AuthInteractive provides a mechanism to
// input password and MFA code ([duo app] / [yubikey] / [google authenticator app])
//
// [duo app]: https://duo.com/
// [yubikey]: https://www.yubico.com/
// [google authenticator app]: https://en.wikipedia.org/wiki/Google_Authenticator
func authInteractive() ssh.AuthMethod {
	return ssh.KeyboardInteractive(
		func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			if len(questions) == 0 {
				fmt.Printf("%s %s\n", user, instruction)
			}
			answers := make([]string, len(questions))
			for i, question := range questions {
				fmt.Println(question)
				if echos[i] {
					if _, err := fmt.Scan(&answers[i]); err != nil {
						return nil, err
					}
				} else {
					answer, err := term.ReadPassword(int(syscall.Stdin))
					if err != nil {
						return nil, err
					}
					answers[i] = string(answer)
				}
			}
			return answers, nil
		})
}

// create an SSH client
func MakeSSHConnection(sshConf *SSHConfig) (*client, error) {
	authMehtod := authInteractive()
	config := &ssh.ClientConfig{
		User: sshConf.User,
		Auth: []ssh.AuthMethod{
			authMehtod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// remote address
	addr := fmt.Sprintf("%s:%d", sshConf.RemoteAddr, sshConf.Port)

	// ssh client which is wrapped inside client
	// type to give many funcationalities
	sshClient, err := ssh.Dial(sshConf.Protocol, addr, config)
	if err != nil {
		return nil, err
	}

	client := newClient(sshClient)
	return client, err
}
