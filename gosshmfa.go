package gosshmfa

import (
	"bytes"
	"fmt"
	"io"
	"log"
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

// AuthInteractive provides a mechanism to
// input password and MFA code ([duo app] / [yubikey] / [google authenticator app])
//
// [duo app]: https://duo.com/
// [yubikey]: https://www.yubico.com/
// [google authenticator app]: https://en.wikipedia.org/wiki/Google_Authenticator
func AuthInteractive() ssh.AuthMethod {
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
// Note: this only works on linux based servers/machines which has /bin/bash enabled as the code starts the /bin/bash enabled and executes the commands
func (conn *session) Run(cmd string) (*bytes.Buffer, *bytes.Buffer) {
	defer conn.sshSession.Close()

	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)
	// start bash [it is important to run any command]
	if err := conn.sshSession.Start("/bin/bash"); err != nil {
		log.Fatalf("failed to start bash\nerr: %s", err.Error())
	}

	// ssh output
	sshOut, err := conn.sshSession.StdoutPipe()
	if err != nil {
		log.Fatalf("failed to initiate standard output pipe\nerr: %s", err.Error())
	}

	// ssh error
	sshErr, err := conn.sshSession.StderrPipe()
	if err != nil {
		log.Fatalf("failed to initiate error pipe\nerr: %s", err.Error())
	}

	// writing output to buffer
	go io.Copy(stdOut, sshOut)
	go io.Copy(stdErr, sshErr)

	// execution of the command
	if err := conn.sshSession.Start(cmd); err != nil {
		log.Fatalf("failed to execute the command:%s\nerr:%s", cmd, err)
	}

	// wait for process to finish
	if err := conn.sshSession.Wait(); err != nil {
		log.Fatalf("failed to wait till the command execution finish, err:%s", err)
	}
	return stdOut, stdErr
}

// RunCmds takes a slice of string as input,
// every command is an entity of the slice
// each command need to be run with a new session.
//
// it might not be very feasible to differentiate between the output of each command.
// plan the set of commands you want to run at once very carefully
//
// there might be delay between execution of the command and
// getting the output depending on the latency and output length
//
// Note: this only works on servers/machines which has /bin/bash as shell, the code starts the bash shell and passes the commad to shell for execution
func (conn *session) RunCmds(cmds []string) (*bytes.Buffer, *bytes.Buffer) {
	defer conn.sshSession.Close()

	stdOut, stdErr := new(bytes.Buffer), new(bytes.Buffer)

	for _, cmd := range cmds {
		currClient, err := conn.makeNewSessionFromExistingSession()
		if err != nil {
			log.Fatalf("problem in creating a new session from an existing session\nerr: %s", err.Error())
		}
		// start bash [it is important to run any command]
		if err := currClient.sshSession.Start("/bin/bash"); err != nil {
			log.Fatalf("failed to start bash \nerr: %s", err.Error())
		}

		// ssh output
		sshOut, err := currClient.sshSession.StdoutPipe()
		if err != nil {
			log.Fatalf("failed to initiate standard output pipe\nerr: %s", err.Error())
		}

		// ssh error
		sshErr, err := currClient.sshSession.StderrPipe()
		if err != nil {
			log.Fatalf("failed to initiate error pipe\nerr: %s", err.Error())
		}

		// writing output to buffer
		go io.Copy(stdOut, sshOut)
		go io.Copy(stdErr, sshErr)

		// execution of the command
		if err := currClient.sshSession.Start(cmd); err != nil {
			log.Fatalf("failed to execute the command:%s\nerr:%s", cmd, err.Error())
		}

		// wait for process to finish
		if err := currClient.sshSession.Wait(); err != nil {
			log.Fatalf("failed to wait till the command execution finish, err:%s", err)
		}
	}
	return stdOut, stdErr
}

// create an SSH client
func MakeSSHConnection(sshConf *SSHConfig) (*client, error) {
	authMehtod := AuthInteractive()
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
