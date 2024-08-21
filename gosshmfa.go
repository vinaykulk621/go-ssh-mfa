// package gosshmfa is a wrapper for ssh package of the golang
// which allows you to ssh into mchines which requires MFA
//
// author: Vinay Kulkarni<kulkarnivinay621@gmail.com>
//
// This package implements everything (almost (i hope so))
// you can with ssh package of go.
package gosshmfa

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// user should provide all these details to make the ssh connection
type SSHConfig struct {
	User       string // username through which ssh connection is made
	Protocol   string // takes one of the two values "tcp" or "udp"
	RemoteAddr string // IP address or server name(FQDN)
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
	// Stdin specifies the remote process's standard input.
	// If Stdin is nil, the remote process reads from an empty
	// bytes.Buffer.
	Stdin io.Reader

	// Stdout and Stderr specify the remote process's standard
	// output and error.
	//
	// If either is nil, Run connects the corresponding file
	// descriptor to an instance of io.Discard. There is a
	// fixed amount of buffering that is shared for the two streams.
	// If either blocks it may eventually cause the remote
	// command to block.
	Stdout io.Writer
	Stderr io.Writer

	sshSession *ssh.Session // ssh session client
	sshClient  *ssh.Client  // ssh client
}

// creates a new client of type client
func newClient(sshClient *ssh.Client) *client {
	return &client{
		sshClient: sshClient,
	}
}

// Dial method from ssh package
//
// Dial initiates a connection to the addr from the remote host.
// The resulting connection has a zero LocalAddr() and RemoteAddr().
func (conn *client) Dial(n, addr string) (net.Conn, error) {
	netConn, err := conn.sshClient.Dial(n, addr)
	return netConn, err
}

// DialContext method from ssh package
//
// DialContext initiates a connection to the addr from the remote host.
//
// The provided Context must be non-nil. If the context expires before the
// connection is complete, an error is returned. Once successfully connected,
// any expiration of the context will not affect the connection.
//
// See func Dial for additional information.
func (conn *client) DialContext(ctx context.Context, n, addr string) (net.Conn, error) {
	netConn, err := conn.sshClient.DialContext(ctx, n, addr)
	return netConn, err
}

// DialTCP method from ssh package
//
// DialTCP connects to the remote address raddr on the network net,
// which must be "tcp", "tcp4", or "tcp6".  If laddr is not nil, it is used
// as the local address for the connection.
func (conn *client) DialTCP(n string, laddr, raddr *net.TCPAddr) (net.Conn, error) {
	netConn, err := conn.sshClient.DialTCP(n, laddr, raddr)
	return netConn, err
}

// HandleChannelOpen method from ssh package
//
// HandleChannelOpen returns a channel on which NewChannel requests
// for the given type are sent. If the type already is being handled,
// nil is returned. The channel is closed when the connection is closed.
func (conn *client) HandleChannelOpen(channelType string) <-chan ssh.NewChannel {
	netConn := conn.sshClient.HandleChannelOpen(channelType)
	return netConn
}

// Listen method from ssh package
//
// Listen requests the remote peer open a listening socket on
// addr. Incoming connections will be available by calling Accept on
// the returned net.Listener. The listener must be serviced, or the
// SSH connection may hang.
// N must be "tcp", "tcp4", "tcp6", or "unix".
func (conn *client) Listen(n, addr string) (net.Listener, error) {
	netListner, err := conn.sshClient.Listen(n, addr)
	return netListner, err
}

// ListenTCP method from ssh package
//
// ListenTCP requests the remote peer open a listening socket
// on laddr. Incoming connections will be available by calling
// Accept on the returned net.Listener.
func (conn *client) ListenTCP(laddr *net.TCPAddr) (net.Listener, error) {
	netListner, err := conn.sshClient.ListenTCP(laddr)
	return netListner, err
}

// ListenUnix method from ssh package
//
// ListenUnix is similar to ListenTCP but uses a Unix domain socket.
func (conn *client) ListenUnix(socketPath string) (net.Listener, error) {
	netListner, err := conn.sshClient.ListenUnix(socketPath)
	return netListner, err
}

// NewSession method from ssh package
//
// NewSession opens a new Session for this client. (A session is a remote
// execution of a program.)
func (conn *client) NewSession() (*ssh.Session, error) {
	session, err := conn.sshClient.NewSession()
	return session, err
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

// close the session
func (conn *session) Close() error {
	err := conn.sshSession.Close()
	return err
}

// creates a new ssh session from the client
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

// CombinedOutput method from ssh package
//
// CombinedOutput runs cmd on the remote host and returns its combined
// standard output and standard error.
func (conn *session) CombinedOutput(cmd string) ([]byte, error) {
	byteData, err := conn.sshSession.CombinedOutput(cmd)
	return byteData, err
}

// Output method from ssh package
//
// Output runs cmd on the remote host and returns its standard output.
func (conn *session) Output(cmd string) ([]byte, error) {
	byteData, err := conn.sshSession.Output(cmd)
	return byteData, err
}

// RequestPty method from ssh package
//
// RequestPty requests the association of a pty with the session on the remote host.
func (conn *session) RequestPty(term string, h int, w int, termmodes ssh.TerminalModes) error {
	err := conn.sshSession.RequestPty(term, h, w, termmodes)
	return err
}

// RequestSubsystem method from ssh package
//
// RequestSubsystem requests the association of a subsystem with the session on the remote host.
// A subsystem is a predefined command that runs in the background when the ssh session is initiated
func (conn *session) RequestSubsystem(subsystem string) error {
	err := conn.sshSession.RequestSubsystem(subsystem)
	return err
}

// Setenv method from ssh package
//
// Setenv sets an environment variable that will be applied to any
// command executed by Shell or Run.
func (conn *session) Setenv(name string, val string) error {
	err := conn.sshSession.Setenv(name, val)
	return err
}

// Shell method from ssh package
//
// Shell starts a login shell on the remote host. A Session only
// accepts one call to Run, Start, Shell, Output, or CombinedOutput.
func (conn *session) Shell() error {
	err := conn.sshSession.Shell()
	return err
}

// Signal method from ssh package
//
// Signal sends the given signal to the remote process.
// sig is one of the SIG* constants.
func (conn *session) Signal(sig ssh.Signal) error {
	err := conn.sshSession.Signal(sig)
	return err
}

// Start method from ssh package
//
// Start runs cmd on the remote host. Typically, the remote
// server passes cmd to the shell for interpretation.
// A Session only accepts one call to Run, Start or Shell.
func (conn *session) Start(cmd string) error {
	err := conn.sshSession.Start(cmd)
	return err
}

// Wait method from ssh package
//
// Wait waits for the remote command to exit.
//
// The returned error is nil if the command runs, has no problems
// copying stdin, stdout, and stderr, and exits with a zero exit
// status.
//
// If the remote server does not send an exit status, an error of type
// *ExitMissingError is returned. If the command completes
// unsuccessfully or is interrupted by a signal, the error is of type
// *ExitError. Other error types may be returned for I/O problems.
func (conn *session) Wait() error {
	err := conn.sshSession.Wait()
	return err
}

// WindowChange method from ssh package
//
// WindowChange informs the remote host about a terminal window dimension change to h rows and w columns.
func (conn *session) WindowChange(h int, w int) error {
	err := conn.sshSession.WindowChange(h, w)
	return err
}

// SendRequest method from ssh package
//
// SendRequest sends an out-of-band channel request on the SSH channel
// underlying the session.
func (conn *session) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	ok, err := conn.sshSession.SendRequest(name, wantReply, payload)
	return ok, err
}

// StderrPipe method from ssh package
//
// StderrPipe returns a pipe that will be connected to the
// remote command's standard error when the command starts.
// There is a fixed amount of buffering that is shared between
// stdout and stderr streams. If the StderrPipe reader is
// not serviced fast enough it may eventually cause the
// remote command to block.
func (conn *session) StderrPipe() (io.Reader, error) {
	ioReader, err := conn.sshSession.StderrPipe()
	return ioReader, err
}

// StdinPipe method from ssh package
//
// StdinPipe returns a pipe that will be connected to the
// remote command's standard input when the command starts.
func (conn *session) StdinPipe() (io.WriteCloser, error) {
	ioWriteCloser, err := conn.sshSession.StdinPipe()
	return ioWriteCloser, err
}

// StdoutPipe method from ssh package
//
// StdoutPipe returns a pipe that will be connected to the
// remote command's standard output when the command starts.
// There is a fixed amount of buffering that is shared between
// stdout and stderr streams. If the StdoutPipe reader is
// not serviced fast enough it may eventually cause the
// remote command to block.
func (conn *session) StdoutPipe() (io.Reader, error) {
	ioReader, err := conn.sshSession.StdoutPipe()
	return ioReader, err
}

// runs a single command and returns output as
//
//	stdOutput, stdError
//
// checkout RunCmds if you want to run multiple commands at once
//
// Note: this only works on linux based servers/machines which has
// /bin/bash enabled as the command is run something like this:
//
//	/bin/bash; <yourCmd>; exit
func (conn *session) Run(cmd string) (*bytes.Buffer, *bytes.Buffer) {
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
// this only works on servers/machines which has /bin/bash as shell, the code starts the bash shell and passes the commad to shell for execution.
// see func Run for more information
func (conn *session) RunCmds(cmds []string) (map[string]string, map[string]string) {

	// the output and error map
	stdOutMap, stdErrMap := make(map[string]string), make(map[string]string)

	for i, cmd := range cmds {

		// exiting from the shell(process) after executing the last command
		if i == len(cmds)-1 {
			cmd += ";exit"
		}

		// making a new client which will be used to create new sessions
		currClient, err := conn.makeNewSessionFromExistingSession()
		if err != nil {
			log.Fatalf("failed to create a new session from an existing session\n\t\terr: %s", err.Error())
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
			log.Printf("there was an error while executing a command, last executed command: %s\n\t\terr: %s", cmd, err.Error())
		}

		// map
		//
		stdOutMap[cmd] = stdOutBuff.String()
		stdErrMap[cmd] = stdErrBuff.String()
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
	// type to give many functionalities
	var (
		sshClient *ssh.Client
		err       error
	)

	// retry login attempts three times
	for attempts := 0; attempts < 3; attempts++ {
		sshClient, err = ssh.Dial(sshConf.Protocol, addr, config)
		if err == nil {
			break
		}
		fmt.Println("failed to connect, please try again.")
	}
	if err != nil {
		return nil, err
	}

	client := newClient(sshClient)
	return client, err
}
