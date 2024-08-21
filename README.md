# go-ssh-mfa

### A wrapper package for the [ssh package](https://pkg.go.dev/golang.org/x/crypto/ssh) which allows you to ssh into machines/servers which requires MFA ([duo-app](https://duo.com/)/[yubikey](https://www.yubico.com/)/[google authenticator](https://en.wikipedia.org/wiki/Google_Authenticator)).

## install

```go
go get -u github.com/vinaykulk621/go-ssh-mfa
```

### This package wraps all the methods offered by ssh package's [clent](<https://pkg.go.dev/golang.org/x/crypto/ssh#Client:~:text=type%20Channel-,type%20Client,func%20(c%20*Client)%20NewSession()%20(*Session%2C%20error),-type%20ClientConfig>) and [session](<https://pkg.go.dev/golang.org/x/crypto/ssh#Client:~:text=chan%20*Request%2C%20error)-,type%20Session,func%20(s%20*Session)%20WindowChange(h%2C%20w%20int)%20error,-type%20Signal>) type (i hope, i did not miss any) along with two new methods `Run` and `RunCmds`.

## Example usage

### configuring credentials

```go
type SSHConfig struct {
	User       string // username through which ssh connection is made
	Protocol   string // takes one of the two values "tcp" or "udp"
	RemoteAddr string // IP address or server name(FQDN)
	Port       int    // port to which ssh connection should be made
}
```

### running a single a command using `Run()` will execute your command something like this: `/bin/bash; <yourCmd>; exit`.

> A Session only accepts one call to Run, Start or Shell. If you want to run multiple commands at once, checkout `RunCmds()`.

```go
package main

import (
    "fmt"
	"log"

	gosshmfa "github.com/vinaykulk621/go-ssh-mfa"
)

func main() {
	config := &gosshmfa.SSHConfig{
		User:       "user",
		Protocol:   "tcp",
		RemoteAddr: "my-server-name",
		Port:       22,
	}
	client, err := gosshmfa.MakeSSHConnection(config)
	if err != nil {
		log.Fatalf("failed to ssh\n\t\terr: %s", err.Error())
	}
	defer client.Close()

	session, err := client.MakeNewSession()
	if err != nil {
		log.Fatalf("failed to create a session\n\t\terr: %s", err.Error())
	}
	defer session.Close()

	stdout, stdErr := session.Run("ls")
	fmt.Println(stdout.String(), stdErr.String())
}
```

### running multiple commands or chaining commands can be achieved through `RunCmds()`.

- `RunCmds()` will loop through all the commands, and for the last command it will execute: `/bin/bash; <yourCmd>; exit`.
- `RunCmds()` will internally create new sessions for each command, as a session only accepts one call to `Run`.
- `RunCmds()` returns 2 maps with commands as keys:
  - `stdOutMap` contains the outputs (if any) or empty string for each command.
  - `stdErrMap` contains the errors (if any) or empty string for each command.

```go
// takes slice of commands as input
//
// returns two maps. one for standard output of
// the commands executed and one if any errors occured
// if no error or output, val will be an empty string
//   - key -- commad
//   - val -- output/error
func main(){
	...

	session, err := ...
	...

	stdOutMap, stdErrMap := session.RunCmds(cmds)
	...
}
```

main.go:

```go
func main() {
	cmds := []string{"ls", "cat ab.txt", "echo 'hi'"}
	config := &gosshmfa.SSHConfig{...}

	client, err := gosshmfa.MakeSSHConnection(config)
	if err != nil { ...	}
	defer client.Close()

	session, err := client.MakeNewSession()
	if err != nil { ...	}
	defer session.Close()

	stdOutMap, stdErrMap := session.RunCmds(cmds)
	fmt.Println(stdOutMap, stdErrMap)
}
```
