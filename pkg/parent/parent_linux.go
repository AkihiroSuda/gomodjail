package parent

import (
	"os"
	"os/exec"

	"github.com/AkihiroSuda/gomodjail/pkg/env"
)

func createCmd(_ []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), env.PrivateChild+"=") // no value
	return cmd, nil
}
