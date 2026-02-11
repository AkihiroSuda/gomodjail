package parent

import (
	"os"
	"os/exec"

	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/env"
	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/pack/osargs"
)

func createCmd(_ []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	// osargs.OSArgs is basically os.Args but is overridden on self-extract mode
	cmd := exec.Command(self, osargs.OSArgs()[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), env.PrivateChild+"=") // no value
	return cmd, nil
}
