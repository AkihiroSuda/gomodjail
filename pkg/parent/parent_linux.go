package parent

import (
	"os"
	"os/exec"

	"github.com/AkihiroSuda/gomodjail/pkg/env"
	"github.com/AkihiroSuda/gomodjail/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/pkg/tracer"
)

func Main(profile *profile.Profile, args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), env.PrivateChild+"=") // no value

	tr, err := tracer.New(cmd, profile)
	if err != nil {
		return err
	}
	return tr.Trace()
}
