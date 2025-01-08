package child

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"github.com/AkihiroSuda/gomodjail/pkg/env"
	"github.com/AkihiroSuda/gomodjail/pkg/profile/seccompprofile"
	seccomp "github.com/seccomp/libseccomp-golang"
)

func Main(args []string) error {
	if os.Geteuid() == 0 {
		// seccompprofile is not ready to cover privileged syscalls yet.
		slog.Warn("gomodjail should not be executed as the root (yet)")
	}
	arg0, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	filter, err := seccomp.NewFilter(seccomp.ActTrace)
	if err != nil {
		return fmt.Errorf("failed to create a seccomp filter: %w", err)
	}
	for _, syscallName := range seccompprofile.AlwaysAllowed {
		sc, err := seccomp.GetSyscallFromName(syscallName)
		if err != nil {
			return fmt.Errorf("failed to get syscall %q: %w", syscallName, err)
		}
		if err := filter.AddRule(sc, seccomp.ActAllow); err != nil {
			return fmt.Errorf("failed to add a rule for %q: %w", syscallName, err)
		}
	}
	if err := filter.Load(); err != nil {
		return fmt.Errorf("failed to load the seccomp filter: %w", err)
	}
	os.Unsetenv(env.PrivateChild)
	if err := syscall.Exec(arg0, args, os.Environ()); err != nil {
		return fmt.Errorf("failed to execute %q %v: %w", arg0, args, err)
	}
	return nil
}
