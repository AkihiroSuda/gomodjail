package child

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"syscall"

	"github.com/AkihiroSuda/gomodjail/pkg/env"
	"github.com/AkihiroSuda/gomodjail/pkg/profile/seccompprofile"
	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/elastic/go-seccomp-bpf/arch"
)

func withoutUnknownSyscalls(ss []string) []string {
	archInfo, err := arch.GetInfo("")
	if err != nil {
		panic(err)
	}
	var res []string
	for _, s := range ss {
		if _, ok := archInfo.SyscallNames[s]; ok {
			res = append(res, s)
		} else {
			slog.Debug("Ignoring syscall not supported on this arch",
				"syscallName", s, "arch", archInfo.ID.String())
		}
	}
	return res
}

func Main(args []string) error {
	if os.Geteuid() == 0 {
		// seccompprofile is not ready to cover privileged syscalls yet.
		slog.Warn("gomodjail should not be executed as the root (yet)")
	}
	arg0, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	os.Unsetenv(env.PrivateChild)

	seccompPolicy := seccomp.Policy{
		DefaultAction: seccomp.ActionTrace,
		Syscalls: []seccomp.SyscallGroup{
			{
				Names:  withoutUnknownSyscalls(seccompprofile.AlwaysAllowed),
				Action: seccomp.ActionAllow,
			},
		},
	}
	seccompFilter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     seccompPolicy,
	}
	if err := seccomp.LoadFilter(seccompFilter); err != nil {
		return fmt.Errorf("failed to load the seccomp filter: %w", err)
	}

	if err := syscall.Exec(arg0, args, os.Environ()); err != nil {
		return fmt.Errorf("failed to execute %q %v: %w", arg0, args, err)
	}
	return nil
}
