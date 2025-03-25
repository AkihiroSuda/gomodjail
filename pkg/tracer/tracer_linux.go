// Package tracer was forked from
// https://github.com/AkihiroSuda/lsf/blob/ff4e43f59c5dc1a93c2b0e81b741bbc439c211da/pkg/tracer/tracer_linux.go
package tracer

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"

	"github.com/AkihiroSuda/gomodjail/pkg/procutil"
	"github.com/AkihiroSuda/gomodjail/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/pkg/tracer/regs"
	"github.com/AkihiroSuda/gomodjail/pkg/unwinder"
	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/sys/unix"
)

func New(cmd *exec.Cmd, profile *profile.Profile) (Tracer, error) {
	selfExe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &unix.SysProcAttr{Ptrace: true}
	archInfo, err := arch.GetInfo("")
	if err != nil {
		return nil, err
	}
	tracer := &tracer{
		cmd:       cmd,
		profile:   profile,
		selfExe:   selfExe,
		pids:      make(map[int]string),
		unwinders: make(map[string]*unwinder.Unwinder),
		archInfo:  archInfo,
	}
	for k, v := range profile.Modules {
		slog.Debug("Loading profile", "module", k, "policy", v)
	}
	return tracer, nil
}

type tracer struct {
	cmd       *exec.Cmd
	profile   *profile.Profile
	selfExe   string
	pids      map[int]string                // key: pid, value: file name
	unwinders map[string]*unwinder.Unwinder // key: file name
	archInfo  *arch.Info
}

const commonPtraceOptions = unix.PTRACE_O_TRACEFORK |
	unix.PTRACE_O_TRACEVFORK |
	unix.PTRACE_O_TRACECLONE |
	unix.PTRACE_O_TRACEEXEC |
	unix.PTRACE_O_TRACEEXIT |
	unix.PTRACE_O_TRACESYSGOOD |
	unix.PTRACE_O_EXITKILL

// Trace traces the process.
// Trace may call [os.Exit].
func (tracer *tracer) Trace() error {
	runtime.LockOSThread() // required by SysProcAttr.Ptrace

	// TODO: propagate signals from parent (see RootlessKit's implementation)

	err := tracer.cmd.Start()
	if err != nil {
		return err
	}
	pGid, err := unix.Getpgid(tracer.cmd.Process.Pid)
	if err != nil {
		return err
	}

	// Catch the birtycry before setting up the ptrace options
	wPid, sig, err := procutil.WaitForStopSignal(-1 * pGid)
	if err != nil {
		return err
	}
	if sig != unix.SIGTRAP {
		return fmt.Errorf("birthcry: expected SIGTRAP, got %+v", sig)
	}
	// Set up the ptrace options
	ptraceOptions := commonPtraceOptions | unix.PTRACE_O_TRACESECCOMP
	if err := unix.PtraceSetOptions(wPid, ptraceOptions); err != nil {
		return fmt.Errorf("failed to set ptrace options: %w", err)
	}
	// Restart the process stopped in the birthcry
	if err := unix.PtraceCont(wPid, 0); err != nil {
		return fmt.Errorf("failed to call PTRACE_CONT (pid=%d) %w", wPid, err)
	}
	for {
		var ws unix.WaitStatus
		wPid, err = unix.Wait4(-1*pGid, &ws, unix.WALL, nil)
		if err != nil {
			return err
		}
		switch {
		case ws.Exited():
			exitStatus := ws.ExitStatus()
			if wPid == tracer.cmd.Process.Pid {
				if exitStatus == 0 {
					slog.Debug("exiting")
				} else {
					slog.Error("exiting with non-zero status", "status", exitStatus)
				}
				os.Exit(exitStatus)
				return nil
			}
			continue
		}
		switch uint32(ws) >> 8 {
		case uint32(unix.SIGTRAP) | (unix.PTRACE_EVENT_SECCOMP << 8):
			var regs regs.Regs
			if err = unix.PtraceGetRegs(wPid, &regs.PtraceRegs); err != nil {
				return fmt.Errorf("failed to read registers for %d: %w", wPid, err)
			}
			if err = tracer.handleSyscall(wPid, &regs); err != nil {
				slog.Debug("failed to handle syscall", "pid", wPid, "syscall", regs.Syscall(), "error", err)
			} else {
				if regs.Modified {
					if err = unix.PtraceSetRegs(wPid, &regs.PtraceRegs); err != nil {
						return fmt.Errorf("failed to set registers for %d: %w", wPid, err)
					}
				}
			}
		}
		if err := unix.PtraceCont(wPid, 0); err != nil {
			return fmt.Errorf("failed to call PTRACE_CONT (pid=%d) %w", wPid, err)
		}
	}
}

func (tracer *tracer) handleSyscall(pid int, regs *regs.Regs) error {
	syscallNr := regs.Syscall()
	// FIXME: check the seccomp arch
	syscallName, ok := tracer.archInfo.SyscallNumbers[int(syscallNr)]
	if !ok {
		return fmt.Errorf("unknown syscall %d", syscallNr)
	}
	switch syscallName {
	case "execve", "execveat":
		defer func() {
			// the process image is going to change
			delete(tracer.pids, pid)
		}()
	}
	filename, ok := tracer.pids[pid]
	if !ok {
		var err error
		filename, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return err
		}
		tracer.pids[pid] = filename
	}
	if filename == tracer.selfExe {
		return nil
	}
	uw, ok := tracer.unwinders[filename]
	if !ok {
		var err error
		uw, err = unwinder.New(filename)
		if err != nil { // No gosymtab
			tracer.unwinders[filename] = nil
			return err
		}
		tracer.unwinders[filename] = uw
	}
	if uw == nil { // No gosymtab
		return nil
	}
	entries, err := uw.Unwind(pid, uintptr(regs.PC()), uintptr(regs.FramePointer()))
	if err != nil {
		return err
	}
	slog.Debug("handler", "pid", pid, "exe", filename, "syscall", syscallName)
	for i, e := range entries {
		slog.Debug("stack", "entryNo", i, "entry", e.String())
		pkgName := e.Func.PackageName()
		if cf := tracer.profile.Confined(pkgName); cf != nil {
			slog.Warn("***Blocked***", "pid", pid, "exe", filename, "syscall", syscallName, "entry", e.String(), "module", cf.Module)
			ret := -1 * int(unix.EPERM)
			regs.SetRet(uint64(ret))
			regs.SetSyscall(unix.SYS_GETPID) // Only needed on amd64?
			return nil
		}
	}
	return nil
}
