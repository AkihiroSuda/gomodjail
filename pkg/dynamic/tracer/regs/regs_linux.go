package regs

import "golang.org/x/sys/unix"

type Regs struct {
	unix.PtraceRegs
	Modified bool
}
