package regs

func (regs *Regs) Syscall() uint64 {
	return regs.Orig_rax
}

func (regs *Regs) Args() []uint64 {
	return []uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
}

func (regs *Regs) SetRet(v uint64) {
	regs.Rax = v
	regs.Modified = true
}

func (regs *Regs) FramePointer() uint64 {
	return regs.Rbp
}
