package regs

func (regs *Regs) Syscall() uint64 {
	return regs.Regs[8]
}

func (regs *Regs) Args() []uint64 {
	return regs.Regs[0:5]
}

func (regs *Regs) SetRet(v uint64) {
	regs.Regs[0] = v
	regs.Modified = true
}

func (regs *Regs) FramePointer() uint64 {
	return regs.Regs[29]
}
