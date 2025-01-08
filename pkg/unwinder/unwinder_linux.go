// Package unwider provides unwinder for Go call stacks.
//
// https://www.grant.pizza/blog/go-stack-traces-bpf/
package unwinder

import (
	"debug/elf"
	"debug/gosym"
	"fmt"

	"github.com/AkihiroSuda/gomodjail/pkg/procutil"
)

type Unwinder struct {
	Symtab *gosym.Table
}

func New(binary string) (*Unwinder, error) {
	e, err := elf.Open(binary)
	if err != nil {
		return nil, err
	}
	gosymtabSec := e.Section(".gosymtab")
	if gosymtabSec == nil {
		return nil, fmt.Errorf("no .gosymtab section found in %q", binary)
	}
	gosymtabData, err := gosymtabSec.Data()
	if err != nil {
		return nil, err
	}

	gopclntabSec := e.Section(".gopclntab")
	if gopclntabSec == nil {
		return nil, fmt.Errorf("no .gopclntab section found in %q", binary)
	}
	gopclntabData, err := gopclntabSec.Data()
	if err != nil {
		return nil, err
	}
	textSec := e.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("no .text section found in %q", binary)
	}

	symtab, err := gosym.NewTable(gosymtabData,
		gosym.NewLineTable(gopclntabData, textSec.Addr))
	if err != nil {
		return nil, err
	}

	u := &Unwinder{
		Symtab: symtab,
	}
	return u, nil
}

func (u *Unwinder) Unwind(pid int, pc, bp uintptr) ([]Entry, error) {
	var res []Entry
	frameCount := 0
	const maxFrames = 1024
	for bp != 0 && frameCount < maxFrames {
		// FIXME: read the memory regions at once
		savedBp, err := procutil.ReadUint64(pid, bp)
		if err != nil {
			return res, err
		}
		retAddr, err := procutil.ReadUint64(pid, bp+wordSize)
		if err != nil {
			return res, err
		}
		var ent Entry
		ent.File, ent.Line, ent.Func = u.Symtab.PCToLine(uint64(pc))
		if ent.Func != nil {
			res = append(res, ent)
		}
		pc = uintptr(retAddr)
		bp = uintptr(savedBp)
		frameCount++
	}
	return res, nil
}

type Entry struct {
	File string
	Line int
	Func *gosym.Func
}

func (e *Entry) String() string {
	return fmt.Sprintf("%s:%d:%s", e.File, e.Line, e.Func.Name)
}
