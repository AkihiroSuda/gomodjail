// Package unwider provides unwinder for Go call stacks.
//
// https://www.grant.pizza/blog/go-stack-traces-bpf/
package unwinder

import (
	"debug/elf"

	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/procutil"
)

const (
	gopclntabSectionName = ".gopclntab"
	textSectionName      = ".text"
	gosymtabSectionName  = ".gosymtab"
)

type elfObjectFile struct {
	*elf.File
}

func (e *elfObjectFile) Section(name string) Section {
	section := e.File.Section(name)
	if section == nil {
		return nil
	}
	return &elfSection{Section: section}
}

type elfSection struct {
	*elf.Section
}

func (s *elfSection) Addr() uint64 {
	return s.Section.Addr
}

func openObjectFile(path string) (ObjectFile, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return &elfObjectFile{File: f}, nil
}

func (u *unwinder) unwind(pid int, pc, bp uintptr) ([]Entry, error) {
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
		ent.File, ent.Line, ent.Func = u.symtab.PCToLine(uint64(pc))
		if ent.Func != nil {
			res = append(res, ent)
		}
		pc = uintptr(retAddr)
		bp = uintptr(savedBp)
		frameCount++
	}
	return res, nil
}
