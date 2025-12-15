// Package unwider provides unwinder for Go call stacks.
//
// https://www.grant.pizza/blog/go-stack-traces-bpf/
package unwinder

import (
	"debug/macho"
	"errors"
)

const (
	gopclntabSectionName = "__gopclntab"
	textSectionName      = "__text"
	gosymtabSectionName  = "__gosymtab"
)

type machoObjectFile struct {
	*macho.File
}

func (e *machoObjectFile) Section(name string) Section {
	section := e.File.Section(name)
	if section == nil {
		return nil
	}
	return &machoSection{Section: section}
}

type machoSection struct {
	*macho.Section
}

func (s *machoSection) Addr() uint64 {
	return s.Section.Addr
}

func openObjectFile(path string) (ObjectFile, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	return &machoObjectFile{File: f}, nil
}

func (u *unwinder) unwind(_ int, _, _ uintptr) ([]Entry, error) {
	_ = wordSize
	return nil, errors.New("unwinder for Darwin is not implemented yet")
}
