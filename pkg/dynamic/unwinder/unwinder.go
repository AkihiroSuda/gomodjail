// Package unwider provides unwinder for Go call stacks.
//
// https://www.grant.pizza/blog/go-stack-traces-bpf/
package unwinder

import (
	"debug/buildinfo"
	"debug/gosym"
	"fmt"
	"io"
	"log/slog"
)

type Unwinder interface {
	Symtab() *gosym.Table
	BuildInfo() *buildinfo.BuildInfo
	Unwind(pid int, pc, bp uintptr) ([]Entry, error)
}

type unwinder struct {
	symtab    *gosym.Table
	buildInfo *buildinfo.BuildInfo
}

func (u *unwinder) Symtab() *gosym.Table {
	return u.symtab
}

func (u *unwinder) BuildInfo() *buildinfo.BuildInfo {
	return u.buildInfo
}

func (u *unwinder) Unwind(pid int, pc, bp uintptr) ([]Entry, error) {
	return u.unwind(pid, pc, bp)
}

type Section interface {
	io.ReaderAt
	Data() ([]byte, error)
	Addr() uint64
}

type ObjectFile interface {
	Section(name string) Section
	Close() error
}

func New(binary string) (Unwinder, error) {
	e, err := openObjectFile(binary)
	if err != nil {
		return nil, err
	}
	gopclntabSec := e.Section(gopclntabSectionName)
	if gopclntabSec == nil {
		return nil, fmt.Errorf("no %s section found in %q", gopclntabSectionName, binary)
	}
	gopclntabData, err := gopclntabSec.Data()
	if err != nil {
		return nil, err
	}
	textSec := e.Section(textSectionName)
	if textSec == nil {
		return nil, fmt.Errorf("no %s section found in %q", textSectionName, binary)
	}

	var gosymtabData []byte
	gosymtabSec := e.Section(gosymtabSectionName)
	if gosymtabSec == nil {
		slog.Warn("no "+gosymtabSectionName+" section found", "binary", binary)
		// gopclntab seems to suffice in this case
	} else {
		gosymtabData, err = gosymtabSec.Data()
		if err != nil {
			return nil, err
		}
	}

	symtab, err := gosym.NewTable(gosymtabData,
		gosym.NewLineTable(gopclntabData, textSec.Addr()))
	if err != nil {
		return nil, err
	}

	buildInfo, err := buildinfo.ReadFile(binary)
	if err != nil {
		return nil, err
	}

	u := &unwinder{
		symtab:    symtab,
		buildInfo: buildInfo,
	}
	return u, nil
}

type Entry struct {
	File string
	Line int
	Func *gosym.Func
}

func (e *Entry) String() string {
	return fmt.Sprintf("%s:%d:%s", e.File, e.Line, e.Func.Name)
}
