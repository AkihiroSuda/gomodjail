package tracer

import (
	"debug/gosym"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/AkihiroSuda/gomodjail/pkg/dynamic/unwinder"
	"github.com/AkihiroSuda/gomodjail/pkg/profile"
)

func LibgomodjailHook() (string, error) {
	hookDylib := os.Getenv("LIBGOMODJAIL_HOOK")
	if hookDylib == "" {
		self, err := os.Executable()
		if err != nil {
			return "", err
		}
		binDir := filepath.Dir(self)             // /usr/local/bin
		localDir := filepath.Dir(binDir)         // /usr/local
		libDir := filepath.Join(localDir, "lib") // /usr/local/lib
		hookDylib = filepath.Join(libDir, "libgomodjail_hook_darwin.dylib")
	}
	if _, err := os.Stat(hookDylib); err != nil {
		return "", err
	}
	return hookDylib, nil
}

func findRuntimeLoadG(symtab *gosym.Table) (uintptr, error) {
	found := symtab.LookupFunc("runtime.load_g")
	if found == nil {
		return 0, errors.New("runtime.load_g not found")
	}
	return uintptr(found.Value), nil
}

func New(cmd *exec.Cmd, profile *profile.Profile) (Tracer, error) {
	uw, err := unwinder.New(cmd.Path)
	if err != nil {
		return nil, err
	}
	symtab := uw.Symtab()
	// len(symtab.Syms) is zero on stripped Mach-O binaries

	var loadG uintptr
	if runtime.GOARCH == "arm64" {
		loadG, err = findRuntimeLoadG(symtab)
		if err != nil {
			slog.Warn("failed to find runtime.load_g", "error", err)
		}
		slog.Debug("found runtime.load_g", "address", fmt.Sprintf("%d", loadG))
	}
	tmpDir, err := os.MkdirTemp("", "gomodjail")
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(tmpDir, "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	hookDylib, err := LibgomodjailHook()
	if err != nil {
		return nil, err
	}
	cmd.Env = append(os.Environ(),
		"DYLD_INSERT_LIBRARIES="+hookDylib,
		"LIBGOMODJAIL_HOOK_SOCKET="+sock,
	)
	if loadG != 0 {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("LIBGOMODJAIL_HOOK_LOAD_G_ADDR=%d", loadG),
		)
	}

	tracer := &tracer{
		cmd:       cmd,
		profile:   profile,
		ln:        ln,
		tmpDir:    tmpDir,
		unwinders: map[string]unwinder.Unwinder{cmd.Path: uw},
	}
	tracer.unwinders[cmd.Path] = uw
	for k, v := range profile.Modules {
		slog.Debug("Loading profile", "module", k, "policy", v)
	}
	return tracer, nil
}

type tracer struct {
	cmd       *exec.Cmd
	profile   *profile.Profile
	ln        net.Listener
	tmpDir    string
	unwinders map[string]unwinder.Unwinder
	mu        sync.RWMutex
}

// Trace traces the process.
func (tracer *tracer) Trace() error {
	go func() {
		for {
			c, err := tracer.ln.Accept()
			if err != nil {
				slog.Error("failed to accept", "error", err)
				break
			}
			go func() {
				if err := tracer.handlerConn(c); err != nil {
					slog.Error("failed to handle connection", "error", err)
				}
			}()
		}
	}()
	err := tracer.cmd.Start()
	if err != nil {
		return err
	}
	return tracer.cmd.Wait()
}

type requestStackEntry struct {
	Address uint64 `json:"address,omitempty"`

	File   string `json:"file,omitempty"`
	Symbol string `json:"symbol,omitempty"`
}

type request struct {
	Pid     int                 `json:"pid"`
	Exe     string              `json:"exe"`
	Syscall string              `json:"syscall"`
	Stack   []requestStackEntry `json:"stack,omitempty"`
}

func (tracer *tracer) handlerConn(c net.Conn) error {
	defer c.Close() //nolint:errcheck
	jsonLenB := make([]byte, 4)
	if _, err := c.Read(jsonLenB); err != nil {
		return err
	}
	jsonLen := binary.NativeEndian.Uint32(jsonLenB)
	if jsonLen > (1 << 16) {
		return fmt.Errorf("invalid json length: %d", jsonLen)
	}
	jsonB := make([]byte, jsonLen)
	if _, err := c.Read(jsonB); err != nil {
		return err
	}
	var req request
	if err := json.Unmarshal(jsonB, &req); err != nil {
		return fmt.Errorf("failed to unmarshal %q: %w", string(jsonB), err)
	}
	slog.Debug("handling request", "req", req)

	tracer.mu.RLock()
	uw, ok := tracer.unwinders[req.Exe]
	tracer.mu.RUnlock()
	if !ok {
		var err error
		uw, err = unwinder.New(req.Exe)
		if err != nil { // No gosymtab
			tracer.unwinders[req.Exe] = nil
			return err
		}
		tracer.unwinders[req.Exe] = uw
		slog.Debug("registered an executable", "exe", req.Exe, "mainModule", uw.BuildInfo().Main.Path)
	}
	if uw == nil { // No gosymtab
		return nil
	}
	symtab := uw.Symtab()
	buildInfo := uw.BuildInfo()
	mainModule := buildInfo.Main.Path

	allow := true
	for _, e := range req.Stack {
		sym := e.Symbol
		if sym == "" {
			_, _, fn := symtab.PCToLine(e.Address)
			if fn != nil {
				sym = fn.Name
				slog.Debug("symtab", "address", fmt.Sprintf("0x%x", e.Address), "sym", sym)
			}
		}
		if sym != "" {
			if cf := tracer.profile.Confined(mainModule, sym); cf != nil {
				slog.Warn("***Blocked***", "pid", req.Pid, "exe", req.Exe, "syscall", req.Syscall, "entry", e, "module", cf.Module, "sym", sym)
				allow = false
				break
			}
		}
	}

	respB := []byte{1, 0, 0, 0, '1'} // little endian
	if !allow {
		respB[4] = '0'
	}
	if _, err := c.Write(respB); err != nil {
		return err
	}
	return nil
}

func (tracer *tracer) Close() error {
	return os.RemoveAll(tracer.tmpDir)
}
