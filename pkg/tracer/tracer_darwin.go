package tracer

import (
	"debug/buildinfo"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

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

func New(cmd *exec.Cmd, profile *profile.Profile) (Tracer, error) {
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

	tracer := &tracer{
		cmd:         cmd,
		profile:     profile,
		ln:          ln,
		tmpDir:      tmpDir,
		mainModules: make(map[string]string),
	}
	for k, v := range profile.Modules {
		slog.Debug("Loading profile", "module", k, "policy", v)
	}
	return tracer, nil
}

type tracer struct {
	cmd         *exec.Cmd
	profile     *profile.Profile
	ln          net.Listener
	tmpDir      string
	mainModules map[string]string // key: filename, value: main module
	mu          sync.RWMutex
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
	mainModule := tracer.mainModules[req.Exe]
	tracer.mu.RUnlock()
	if mainModule == "" {
		buildInfo, err := buildinfo.ReadFile(req.Exe)
		if err != nil {
			return err
		}
		mainModule = buildInfo.Main.Path
		tracer.mu.Lock()
		tracer.mainModules[req.Exe] = mainModule
		tracer.mu.Unlock()
	}

	allow := true
	for _, e := range req.Stack {
		if cf := tracer.profile.Confined(mainModule, e.Symbol); cf != nil {
			slog.Warn("***Blocked***", "pid", req.Pid, "exe", req.Exe, "syscall", req.Syscall, "entry", e, "module", cf.Module)
			allow = false
			break
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
