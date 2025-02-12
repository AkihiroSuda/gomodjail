package tracer

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/AkihiroSuda/gomodjail/pkg/profile"
)

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
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	binDir := filepath.Dir(self)             // /usr/local/bin
	localDir := filepath.Dir(binDir)         // /usr/local
	libDir := filepath.Join(localDir, "lib") // /usr/local/lib
	hookDylib := filepath.Join(libDir, "libgomodjail_hook_darwin.dylib")
	if _, err := os.Stat(hookDylib); err != nil {
		return nil, err
	}
	cmd.Env = append(os.Environ(),
		"DYLD_INSERT_LIBRARIES="+hookDylib,
		"LIBGOMODJAIL_HOOK_SOCKET="+sock,
	)

	tracer := &tracer{
		cmd:     cmd,
		profile: profile,
		ln:      ln,
		tmpDir:  tmpDir,
	}
	for k, v := range profile.Modules {
		slog.Debug("Loading profile", "module", k, "policy", v)
	}
	return tracer, nil
}

type tracer struct {
	cmd     *exec.Cmd
	profile *profile.Profile
	ln      net.Listener
	tmpDir  string
}

// Trace traces the process.
// Trace may call [os.Exit].
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
	defer c.Close()
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

	// TODO: consolidate OS-specific codes
	allow := true
	for _, e := range req.Stack {
		for module, policy := range tracer.profile.Modules {
			if policy == profile.PolicyConfined {
				if strings.HasPrefix(e.Symbol, module) {
					slog.Warn("***Blocked***", "pid", req.Pid, "exe", req.Exe, "syscall", req.Syscall, "entry", e, "module", module)
					allow = false
					break
				}
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
