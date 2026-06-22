package analyze

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

const poisonedMod = "github.com/AkihiroSuda/gomodjail/examples/poisoned"

func TestReportOK(t *testing.T) {
	var buf bytes.Buffer
	report(&buf, nil)
	assert.Assert(t, strings.Contains(buf.String(), "no policy violations"), "got %q", buf.String())
}

func TestReportViolation(t *testing.T) {
	v := policy.Violation{
		Module:     poisonedMod,
		Capability: policy.CapExec,
		Path: []capslock.FuncRef{
			{Name: "victim.main", Package: "victim"},
			{Name: poisonedMod + ".Add", Package: poisonedMod, Filename: "poisoned.go", Line: 19},
			{Name: "os/exec.Command", Package: "os/exec"},
		},
		OwnerIndex: 1,
	}
	var buf bytes.Buffer
	report(&buf, []policy.Violation{v})
	out := buf.String()
	assert.Assert(t, strings.Contains(out, poisonedMod), "got %q", out)
	assert.Assert(t, strings.Contains(out, policy.CapExec), "got %q", out)
	assert.Assert(t, strings.Contains(out, "os/exec.Command"), "got %q", out)
	// The owner frame is marked with "> "; other frames are not.
	assert.Assert(t, strings.Contains(out, "> "+poisonedMod+".Add"), "owner frame must be marked; got %q", out)
}

func TestReportEscapeHatchMarker(t *testing.T) {
	v := policy.Violation{
		Module:     poisonedMod,
		Capability: policy.CapUnsafePointer,
		Path:       []capslock.FuncRef{{Name: poisonedMod + ".X", Package: poisonedMod}},
		OwnerIndex: 0,
	}
	var buf bytes.Buffer
	report(&buf, []policy.Violation{v})
	assert.Assert(t, strings.Contains(buf.String(), "unanalyzable"), "got %q", buf.String())
}

func TestReportDedupes(t *testing.T) {
	v := policy.Violation{
		Module:     poisonedMod,
		Capability: policy.CapExec,
		Path:       []capslock.FuncRef{{Name: poisonedMod + ".Add", Package: poisonedMod}},
		OwnerIndex: 0,
	}
	var buf bytes.Buffer
	report(&buf, []policy.Violation{v, v, v})
	assert.Equal(t, strings.Count(buf.String(), "confined module reaches"), 1)
}

// withWorkdir runs fn with the process working directory temporarily set to
// dir. The lint command (and Capslock) load packages relative to cwd, so the
// end-to-end tests must run from the target module root.
func withWorkdir(t *testing.T, dir string, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	assert.NilError(t, err)
	assert.NilError(t, os.Chdir(dir))
	defer func() { assert.NilError(t, os.Chdir(orig)) }()
	fn()
}

func victimDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "examples", "victim"))
	assert.NilError(t, err)
	return dir
}

func runAnalyze(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// TestAnalyzeVictimFails is the headline M3 regression: linting examples/victim,
// whose go.mod confines the poisoned module, must fail with the EXEC violation
// attributed to poisoned.
func TestAnalyzeVictimFails(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		out, err := runAnalyze(t, "./...")
		assert.Assert(t, err != nil, "lint must fail; out=%q", out)
		assert.Assert(t, strings.Contains(out, poisonedMod), "out=%q", out)
		assert.Assert(t, strings.Contains(out, policy.CapExec), "out=%q", out)
	})
}

// TestAnalyzePasses confirms a clean exit: confining a reachable but benign
// package (strings, used by poisoned but reaching no sink) yields no violation.
func TestAnalyzePasses(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		out, err := runAnalyze(t, "--go-mod=", "--policy=strings=confined", "./...")
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "no policy violations"), "out=%q", out)
	})
}

// TestAnalyzeNoConfinedModules errors helpfully rather than silently passing when
// nothing is confined — a security gate should not no-op on misconfiguration.
func TestAnalyzeNoConfinedModules(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		_, err := runAnalyze(t, "--go-mod=", "./...")
		assert.ErrorContains(t, err, "no confined modules")
	})
}
