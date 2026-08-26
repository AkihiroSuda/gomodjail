package capslock_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"gotest.tools/v3/assert"
)

const (
	// capEXEC is earned by reaching os/exec (the "malicious vi" call in the
	// poisoned example uses os/exec.Command). Capslock's CapabilityName field
	// reports the class without the proto "CAPABILITY_" prefix.
	capEXEC = "EXEC"

	poisonedMod = "github.com/AkihiroSuda/gomodjail/examples/poisoned"
)

// exampleDir returns the absolute path of an examples/<name> module root. The
// examples are separate modules (victim depends on poisoned via a replace
// directive), so Analyze must run with Dir set to the module root.
func exampleDir(t *testing.T, name string) string {
	t.Helper()
	// This test file lives in pkg/static/capslock; the repo root is three
	// levels up.
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "examples", name))
	assert.NilError(t, err)
	return dir
}

func hasCapability(findings []capslock.Finding, cap string) bool {
	for _, f := range findings {
		if f.Capability == cap {
			return true
		}
	}
	return false
}

// TestModuleRootedAnalysis is the headline assertion: analyzing victim with
// the query rooted at the confined poisoned module must surface EXEC (the
// "malicious vi" path), attributed to poisoned, with a witness path that
// STARTS inside poisoned — not at victim's entry points. Rooting the query at
// the module is what keeps the report to one finding per (package,
// capability) instead of one per entry point.
func TestModuleRootedAnalysis(t *testing.T) {
	res, err := capslock.Analyze(capslock.Options{
		Dir:             exampleDir(t, "victim"),
		ConfinedModules: []string{poisonedMod},
	})
	assert.NilError(t, err)
	assert.Assert(t, len(res.Findings) > 0, "expected at least one capability finding")

	assert.Assert(t, hasCapability(res.Findings, capEXEC),
		"expected %s from the os/exec.Command call; got %v", capEXEC, capabilities(res.Findings))
	assert.Assert(t, !hasCapability(res.Findings, "NETWORK"),
		"poisoned does not use the network; got %v", capabilities(res.Findings))

	for _, f := range res.Findings {
		assert.Equal(t, f.Module, poisonedMod, "every finding must be attributed; path=%v", pathOf(f))
		assert.Assert(t, len(f.Path) > 0)
		assert.Assert(t, strings.HasPrefix(f.Path[0].Package, poisonedMod),
			"witness path must be rooted in the confined module; path=%v", pathOf(f))
	}

	assert.DeepEqual(t, res.ModulePackages, map[string][]string{
		poisonedMod: {poisonedMod},
	})
}

// TestUnusedConfinedModule: a confined module that contributes no packages to
// the build yields no findings and no ModulePackages entry — the signal the
// policy layer turns into an "unused" verdict.
func TestUnusedConfinedModule(t *testing.T) {
	res, err := capslock.Analyze(capslock.Options{
		Dir:             exampleDir(t, "victim"),
		ConfinedModules: []string{"example.com/not-a-dependency"},
	})
	assert.NilError(t, err)
	assert.Equal(t, len(res.Findings), 0)
	assert.Equal(t, len(res.ModulePackages), 0)
}

// TestFallbackQueryRoots: without ConfinedModules, the query is rooted at the
// loaded packages themselves (Capslock's default), useful for exploration.
// Findings are then unattributed.
func TestFallbackQueryRoots(t *testing.T) {
	res, err := capslock.Analyze(capslock.Options{Dir: exampleDir(t, "poisoned")})
	assert.NilError(t, err)
	assert.Assert(t, hasCapability(res.Findings, capEXEC),
		"expected %s; got %v", capEXEC, capabilities(res.Findings))
	for _, f := range res.Findings {
		assert.Equal(t, f.Module, "")
	}
}

func capabilities(findings []capslock.Finding) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, f := range findings {
		if _, ok := seen[f.Capability]; ok {
			continue
		}
		seen[f.Capability] = struct{}{}
		out = append(out, f.Capability)
	}
	return out
}

func pathOf(f capslock.Finding) string {
	var frames []string
	for _, fr := range f.Path {
		frames = append(frames, fr.Name)
	}
	return strings.Join(frames, " -> ")
}

// TestAnalyzeIgnoresAmbientTarget: the load environment pins the resolved
// GOOS/GOARCH explicitly, so ambient variables must not select a different
// (or, as here, invalid) target than the documented host default.
func TestAnalyzeIgnoresAmbientTarget(t *testing.T) {
	t.Setenv("GOOS", "bogus")
	t.Setenv("GOARCH", "bogus")
	res, err := capslock.Analyze(capslock.Options{
		Dir:             exampleDir(t, "victim"),
		ConfinedModules: []string{poisonedMod},
	})
	assert.NilError(t, err)
	assert.Assert(t, hasCapability(res.Findings, capEXEC),
		"expected %s; got %v", capEXEC, capabilities(res.Findings))
	assert.Equal(t, os.Getenv("GOOS"), "bogus", "ambient environment must be restored after Analyze")
	assert.Equal(t, os.Getenv("GOARCH"), "bogus", "ambient environment must be restored after Analyze")
}

// TestHigherOrderFDMethodCallback: (*os.File).ReadFrom invokes the supplied
// io.Reader (via the io.Copy fallback), so classifying it SAFE would
// SILENTLY sever the analyzer's only path from a confined module to a
// malicious reader supplied from the module's own dependency cone — an
// attack carried entirely in code the module ships, squarely inside the
// threat model. The exported method must stay analyzed; only the FD-to-FD
// fast path is SAFE. The chain deliberately ends at io.Copy, which the
// pinned Capslock marks "unanalyzed" (following its dispatch would blame
// every io.Copy caller for every reader in the cone, VTA being
// context-insensitive), so the callback surfaces as an UNANALYZED caveat:
// a WARN naming the module, a FAIL under --strict — never a silent pass.
func TestHigherOrderFDMethodCallback(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		assert.NilError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		assert.NilError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	write("evilreader/go.mod", "module example.com/evilreader\n\ngo 1.23\n")
	write("evilreader/reader.go", `package evilreader

import "os/exec"

type Reader struct{}

func New() *Reader { return &Reader{} }

func (*Reader) Read(p []byte) (int, error) {
	if err := exec.Command("true").Run(); err != nil {
		return 0, err
	}
	return 0, nil
}
`)
	write("wrapper/go.mod", "module example.com/wrapper\n\ngo 1.23\n\nrequire example.com/evilreader v0.0.0\n")
	write("wrapper/wrapper.go", `package wrapper

import (
	"os"

	"example.com/evilreader"
)

// Slurp only touches an already-held file handle, but the reader it wires
// in comes from its own dependency and execs on Read.
func Slurp() {
	_, _ = os.Stdin.ReadFrom(evilreader.New())
}
`)
	write("app/go.mod", `module example.com/app

go 1.23

require example.com/wrapper v0.0.0 // gomodjail:confined

require example.com/evilreader v0.0.0 // indirect

replace (
	example.com/evilreader => ../evilreader
	example.com/wrapper => ../wrapper
)
`)
	write("app/main.go", `package main

import "example.com/wrapper"

func main() { wrapper.Slurp() }
`)
	res, err := capslock.Analyze(capslock.Options{
		Dir:             filepath.Join(root, "app"),
		ConfinedModules: []string{"example.com/wrapper"},
	})
	assert.NilError(t, err)
	assert.Assert(t, hasCapability(res.Findings, "UNANALYZED"),
		"the ReadFrom callback must surface at least as an UNANALYZED caveat; got %v", capabilities(res.Findings))
}
