package capslock_test

import (
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
