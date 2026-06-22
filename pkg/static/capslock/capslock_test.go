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

	poisonedPkg = "github.com/AkihiroSuda/gomodjail/examples/poisoned"
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

// pathTouchesPackage reports whether any frame of the call path is owned by the
// given package path (exact match or a sub-package). This mirrors the
// module-ownership test the policy layer (M2) will use to attribute a
// capability to a confined module.
func pathTouchesPackage(f capslock.Finding, pkgPrefix string) bool {
	for _, fr := range f.Path {
		p := fr.Package
		if p == pkgPrefix || strings.HasPrefix(p, pkgPrefix+"/") {
			return true
		}
		// Fall back to the qualified function name when the per-frame package
		// path is unavailable (older Capslock shapes omit Function.Package).
		if strings.HasPrefix(fr.Name, pkgPrefix+".") || strings.HasPrefix(fr.Name, "("+pkgPrefix+".") {
			return true
		}
	}
	return false
}

// TestPoisonedSurfacesExec is the headline M1 assertion: the "malicious vi"
// path in examples/poisoned must surface as an EXEC capability. This is the
// static analog of the dynamic mode's "Blocked syscall" demo.
func TestPoisonedSurfacesExec(t *testing.T) {
	res, err := capslock.Analyze(capslock.Options{Dir: exampleDir(t, "poisoned")})
	assert.NilError(t, err)
	assert.Assert(t, len(res.Findings) > 0, "expected at least one capability finding")

	assert.Assert(t, hasCapability(res.Findings, capEXEC),
		"expected %s from the os/exec.Command call; got %v", capEXEC, capabilities(res.Findings))

	// Specificity sanity check: poisoned does no networking, so the classifier
	// must not be indiscriminately reporting every capability.
	assert.Assert(t, !hasCapability(res.Findings, "NETWORK"),
		"poisoned does not use the network; got %v", capabilities(res.Findings))
}

// TestVictimAttributesExecThroughPoisoned confirms the transitive attribution
// that the per-module policy gate depends on: victim's own code is benign
// (it only calls fmt and poisoned.Add), but the EXEC capability is reachable
// and its call path passes through the poisoned package.
func TestVictimAttributesExecThroughPoisoned(t *testing.T) {
	res, err := capslock.Analyze(capslock.Options{Dir: exampleDir(t, "victim")})
	assert.NilError(t, err)
	assert.Assert(t, len(res.Findings) > 0, "expected at least one capability finding")

	var execFindings []capslock.Finding
	for _, f := range res.Findings {
		if f.Capability == capEXEC {
			execFindings = append(execFindings, f)
		}
	}
	assert.Assert(t, len(execFindings) > 0,
		"expected %s reachable from victim; got %v", capEXEC, capabilities(res.Findings))

	attributed := false
	for _, f := range execFindings {
		if pathTouchesPackage(f, poisonedPkg) {
			attributed = true
			break
		}
	}
	assert.Assert(t, attributed,
		"expected an EXEC call path through %q; paths=%v", poisonedPkg, paths(execFindings))
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

func paths(findings []capslock.Finding) []string {
	var out []string
	for _, f := range findings {
		var frames []string
		for _, fr := range f.Path {
			frames = append(frames, fr.Name)
		}
		out = append(out, strings.Join(frames, " -> "))
	}
	return out
}
