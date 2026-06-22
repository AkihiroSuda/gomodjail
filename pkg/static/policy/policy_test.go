package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/mod/modfile"
	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/fromgomod"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

const (
	victimMod   = "github.com/AkihiroSuda/gomodjail/examples/victim"
	poisonedMod = "github.com/AkihiroSuda/gomodjail/examples/poisoned"
)

// profileWith builds a profile rooted at mainMod with the given per-module
// policies, mimicking what fromgomod produces from a go.mod.
func profileWith(mainMod string, mods map[string]profile.Policy) *profile.Profile {
	prof := profile.New()
	prof.Module = mainMod
	for m, p := range mods {
		prof.Modules[m] = p
	}
	return prof
}

// execFindingThroughPoisoned is a synthetic finding mirroring the shape
// Capslock produces for the victim analysis: victim.main -> poisoned.Add ->
// os/exec.Command, classified EXEC.
func execFindingThroughPoisoned() capslock.Finding {
	return capslock.Finding{
		Capability:  policy.CapExec,
		PackageName: victimMod,
		Path: []capslock.FuncRef{
			{Name: victimMod + ".main", Package: victimMod},
			{Name: poisonedMod + ".Add", Package: poisonedMod},
			{Name: "os/exec.Command", Package: "os/exec"},
		},
	}
}

func TestCheckAttributesToConfinedModule(t *testing.T) {
	prof := profileWith(victimMod, map[string]profile.Policy{
		poisonedMod: profile.PolicyConfined,
	})
	vs := policy.Check(prof, []capslock.Finding{execFindingThroughPoisoned()}, policy.Strict())
	assert.Equal(t, len(vs), 1)
	assert.Equal(t, vs[0].Module, poisonedMod)
	assert.Equal(t, vs[0].Capability, policy.CapExec)
	assert.Equal(t, vs[0].OwnerIndex, 1) // the poisoned.Add frame
}

func TestCheckIgnoresUnconfinedReach(t *testing.T) {
	// EXEC is reachable, but no module is confined: not a violation. The gate
	// fires only for modules the policy actually confines.
	prof := profileWith(victimMod, nil)
	vs := policy.Check(prof, []capslock.Finding{execFindingThroughPoisoned()}, policy.Strict())
	assert.Equal(t, len(vs), 0)

	// Explicitly unconfined is likewise not a violation.
	prof = profileWith(victimMod, map[string]profile.Policy{
		poisonedMod: profile.PolicyUnconfined,
	})
	vs = policy.Check(prof, []capslock.Finding{execFindingThroughPoisoned()}, policy.Strict())
	assert.Equal(t, len(vs), 0)
}

func TestCheckTransitiveThroughConfinedCaller(t *testing.T) {
	// If victim itself is confined, the EXEC it reaches *through* poisoned is
	// still attributed to victim: capability flows through calls regardless of
	// the callee's label (design §12 Q3).
	prof := profileWith(victimMod, map[string]profile.Policy{
		victimMod: profile.PolicyConfined,
	})
	vs := policy.Check(prof, []capslock.Finding{execFindingThroughPoisoned()}, policy.Strict())
	assert.Equal(t, len(vs), 1)
	assert.Equal(t, vs[0].Module, victimMod)
	assert.Equal(t, vs[0].OwnerIndex, 0) // victim.main, the first owned frame
}

func TestCheckAllowedCapabilityPasses(t *testing.T) {
	prof := profileWith(victimMod, map[string]profile.Policy{
		poisonedMod: profile.PolicyConfined,
	})
	// A policy that permits EXEC yields no violation for an EXEC finding.
	vs := policy.Check(prof, []capslock.Finding{execFindingThroughPoisoned()}, policy.Allowing(policy.CapExec))
	assert.Equal(t, len(vs), 0)
}

func TestCheckMethodFrameAttribution(t *testing.T) {
	// Methods are formatted "(*pkg.Type).Method"; the leading "(" defeats name
	// prefix matching, so attribution must succeed via the frame's Package.
	f := capslock.Finding{
		Capability:  policy.CapFiles,
		PackageName: victimMod,
		Path: []capslock.FuncRef{
			{Name: "(*" + poisonedMod + ".Writer).Write", Package: poisonedMod},
			{Name: "(*os.File).Write", Package: "os"},
		},
	}
	prof := profileWith(victimMod, map[string]profile.Policy{
		poisonedMod: profile.PolicyConfined,
	})
	vs := policy.Check(prof, []capslock.Finding{f}, policy.Strict())
	assert.Equal(t, len(vs), 1)
	assert.Equal(t, vs[0].Module, poisonedMod)
	assert.Equal(t, vs[0].OwnerIndex, 0)
}

func TestStrictPolicyDeniesEverythingButSafe(t *testing.T) {
	pol := policy.Strict()
	for _, c := range []string{policy.CapExec, policy.CapFiles, policy.CapNetwork,
		policy.CapSystemCalls, policy.CapCGO, policy.CapUnsafePointer, policy.CapReflect,
		policy.CapUnanalyzed, "SOME_FUTURE_CAPABILITY"} {
		assert.Assert(t, pol.Denies(c), "strict policy must deny %q", c)
	}
	assert.Assert(t, !pol.Denies(policy.CapSafe), "SAFE must not be a violation")
	assert.Assert(t, !pol.Denies(""), "empty capability must not be a violation")
}

// TestGateOverVictim is the M2 integration test: run the real Capslock
// analysis over examples/victim with the policy parsed from its go.mod (which
// marks poisoned confined) and assert the EXEC capability is gated, attributed
// to the poisoned module, with a call path that runs through it.
func TestGateOverVictim(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "examples", "victim"))
	assert.NilError(t, err)

	prof := profileFromGoMod(t, filepath.Join(dir, "go.mod"))
	assert.Equal(t, prof.Module, victimMod)
	assert.Equal(t, prof.Modules[poisonedMod], profile.PolicyConfined)

	res, err := capslock.Analyze(capslock.Options{Dir: dir})
	assert.NilError(t, err)

	vs := policy.Check(prof, res.Findings, policy.Strict())
	assert.Assert(t, len(vs) > 0, "expected at least one violation for confined poisoned module")

	var exec *policy.Violation
	for i := range vs {
		if vs[i].Capability == policy.CapExec && vs[i].Module == poisonedMod {
			exec = &vs[i]
			break
		}
	}
	assert.Assert(t, exec != nil, "expected an EXEC violation attributed to %q; got %+v", poisonedMod, vs)
	assert.Assert(t, exec.OwnerIndex >= 0 && exec.OwnerIndex < len(exec.Path))
	assert.Equal(t, exec.Path[exec.OwnerIndex].Package, poisonedMod)

	// Same findings, but with poisoned NOT confined: no violations. Confirms
	// the gate is driven by the go.mod policy, not by reachability alone.
	clean := profileWith(victimMod, nil)
	assert.Equal(t, len(policy.Check(clean, res.Findings, policy.Strict())), 0)
}

func profileFromGoMod(t *testing.T, path string) *profile.Profile {
	t.Helper()
	b, err := os.ReadFile(path)
	assert.NilError(t, err)
	mf, err := modfile.Parse(path, b, nil)
	assert.NilError(t, err)
	prof := profile.New()
	assert.NilError(t, fromgomod.FromGoMod(mf, prof))
	return prof
}
