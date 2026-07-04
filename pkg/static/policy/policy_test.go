package policy_test

import (
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

const (
	yamlMod     = "sigs.k8s.io/yaml"
	poisonedMod = "github.com/AkihiroSuda/gomodjail/examples/poisoned"
)

func refs(names ...string) []capslock.FuncRef {
	out := make([]capslock.FuncRef, 0, len(names))
	for _, n := range names {
		out = append(out, capslock.FuncRef{Name: n})
	}
	return out
}

func result(findings []capslock.Finding, modulePackages map[string][]string) *capslock.Result {
	return &capslock.Result{Findings: findings, ModulePackages: modulePackages}
}

func TestSeverityTiers(t *testing.T) {
	pol := policy.Default()
	for _, c := range []string{policy.CapFiles, policy.CapNetwork, policy.CapExec,
		policy.CapSystemCalls, policy.CapOperatingSystem, policy.CapModifySystemState,
		policy.CapCGO} {
		assert.Equal(t, pol.Severity(c), policy.SeverityDeny, "capability %s", c)
	}
	for _, c := range []string{policy.CapReflect, policy.CapUnsafePointer,
		policy.CapUnanalyzed, policy.CapArbitraryExecution} {
		assert.Equal(t, pol.Severity(c), policy.SeverityCaveat, "capability %s", c)
	}
	for _, c := range []string{policy.CapSafe, policy.CapReadSystemState, policy.CapRuntime, ""} {
		assert.Equal(t, pol.Severity(c), policy.SeverityAllow, "capability %q", c)
	}
}

// TestSeverityHierarchicalNames: Capslock reports refined classes like
// "MODIFY_SYSTEM_STATE/SIGNALS"; they inherit the top-level class's tier
// unless explicitly mapped.
func TestSeverityHierarchicalNames(t *testing.T) {
	pol := policy.Default()
	assert.Equal(t, pol.Severity("MODIFY_SYSTEM_STATE/SIGNALS"), policy.SeverityDeny)
	assert.Equal(t, pol.Severity("MODIFY_SYSTEM_STATE/ENV"), policy.SeverityDeny)
	assert.Equal(t, pol.Severity("SOME_FUTURE/THING"), policy.SeverityDeny)
}

// TestSeverityFailClosed: a capability class this package does not know (e.g.
// introduced by a future Capslock release) must be denied, never allowed.
func TestSeverityFailClosed(t *testing.T) {
	assert.Equal(t, policy.Default().Severity("SOME_FUTURE_CAPABILITY"), policy.SeverityDeny)
}

func TestEvaluateViolation(t *testing.T) {
	res := result([]capslock.Finding{
		{Capability: policy.CapExec, Module: poisonedMod, Package: poisonedMod,
			Path: refs(poisonedMod+".Add", "os/exec.Command")},
	}, map[string][]string{poisonedMod: {poisonedMod}})

	reports := policy.Evaluate([]string{poisonedMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	r := reports[0]
	assert.Assert(t, !r.OK())
	assert.Equal(t, len(r.Violations), 1)
	assert.Equal(t, r.Violations[0].Capability, policy.CapExec)
	assert.Equal(t, len(r.Caveats), 0)
}

// TestEvaluateCaveat: reflect/unsafe are warnings, not violations — a yaml
// parser that does pure computation must pass the default gate (this is the
// nerdctl regression: 33/33 confined modules failed when REFLECT was a hard
// failure, because anything touching encoding/json reaches reflect).
func TestEvaluateCaveat(t *testing.T) {
	res := result([]capslock.Finding{
		{Capability: policy.CapReflect, Module: yamlMod, Package: yamlMod,
			Path: refs(yamlMod+".Unmarshal", "reflect.ValueOf")},
		{Capability: policy.CapUnsafePointer, Module: yamlMod, Package: yamlMod,
			Path: refs(yamlMod + ".convert")},
	}, map[string][]string{yamlMod: {yamlMod}})

	reports := policy.Evaluate([]string{yamlMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	r := reports[0]
	assert.Assert(t, r.OK(), "caveats alone must not fail the default gate")
	assert.Equal(t, len(r.Violations), 0)
	assert.Equal(t, len(r.Caveats), 2)
	assert.Equal(t, r.Caveats[0].Capability, policy.CapReflect)
	assert.Equal(t, r.Caveats[1].Capability, policy.CapUnsafePointer)
}

func TestEvaluateAllowedCapabilitiesIgnored(t *testing.T) {
	res := result([]capslock.Finding{
		{Capability: policy.CapReadSystemState, Module: yamlMod, Package: yamlMod, Path: refs(yamlMod + ".getenv")},
		{Capability: policy.CapRuntime, Module: yamlMod, Package: yamlMod, Path: refs(yamlMod + ".stats")},
	}, map[string][]string{yamlMod: {yamlMod}})

	reports := policy.Evaluate([]string{yamlMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	assert.Assert(t, reports[0].OK())
	assert.Equal(t, len(reports[0].Caveats), 0)
}

// TestEvaluateShortestWitness: multiple findings for the same (module,
// capability) collapse to one witness, keeping the shortest path. This is the
// aggregation that turns thousands of near-duplicate path reports into one
// auditable piece of evidence per fact.
func TestEvaluateShortestWitness(t *testing.T) {
	long := refs(poisonedMod+".A", poisonedMod+".B", poisonedMod+".C", "os/exec.Command")
	short := refs(poisonedMod+".Add", "os/exec.Command")
	res := result([]capslock.Finding{
		{Capability: policy.CapExec, Module: poisonedMod, Package: poisonedMod + "/a", Path: long},
		{Capability: policy.CapExec, Module: poisonedMod, Package: poisonedMod + "/b", Path: short},
	}, map[string][]string{poisonedMod: {poisonedMod + "/a", poisonedMod + "/b"}})

	reports := policy.Evaluate([]string{poisonedMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	assert.Equal(t, len(reports[0].Violations), 1)
	assert.Equal(t, len(reports[0].Violations[0].Path), len(short))
}

// TestEvaluateUnusedModule: a confined module with no packages in the build
// gets an explicit "unused" report rather than silently passing, so stale
// annotations stay visible.
func TestEvaluateUnusedModule(t *testing.T) {
	reports := policy.Evaluate([]string{"example.com/unused"}, result(nil, nil), nil)
	assert.Equal(t, len(reports), 1)
	assert.Assert(t, reports[0].OK())
	assert.Assert(t, reports[0].Unused)
}

// TestEvaluateUnattributedFindingsIgnored: findings without a module (from a
// non-module-rooted analysis) must not pollute the per-module reports.
func TestEvaluateUnattributedFindingsIgnored(t *testing.T) {
	res := result([]capslock.Finding{
		{Capability: policy.CapExec, Module: "", Package: "example.com/other", Path: refs("other.F")},
	}, map[string][]string{poisonedMod: {poisonedMod}})
	reports := policy.Evaluate([]string{poisonedMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	assert.Assert(t, reports[0].OK())
}

func TestEvaluateReportsSorted(t *testing.T) {
	reports := policy.Evaluate([]string{"z.example.com/b", "a.example.com/a"}, result(nil, nil), nil)
	assert.Equal(t, len(reports), 2)
	assert.Equal(t, reports[0].Module, "a.example.com/a")
	assert.Equal(t, reports[1].Module, "z.example.com/b")
}

// TestGateOverVictim is the end-to-end policy test: run the real Capslock
// analysis over examples/victim rooted at the confined poisoned module, and
// assert the verdict is a FAIL with an EXEC witness path that starts inside
// poisoned (not at victim's entry points).
func TestGateOverVictim(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "examples", "victim"))
	assert.NilError(t, err)

	res, err := capslock.Analyze(capslock.Options{
		Dir:             dir,
		ConfinedModules: []string{poisonedMod},
	})
	assert.NilError(t, err)
	assert.Assert(t, len(res.ModulePackages[poisonedMod]) > 0,
		"poisoned must be found in victim's build; got %v", res.ModulePackages)

	reports := policy.Evaluate([]string{poisonedMod}, res, nil)
	assert.Equal(t, len(reports), 1)
	r := reports[0]
	assert.Assert(t, !r.OK(), "poisoned must fail the gate; got %+v", r)

	var exec *policy.Witness
	for i := range r.Violations {
		if r.Violations[i].Capability == policy.CapExec {
			exec = &r.Violations[i]
			break
		}
	}
	assert.Assert(t, exec != nil, "expected an EXEC violation; got %+v", r.Violations)
	assert.Assert(t, len(exec.Path) > 0)
	assert.Equal(t, exec.Path[0].Package, poisonedMod,
		"witness path must be rooted inside the confined module")
}
