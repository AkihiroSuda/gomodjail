// Package policy is gomodjail's per-confined-module gate: it turns Capslock's
// unfiltered capability findings (obtained via pkg/static/capslock) into
// pass/fail verdicts driven by the // gomodjail:confined annotations parsed
// from go.mod (pkg/profile).
//
// This is the novel, gomodjail-specific layer the design calls out: Capslock
// answers "what capabilities does this program reach, and by what path"; this
// package answers "does a *confined module* reach a *disallowed* capability."
// The framing — restrict to call-graph frames owned by a confined module, then
// check reachability to a denied sink — is the part Capslock does not provide.
//
// Posture: fail closed. A capability class is a violation unless it is
// explicitly allowed, so a class introduced by a future Capslock version is
// denied until reviewed rather than silently permitted.
package policy

import (
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
)

// Capslock capability-class names, in the short form reported by
// capslock.Finding.Capability (Capslock's CapabilityName, without the proto
// "CAPABILITY_" prefix). Enumerated here so the gate's vocabulary is auditable
// in one place; Capslock documents these names as unstable until its 1.0
// release, hence the pinned dependency.
//
// These map onto the gomodjail confinement intents from the design:
//   - no filesystem    => CapFiles
//   - no process exec  => CapExec, CapArbitraryExecution
//   - no raw syscalls  => CapSystemCalls
//   - no network       => CapNetwork
//   - unanalyzable     => CapCGO, CapUnsafePointer, CapReflect,
//     CapArbitraryExecution, CapUnanalyzed
const (
	CapSafe               = "SAFE"
	CapFiles              = "FILES"
	CapNetwork            = "NETWORK"
	CapExec               = "EXEC"
	CapSystemCalls        = "SYSTEM_CALLS"
	CapOperatingSystem    = "OPERATING_SYSTEM"
	CapArbitraryExecution = "ARBITRARY_EXECUTION"
	CapCGO                = "CGO"
	CapUnsafePointer      = "UNSAFE_POINTER"
	CapReflect            = "REFLECT"
	CapUnanalyzed         = "UNANALYZED"
	CapRuntime            = "RUNTIME"
	CapReadSystemState    = "READ_SYSTEM_STATE"
	CapModifySystemState  = "MODIFY_SYSTEM_STATE"
)

// Policy decides which capability classes a confined module may still reach.
//
// The zero value denies everything (the strict default — see Strict). A
// capability is allowed only if it appears in Allowed; SAFE and the empty
// capability are never violations.
type Policy struct {
	// Allowed is the set of capability-class names a confined module may
	// reach. Anything not in this set is a violation.
	Allowed map[string]struct{}
}

// EscapeHatchCapabilities are the capability classes that defeat sound static
// analysis: each can manufacture a call the call graph cannot see — cgo and
// assembly, unsafe.Pointer arithmetic, reflective dispatch, //go:linkname
// targets, arbitrary execution, or a path Capslock gave up following
// (UNANALYZED). A confined module that reaches any of them cannot be vouched
// for, so they are denied unconditionally: even a capability-scoped policy that
// permits other classes can never permit these (design §5.3, "unanalyzable ⇒
// fail").
var EscapeHatchCapabilities = map[string]struct{}{
	CapCGO:                {},
	CapUnsafePointer:      {},
	CapReflect:            {},
	CapArbitraryExecution: {},
	CapUnanalyzed:         {},
}

// IsEscapeHatch reports whether reaching the capability class makes a confined
// module unanalyzable, and therefore an unconditional lint failure.
func IsEscapeHatch(capability string) bool {
	_, ok := EscapeHatchCapabilities[capability]
	return ok
}

// Strict returns the default policy: deny every capability class. This is the
// meaning of a bare "// gomodjail:confined" annotation. Capability-scoped
// relaxations (e.g. confined=fs-read) are deferred to a later milestone.
func Strict() *Policy {
	return &Policy{Allowed: map[string]struct{}{}}
}

// Allowing returns a policy that permits exactly the given capability classes
// (and denies the rest). Useful for tests and, later, capability-scoped
// policies.
func Allowing(caps ...string) *Policy {
	allowed := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		allowed[c] = struct{}{}
	}
	return &Policy{Allowed: allowed}
}

// Denies reports whether reaching the given capability class is a violation
// for a confined module under this policy.
func (pol *Policy) Denies(capability string) bool {
	if capability == "" || capability == CapSafe {
		return false
	}
	if IsEscapeHatch(capability) {
		return true
	}
	_, ok := pol.Allowed[capability]
	return !ok
}

// Violation is a single denied capability reachable from a confined module.
type Violation struct {
	// Module is the confined module the capability is attributed to (the
	// module that owns a frame on the call path).
	Module string
	// Capability is the denied capability-class name (e.g. "EXEC").
	Capability string
	// PackageName is the queried package the finding was reported for.
	PackageName string
	// Path is the call chain from a queried entrypoint to the sink, exactly
	// as Capslock computed it. The frame owned by Module sits at OwnerIndex.
	Path []capslock.FuncRef
	// OwnerIndex is the index into Path of the first Module-owned frame.
	OwnerIndex int
}

// Check applies prof's confinement policy to a set of Capslock findings and
// returns every violation.
//
// A finding is a violation when (a) its capability class is denied by pol and
// (b) some frame on its call path is owned by a module marked confined in
// prof. Attribution is transitive by construction: if a confined module's
// frame lies anywhere on a path that reaches a denied sink, the module can
// reach that sink — regardless of whether the intervening callees are
// themselves confined (design §12 Q3).
//
// pol may be nil, in which case Strict() is used.
func Check(prof *profile.Profile, findings []capslock.Finding, pol *Policy) []Violation {
	if pol == nil {
		pol = Strict()
	}
	var violations []Violation
	for _, f := range findings {
		if !pol.Denies(f.Capability) {
			continue
		}
		conf, idx := attribute(prof, f)
		if conf == nil {
			continue
		}
		violations = append(violations, Violation{
			Module:      conf.Module,
			Capability:  f.Capability,
			PackageName: f.PackageName,
			Path:        f.Path,
			OwnerIndex:  idx,
		})
	}
	return violations
}

// attribute finds the first frame on the finding's path that is owned by a
// confined module, returning that confinement and the frame index. It reuses
// profile.Confined for the module-ownership test so static and dynamic modes
// agree on what "belongs to module M" means.
func attribute(prof *profile.Profile, f capslock.Finding) (*profile.Confinment, int) {
	for i, fr := range f.Path {
		for _, sym := range frameSymbols(fr) {
			if c := prof.Confined(prof.Module, sym); c != nil {
				return c, i
			}
		}
	}
	return nil, -1
}

// frameSymbols yields the symbol strings to test a frame against
// profile.Confined, most specific first. The package path is preferred because
// it matches reliably even for methods, whose qualified names Capslock formats
// as "(*pkg.Type).Method" (a leading "(" that defeats prefix matching). The
// function name is a fallback for older Capslock shapes that omit the per-frame
// package.
func frameSymbols(fr capslock.FuncRef) []string {
	var syms []string
	if fr.Package != "" {
		syms = append(syms, fr.Package)
	}
	if fr.Name != "" {
		syms = append(syms, fr.Name)
	}
	return syms
}
