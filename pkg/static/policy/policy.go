// Package policy is gomodjail's per-confined-module gate: it turns Capslock's
// module-rooted capability findings (obtained via pkg/static/capslock) into
// one verdict per confined module.
//
// This is the novel, gomodjail-specific layer the design calls out: Capslock
// answers "what capabilities does this module's code reach, and by what path";
// this package answers "is that acceptable for a module the user marked
// // gomodjail:confined."
//
// Severity model (design v3). Capability classes fall into three tiers,
// chosen to match what dynamic mode actually enforced (syscalls) while
// staying honest about what static analysis can and cannot prove:
//
//   - Deny: real, dangerous behavior visible in the call graph — filesystem,
//     network, exec, raw syscalls, OS state, cgo. Reaching one of these is a
//     VIOLATION and fails the gate. Dynamic mode blocked exactly these at the
//     syscall boundary.
//   - Caveat: analysis-confidence downgrades — reflect, unsafe.Pointer,
//     assembly//go:linkname (ARBITRARY_EXECUTION), and paths Capslock could
//     not follow. These are not proven misbehavior (dynamic mode never
//     blocked them; essentially every marshaling library reaches reflect via
//     encoding/json, and every optimized hash library ships assembly), but
//     they mean the absence of a Deny finding is not a proof. Reported loudly
//     as warnings; promoted to violations under strict mode.
//   - Allow: benign for a confined module — SAFE, reading system state
//     (os.Getenv), runtime introspection. Dynamic mode never blocked these
//     either (they do not hit a filtered syscall).
//
// Posture: fail closed at the vocabulary level. A capability class this
// package does not know (e.g. introduced by a future Capslock version) is
// treated as Deny until reviewed, never silently allowed.
package policy

import (
	"sort"
	"strings"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
)

// Capslock capability-class names, in the short form reported by
// capslock.Finding.Capability (Capslock's CapabilityName, without the proto
// "CAPABILITY_" prefix). Enumerated here so the gate's vocabulary is auditable
// in one place; Capslock documents these names as unstable until its 1.0
// release, hence the pinned dependency.
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

// Severity is the tier a capability class falls into for a confined module.
type Severity int

const (
	// SeverityAllow: benign for a confined module; not reported.
	SeverityAllow Severity = iota
	// SeverityCaveat: not misbehavior, but defeats static verification.
	// Reported as a warning; a violation under strict mode.
	SeverityCaveat
	// SeverityDeny: dangerous behavior. Always a violation.
	SeverityDeny
)

func (s Severity) String() string {
	switch s {
	case SeverityAllow:
		return "allow"
	case SeverityCaveat:
		return "caveat"
	case SeverityDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// defaultSeverity is the built-in tier of every known capability class.
// Anything absent from this map is Deny (fail closed).
//
// ARBITRARY_EXECUTION is a caveat, not a violation: Capslock assigns it to
// hand-written assembly and //go:linkname — code the analyzer cannot inspect.
// That is the same epistemic status as unsafe/reflect ("cannot be verified"),
// not evidence of process execution (which is EXEC). Treating it as Deny
// fails every optimized hash/compression library (xxhash, blake3, klauspost)
// that dynamic mode confined without trouble.
var defaultSeverity = map[capslock.Capability]Severity{
	CapSafe:               SeverityAllow,
	CapReadSystemState:    SeverityAllow,
	CapRuntime:            SeverityAllow,
	CapReflect:            SeverityCaveat,
	CapUnsafePointer:      SeverityCaveat,
	CapUnanalyzed:         SeverityCaveat,
	CapArbitraryExecution: SeverityCaveat,
	CapFiles:              SeverityDeny,
	CapNetwork:            SeverityDeny,
	CapExec:               SeverityDeny,
	CapSystemCalls:        SeverityDeny,
	CapOperatingSystem:    SeverityDeny,
	CapModifySystemState:  SeverityDeny,
	CapCGO:                SeverityDeny,
}

// Policy maps capability classes to severities for confined modules.
type Policy struct {
	severity map[capslock.Capability]Severity
}

// Default returns the built-in policy described in the package comment.
func Default() *Policy {
	m := make(map[capslock.Capability]Severity, len(defaultSeverity))
	for k, v := range defaultSeverity {
		m[k] = v
	}
	return &Policy{severity: m}
}

// Severity returns the tier of the given capability class. Hierarchical
// names (e.g. "MODIFY_SYSTEM_STATE/SIGNALS") fall back to their top-level
// class when the full name has no explicit entry. Unknown classes are Deny
// (fail closed); only the empty string and SAFE are inherently Allow.
func (pol *Policy) Severity(capability capslock.Capability) Severity {
	if capability == "" || capability == CapSafe {
		return SeverityAllow
	}
	if s, ok := pol.severity[capability]; ok {
		return s
	}
	if top, _, found := strings.Cut(capability, "/"); found {
		if s, ok := pol.severity[top]; ok {
			return s
		}
	}
	return SeverityDeny
}

// Witness is one reachable capability with a representative call path,
// rooted at a function the confined module owns.
type Witness struct {
	Capability capslock.Capability `json:"capability"`
	Path       []capslock.FuncRef  `json:"path,omitempty"`
}

// ModuleReport is the verdict for one confined module.
type ModuleReport struct {
	// Module is the confined module path from go.mod.
	Module string `json:"module"`
	// Packages are the module's packages found in the analyzed program.
	Packages []string `json:"packages,omitempty"`
	// Unused is true when no package of the module is in the build: there is
	// nothing to verify (and nothing that can run).
	Unused bool `json:"unused,omitempty"`
	// Violations are Deny-tier capabilities the module reaches, one witness
	// per capability class (the shortest path found).
	Violations []Witness `json:"violations,omitempty"`
	// Caveats are Caveat-tier capabilities the module reaches. They do not
	// fail the gate by default but mean the verdict is best-effort.
	Caveats []Witness `json:"caveats,omitempty"`
}

// OK reports whether the module passed (possibly with caveats).
func (r *ModuleReport) OK() bool {
	return len(r.Violations) == 0
}

// Evaluate aggregates module-rooted findings into one report per confined
// module. For each (module, capability) pair the shortest witness path is
// kept: the goal is one auditable piece of evidence per fact, not an
// exhaustive path inventory.
//
// pol may be nil, in which case Default() is used. The returned reports are
// sorted by module path and include an entry for every confined module, even
// unused ones (so a stale annotation is visible rather than silently passing).
func Evaluate(confinedModules []string, res *capslock.Result, pol *Policy) []ModuleReport {
	if pol == nil {
		pol = Default()
	}
	// witness[module][capability] = shortest path seen so far
	witness := make(map[string]map[capslock.Capability]Witness)
	for _, f := range res.Findings {
		if f.Module == "" {
			continue // not attributed to a confined module
		}
		if pol.Severity(f.Capability) == SeverityAllow {
			continue
		}
		byCap := witness[f.Module]
		if byCap == nil {
			byCap = make(map[capslock.Capability]Witness)
			witness[f.Module] = byCap
		}
		if w, ok := byCap[f.Capability]; !ok || len(f.Path) < len(w.Path) {
			byCap[f.Capability] = Witness{Capability: f.Capability, Path: f.Path}
		}
	}

	reports := make([]ModuleReport, 0, len(confinedModules))
	for _, mod := range confinedModules {
		r := ModuleReport{
			Module:   mod,
			Packages: res.ModulePackages[mod],
			Unused:   len(res.ModulePackages[mod]) == 0,
		}
		for _, w := range sortedWitnesses(witness[mod]) {
			switch pol.Severity(w.Capability) {
			case SeverityDeny:
				r.Violations = append(r.Violations, w)
			case SeverityCaveat:
				r.Caveats = append(r.Caveats, w)
			}
		}
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Module < reports[j].Module })
	return reports
}

func sortedWitnesses(byCap map[capslock.Capability]Witness) []Witness {
	out := make([]Witness, 0, len(byCap))
	for _, w := range byCap {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Capability < out[j].Capability })
	return out
}
