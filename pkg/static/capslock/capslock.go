// Package capslock is the single point of contact between gomodjail and
// Google's Capslock (github.com/google/capslock) capability analyzer.
//
// Capslock owns the heavy lifting: it loads packages, builds the SSA program
// and a VTA call graph, and walks transitive calls to a curated set of
// privileged standard-library "sink" symbols, classifying each into a
// capability class (FILES, EXEC, NETWORK, ARBITRARY_EXECUTION, ...).
//
// gomodjail's novel contribution is the policy layer (see pkg/static/policy,
// added in M2), not the analysis. To keep that contribution insulated from
// Capslock's pre-1.0 churn, ALL Capslock and Capslock-proto types are confined
// to this package: callers receive only the gomodjail-local Finding/FuncRef
// types declared below. A breaking Capslock change is therefore a one-package
// fix.
package capslock

import (
	"fmt"
	"os"

	"golang.org/x/tools/go/packages"

	"github.com/google/capslock/analyzer"
	cpb "github.com/google/capslock/proto"
)

// Capability is a Capslock capability-class name, e.g. "CAPABILITY_EXEC".
//
// The string form (rather than Capslock's proto enum) is deliberate: it keeps
// the proto types out of the public API and matches what the policy layer
// reasons about. Capslock documents these names as unstable until its 1.0
// release, which is why the dependency is pinned and vendored.
type Capability = string

// FuncRef is one frame of a call path: a function or method and where it is
// defined. It mirrors the data in Capslock's proto Function without exposing
// the proto type.
type FuncRef struct {
	// Name is the function or method name as Capslock reports it, e.g.
	// "os/exec.Command" or "(*os/exec.Cmd).Run".
	Name string
	// Package is the package path the function belongs to. May be empty for
	// frames Capslock could not attribute to a package.
	Package string
	// Filename, Line and Column locate the definition. Filename may be empty.
	Filename string
	Line     int64
	Column   int64
}

// Finding is a single reachable capability, with the call path that reaches it.
//
// One Capslock CapabilityInfo becomes one Finding. The Path is ordered from a
// queried entrypoint down to the sink; the last frame is (at or near) the
// privileged standard-library call that earns the capability. The policy layer
// uses Path to attribute a capability to a confined module by inspecting which
// frames are owned by that module.
type Finding struct {
	// Capability is the Capslock capability-class name, e.g. "CAPABILITY_EXEC".
	Capability Capability
	// PackageName is the queried package the capability is reported for.
	PackageName string
	// PackageDir is that package's directory on disk, if known.
	PackageDir string
	// Direct is true when the capability comes from a call within
	// PackageName itself, false when it is reached transitively through a
	// dependency.
	Direct bool
	// Path is the call chain from a queried entrypoint to the sink.
	Path []FuncRef
}

// Options configures a single Analyze run.
type Options struct {
	// Dir is the working directory for package loading. For a multi-module
	// layout (such as gomodjail's examples, where victim depends on poisoned
	// via a replace directive) this must be the module root so the module
	// graph and replace directives resolve. Defaults to the process working
	// directory when empty.
	Dir string
	// Patterns are the package patterns to analyze (go/packages syntax).
	// Defaults to []string{"./..."}.
	Patterns []string
	// BuildTags, GOOS and GOARCH select the build configuration to analyze,
	// mirroring Capslock's -buildtags/-goos/-goarch. Empty means host default.
	BuildTags string
	GOOS      string
	GOARCH    string
}

// Result is the structured outcome of an Analyze run.
type Result struct {
	// Findings is every reachable capability Capslock reported, translated
	// into gomodjail-local types.
	Findings []Finding
}

// Analyze loads the requested packages and runs Capslock's capability analysis
// over them, returning the reachable capabilities and their call paths.
//
// It does not apply any policy: it reports what Capslock found, unfiltered.
// Turning findings into pass/fail verdicts per confined module is the job of
// the policy layer built on top of this package.
func Analyze(opts Options) (*Result, error) {
	patterns := opts.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	pkgs, err := loadPackages(opts, patterns)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages matched %v in %q", patterns, opts.Dir)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d error(s) while loading packages %v", n, patterns)
	}

	queried := analyzer.GetQueriedPackages(pkgs)
	cfg := &analyzer.Config{
		// Baseline curated capability map. false => keep the UNANALYZED class,
		// which gomodjail's policy layer treats as a fail-closed signal rather
		// than discarding.
		Classifier: analyzer.GetClassifier(false),
	}

	cil := analyzer.GetCapabilityInfo(pkgs, queried, cfg)
	return &Result{Findings: convertFindings(cil)}, nil
}

// loadPackages builds the go/packages configuration and loads the requested
// patterns. It reuses Capslock's exported load mode (so we feed the analyzer
// exactly what it expects) but constructs the Config directly because
// Capslock's own analyzer.LoadPackages does not expose a Dir, and our examples
// live in sibling modules joined by a replace directive.
func loadPackages(opts Options, patterns []string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: analyzer.PackagesLoadModeNeeded,
		Dir:  opts.Dir,
	}
	if opts.BuildTags != "" {
		cfg.BuildFlags = []string{"-tags=" + opts.BuildTags}
	}
	if opts.GOOS != "" || opts.GOARCH != "" {
		env := append([]string(nil), os.Environ()...)
		if opts.GOOS != "" {
			env = append(env, "GOOS="+opts.GOOS)
		}
		if opts.GOARCH != "" {
			env = append(env, "GOARCH="+opts.GOARCH)
		}
		cfg.Env = env
	}
	return packages.Load(cfg, patterns...)
}

func convertFindings(cil *cpb.CapabilityInfoList) []Finding {
	if cil == nil {
		return nil
	}
	out := make([]Finding, 0, len(cil.GetCapabilityInfo()))
	for _, ci := range cil.GetCapabilityInfo() {
		f := Finding{
			Capability:  capabilityName(ci),
			PackageName: ci.GetPackageName(),
			PackageDir:  ci.GetPackageDir(),
			Direct:      ci.GetCapabilityType() == cpb.CapabilityType_CAPABILITY_TYPE_DIRECT,
		}
		for _, fn := range ci.GetPath() {
			ref := FuncRef{
				Name:    fn.GetName(),
				Package: fn.GetPackage(),
			}
			if site := fn.GetSite(); site != nil {
				ref.Filename = site.GetFilename()
				ref.Line = site.GetLine()
				ref.Column = site.GetColumn()
			}
			f.Path = append(f.Path, ref)
		}
		out = append(out, f)
	}
	return out
}

// capabilityName returns the Capslock capability-class name for a finding,
// preferring the explicit CapabilityName field (present since Capslock v0.3.0)
// and falling back to the enum's name for older shapes.
func capabilityName(ci *cpb.CapabilityInfo) Capability {
	if n := ci.GetCapabilityName(); n != "" {
		return n
	}
	return ci.GetCapability().String()
}
