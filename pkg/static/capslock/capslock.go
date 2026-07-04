// Package capslock is the single point of contact between gomodjail and
// Google's Capslock (github.com/google/capslock) capability analyzer.
//
// Capslock owns the heavy lifting: it loads packages, builds the SSA program
// and a VTA call graph, and walks transitive calls to a curated set of
// privileged standard-library "sink" symbols, classifying each into a
// capability class (FILES, EXEC, NETWORK, ARBITRARY_EXECUTION, ...).
//
// gomodjail's job is to ask the right question. Each confined module is
// analyzed in its own DEPENDENCY SLICE: the packages fed to Capslock are the
// module's packages (which pull in the module's own dependencies and the
// standard library, and nothing else), and the query is rooted at the
// module's packages. Two failure modes of the naive whole-program approach
// are avoided by construction:
//
//   - Rooting the query at the depender produces one finding per
//     (entry point x capability) — thousands of near-duplicate reports of the
//     same fact on a real program. Rooting it at the module produces one
//     finding per (module package x capability), with the call path starting
//     inside the module.
//   - A whole-program call graph resolves dynamic dispatch (error.Error,
//     io.Writer.Write, fmt.Stringer.String, ...) to every type in the HOST
//     program, blaming a confined module for capabilities of values only the
//     host could have handed it (e.g. a YAML emitter "reaching" the network
//     because some other dependency registers a syslog io.Writer). In the
//     module's own slice such types do not exist; what remains is what the
//     module's own code and its own dependency cone can do — the same scope
//     as Capslock's per-module results on deps.dev.
//
// To insulate gomodjail from Capslock's pre-1.0 churn, ALL Capslock and
// Capslock-proto types are confined to this package: callers receive only the
// gomodjail-local Finding/FuncRef types declared below. A breaking Capslock
// change is therefore a one-package fix.
package capslock

import (
	_ "embed"
	"fmt"
	"go/types"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/google/capslock/analyzer"
	"github.com/google/capslock/interesting"
	cpb "github.com/google/capslock/proto"
)

// overridesCM is gomodjail's override capability map, merged over Capslock's
// builtin classifier. See the comments in the file for what it changes and
// why; treat any edit as a security-reviewed event.
//
//go:embed gomodjail.cm
var overridesCM string

// Capability is a Capslock capability-class name, e.g. "EXEC". Names may be
// hierarchical, e.g. "MODIFY_SYSTEM_STATE/SIGNALS".
//
// The string form (rather than Capslock's proto enum) is deliberate: it keeps
// the proto types out of the public API and matches what the policy layer
// reasons about. Capslock documents these names as unstable until its 1.0
// release, which is why the dependency is pinned.
type Capability = string

// FuncRef is one frame of a call path: a function or method and where it is
// defined. It mirrors the data in Capslock's proto Function without exposing
// the proto type.
type FuncRef struct {
	// Name is the function or method name as Capslock reports it, e.g.
	// "os/exec.Command" or "(*os/exec.Cmd).Run".
	Name string `json:"name"`
	// Package is the package path the function belongs to. May be empty for
	// frames Capslock could not attribute to a package.
	Package string `json:"package,omitempty"`
	// Filename, Line and Column locate the call site. Filename may be empty.
	Filename string `json:"filename,omitempty"`
	Line     int64  `json:"line,omitempty"`
	Column   int64  `json:"column,omitempty"`
}

// Finding is a single reachable capability, with a witness call path.
//
// When the analysis is rooted at confined modules (Options.ConfinedModules),
// Path[0] is a function owned by Module and the last frame is (at or near)
// the privileged standard-library call that earns the capability. Capslock
// reports one finding per (capability, package) at package granularity; the
// policy layer aggregates these to one witness per (module, capability).
type Finding struct {
	// Capability is the Capslock capability-class name, e.g. "EXEC".
	Capability Capability `json:"capability"`
	// Module is the confined module that owns the root frame of Path.
	// Empty when the analysis was not rooted at confined modules.
	Module string `json:"module,omitempty"`
	// Package is the package path of the root frame.
	Package string `json:"package,omitempty"`
	// Path is the witness call chain from a module-owned function to the sink.
	Path []FuncRef `json:"path,omitempty"`
}

// Options configures a single Analyze run.
type Options struct {
	// Dir is the working directory for package loading. For a multi-module
	// layout (such as gomodjail's examples, where victim depends on poisoned
	// via a replace directive) this must be the module root so the module
	// graph and replace directives resolve. Defaults to the process working
	// directory when empty.
	Dir string
	// Patterns are the package patterns to load (go/packages syntax).
	// Defaults to []string{"./..."}. The load determines which packages (and
	// which versions) of the confined modules take part in the build; the
	// analysis itself runs per confined module on that module's slice of the
	// loaded program.
	Patterns []string
	// ConfinedModules are the module paths to analyze. Each is analyzed in
	// its own dependency slice, and every Finding is attributed to the module
	// whose slice produced it. When empty, a single whole-program analysis
	// runs with the query rooted at the loaded packages themselves
	// (Capslock's default behavior, useful for exploration); Findings are
	// then unattributed.
	ConfinedModules []string
	// BuildTags, GOOS and GOARCH select the build configuration to analyze,
	// mirroring Capslock's -buildtags/-goos/-goarch. Empty GOOS/GOARCH mean
	// the host's runtime values; ambient GOOS/GOARCH environment variables
	// are deliberately ignored, so the analyzed target is always explicit.
	BuildTags string
	GOOS      string
	GOARCH    string
	// Parallel is the maximum number of confined modules analyzed
	// concurrently; 0 or negative means GOMAXPROCS. Each concurrent analysis
	// builds its own SSA program and call graph for its module's dependency
	// slice, so memory use grows with this value.
	Parallel int
}

// Result is the structured outcome of an Analyze run.
type Result struct {
	// Findings is every reachable capability Capslock reported, translated
	// into gomodjail-local types and (when ConfinedModules was set) attributed
	// to the confined module whose dependency slice produced them.
	Findings []Finding
	// ModulePackages maps each requested confined module to the packages of
	// that module found in the loaded program. A confined module absent from
	// this map contributes no code to the build ("unused"): nothing to verify.
	ModulePackages map[string][]string
}

// Analyze loads the requested packages and runs Capslock's capability
// analysis once per confined module, over that module's dependency slice.
//
// It does not apply any policy: it reports what Capslock found, unfiltered.
// Turning findings into per-module verdicts is the job of the policy layer
// built on top of this package.
//
// Analyze is safe for concurrent use, but calls are serialized internally:
// the analysis pins GOOS/GOARCH in the process environment for its duration
// (restored on return), because Capslock reads the ambient environment.
// analyzeMu serializes Analyze: the analysis pins GOOS/GOARCH in the
// process environment for its whole duration (see below), which concurrent
// calls could otherwise corrupt for each other.
var analyzeMu sync.Mutex

func Analyze(opts Options) (*Result, error) {
	analyzeMu.Lock()
	defer analyzeMu.Unlock()

	patterns := opts.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	// Resolve the target platform and pin it in the process environment (in
	// addition to the load environment in loadPackages) for the duration of
	// the analysis, restoring the previous state on return: ambient
	// GOOS/GOARCH must not silently select a different target than the
	// documented and reported one, and Capslock internally lists the
	// standard library with the process environment
	// (analyzer.standardLibraryPackages — a sync.Once, so the pinning also
	// makes that one-time computation deterministic), which has to agree.
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	restoreGOOS, err := setenvRestore("GOOS", opts.GOOS)
	if err != nil {
		return nil, err
	}
	defer restoreGOOS()
	restoreGOARCH, err := setenvRestore("GOARCH", opts.GOARCH)
	if err != nil {
		return nil, err
	}
	defer restoreGOARCH()

	loadStart := time.Now()
	pkgs, err := loadPackages(opts, patterns)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}
	slog.Debug("capslock: loaded packages", "patterns", patterns, "duration", time.Since(loadStart))
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages matched %v in %q", patterns, opts.Dir)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		return nil, fmt.Errorf("%d error(s) while loading packages %v", n, patterns)
	}

	// Capslock's curated capability map plus gomodjail's pinned overrides.
	// The UNANALYZED class is kept (not excluded), so gomodjail's policy
	// layer can surface unfollowable paths as analysis caveats.
	classifier, err := interesting.LoadClassifier("gomodjail.cm", strings.NewReader(overridesCM), false)
	if err != nil {
		return nil, fmt.Errorf("loading gomodjail classifier overrides: %w", err)
	}
	cfg := &analyzer.Config{
		Classifier: classifier,
		// One finding per (capability, package) instead of per (capability,
		// function): the policy layer needs a witness per module, not an
		// exhaustive function inventory.
		Granularity: analyzer.GranularityPackage,
	}

	res := &Result{ModulePackages: make(map[string][]string)}
	if len(opts.ConfinedModules) == 0 {
		cil := analyzer.GetCapabilityInfo(pkgs, analyzer.GetQueriedPackages(pkgs), cfg)
		res.Findings = convertFindings(cil, "")
		return res, nil
	}

	byModule := collectConfinedPackages(pkgs, opts.ConfinedModules, res.ModulePackages)
	type job struct {
		mod   string
		roots []*packages.Package
	}
	var jobs []job
	for _, mod := range opts.ConfinedModules {
		if roots := byModule[mod]; len(roots) > 0 {
			jobs = append(jobs, job{mod, roots})
		} // else: unused module, nothing in the build
	}
	parallel := min(max(opts.Parallel, 1), len(jobs))
	if opts.Parallel <= 0 {
		parallel = min(runtime.GOMAXPROCS(0), len(jobs))
	}
	if parallel > 1 {
		// Capslock rewrites the shared ASTs in place at the start of every
		// analysis (sort.Slice/Once.Do calls become direct calls for
		// call-graph precision). The rewrite is idempotent but not safe to
		// run concurrently, so apply it to every loaded package up front:
		// the concurrent analyses' own rewrite passes then find nothing left
		// to mutate, and the shared ASTs are only read. See rewrite.go.
		warmStart := time.Now()
		residual := warmUpRewrites(pkgs)
		slog.Debug("capslock: applied AST rewrites", "duration", time.Since(warmStart))
		if residual > 0 {
			// A site Capslock wants to rewrite but cannot (e.g. a dead-code
			// `sort.Sort(nil)`) stays in the ASTs, and every analysis pass
			// re-writes shared type information for it before giving up —
			// not read-only, so running concurrently would be a data race.
			slog.Warn("capslock: falling back to sequential analysis: the loaded packages contain call sites whose rewrite cannot converge",
				"sites", residual)
			parallel = 1
		}
	}
	findingsByJob := make([][]Finding, len(jobs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(parallel, 1))
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			queried := make(map[*types.Package]struct{}, len(j.roots))
			for _, p := range j.roots {
				queried[p.Types] = struct{}{}
			}
			cfgCopy := *cfg // GetCapabilityInfo may write config defaults
			modStart := time.Now()
			cil := analyzer.GetCapabilityInfo(j.roots, queried, &cfgCopy)
			slog.Debug("capslock: analyzed module", "module", j.mod, "packages", len(j.roots), "duration", time.Since(modStart))
			findingsByJob[i] = convertFindings(cil, j.mod)
		}()
	}
	wg.Wait()
	for _, findings := range findingsByJob {
		res.Findings = append(res.Findings, findings...)
	}
	sortFindings(res.Findings)
	return res, nil
}

// collectConfinedPackages walks the whole loaded program (including
// dependencies) and groups the packages owned by each confined module.
// Ownership comes from the go/packages module metadata (NeedModule), which is
// exact — no symbol-prefix matching needed. It also fills modulePackages
// (module -> its package paths, sorted) for "unused module" reporting.
func collectConfinedPackages(pkgs []*packages.Package, confinedModules []string,
	modulePackages map[string][]string,
) map[string][]*packages.Package {
	confined := make(map[string]struct{}, len(confinedModules))
	for _, m := range confinedModules {
		confined[m] = struct{}{}
	}
	byModule := make(map[string][]*packages.Package)
	packages.Visit(pkgs, func(p *packages.Package) bool {
		if p.Module == nil || p.Types == nil {
			return true // standard library
		}
		if _, ok := confined[p.Module.Path]; !ok {
			return true
		}
		byModule[p.Module.Path] = append(byModule[p.Module.Path], p)
		modulePackages[p.Module.Path] = append(modulePackages[p.Module.Path], p.PkgPath)
		return true
	}, nil)
	for _, v := range modulePackages {
		sort.Strings(v)
	}
	for _, v := range byModule {
		sort.Slice(v, func(i, j int) bool { return v[i].PkgPath < v[j].PkgPath })
	}
	return byModule
}

// setenvRestore sets key=value and returns a function that restores the
// previous state, including unset.
func setenvRestore(key, value string) (restore func(), _ error) {
	prev, existed := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		return nil, err
	}
	return func() {
		if existed {
			_ = os.Setenv(key, prev)
		} else {
			_ = os.Unsetenv(key)
		}
	}, nil
}

// loadPackages builds the go/packages configuration and loads the requested
// patterns. It reuses Capslock's exported load mode (so we feed the analyzer
// exactly what it expects, including NeedModule for ownership attribution)
// but constructs the Config directly because Capslock's own
// analyzer.LoadPackages does not expose a Dir, and our examples live in
// sibling modules joined by a replace directive.
func loadPackages(opts Options, patterns []string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: analyzer.PackagesLoadModeNeeded,
		Dir:  opts.Dir,
	}
	if opts.BuildTags != "" {
		cfg.BuildFlags = []string{"-tags=" + opts.BuildTags}
	}
	// GOOS/GOARCH are always set by Analyze; pin them in the load
	// environment explicitly rather than relying on the process environment.
	cfg.Env = append(os.Environ(), "GOOS="+opts.GOOS, "GOARCH="+opts.GOARCH)
	return packages.Load(cfg, patterns...)
}

func convertFindings(cil *cpb.CapabilityInfoList, module string) []Finding {
	if cil == nil {
		return nil
	}
	out := make([]Finding, 0, len(cil.GetCapabilityInfo()))
	for _, ci := range cil.GetCapabilityInfo() {
		f := Finding{
			Capability: capabilityName(ci),
			Module:     module,
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
		if len(f.Path) > 0 && f.Path[0].Package != "" {
			f.Package = f.Path[0].Package
		} else {
			// Capslock stores the root package *path* in PackageDir (and the
			// short name in PackageName).
			f.Package = ci.GetPackageDir()
		}
		out = append(out, f)
	}
	return out
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Module != findings[j].Module {
			return findings[i].Module < findings[j].Module
		}
		if findings[i].Capability != findings[j].Capability {
			return findings[i].Capability < findings[j].Capability
		}
		return findings[i].Package < findings[j].Package
	})
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
