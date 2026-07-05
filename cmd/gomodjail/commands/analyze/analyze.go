// Package analyze implements `gomodjail analyze`, the static-analysis gate
// that replaces dynamic runtime confinement as gomodjail's default. It reads
// the // gomodjail:confined policy from go.mod, runs the Capslock-backed
// capability analysis rooted at the confined modules' packages, and prints
// one verdict per confined module:
//
//	FAIL — the module reaches a denied capability (filesystem, network, exec,
//	       raw syscalls, ...). Always exits non-zero.
//	WARN — the module uses an analysis escape hatch (reflect, unsafe, or a
//	       path the analyzer could not follow). The verdict is best-effort;
//	       exits non-zero only with --strict.
//	ok   — no denied capability is reachable from the module's code.
package analyze

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/mod/modfile"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/fromgomod"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

func Example() string {
	return `  # Analyze the current module, reading policy from ./go.mod:
  gomodjail analyze ./...

  # Fail on warnings (reflect/unsafe/unanalyzable paths) too:
  gomodjail analyze --strict ./...

  # Analyze with an ad-hoc policy instead of go.mod:
  gomodjail analyze --go-mod="" --policy=example.com/module=confined ./...`
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "analyze [flags] [packages]",
		Short:                 "Statically verify that confined modules cannot reach disallowed capabilities",
		Example:               Example(),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("go-mod", "go.mod", "go.mod file with comment lines like `gomodjail:confined` (empty to skip)")
	flags.StringToString("policy", nil, "e.g., example.com/module=confined (overrides go.mod)")
	flags.Bool("strict", false, "treat warnings (reflect, unsafe, unanalyzable paths) as violations")
	flags.Bool("explain", false, "print witness call paths for warnings, not just violations")
	flags.String("format", "text", "output format (text|json|sarif)")
	flags.String("goos", "", "GOOS to analyze (default: host)")
	flags.String("goarch", "", "GOARCH to analyze (default: host)")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	prof, src, err := loadProfile(flags)
	if err != nil {
		return err
	}
	if err = prof.Validate(); err != nil {
		return err
	}
	confined := confinedModules(prof)
	if len(confined) == 0 {
		return errors.New("no confined modules in policy (Hint: annotate go.mod with `// gomodjail:confined`, or pass --policy=MODULE=confined)")
	}

	patterns := args
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	strict, _ := flags.GetBool("strict")
	explain, _ := flags.GetBool("explain")
	format, _ := flags.GetString("format")
	goos, _ := flags.GetString("goos")
	goarch, _ := flags.GetString("goarch")

	slog.DebugContext(ctx, "running capability analysis",
		"patterns", patterns, "confinedModules", len(confined), "goos", goos, "goarch", goarch)
	res, err := capslock.Analyze(capslock.Options{
		Patterns:        patterns,
		ConfinedModules: confined,
		GOOS:            goos,
		GOARCH:          goarch,
	})
	if err != nil {
		return err
	}

	reports := policy.Evaluate(confined, res, policy.Default())
	w := cmd.OutOrStdout()
	switch format {
	case "text":
		if err := report(w, reports, reportOptions{Strict: strict, Explain: explain}); err != nil {
			return err
		}
	case "json":
		if err := reportJSON(w, reports, strict); err != nil {
			return err
		}
	case "sarif":
		if err := reportSARIF(w, reports, src, strict); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown format %q (expected text|json|sarif)", format)
	}

	s := summarize(reports)
	if s.Violations > 0 {
		return fmt.Errorf("%d of %d confined module(s) can reach a denied capability", s.Violations, len(reports))
	}
	if strict && s.Warnings > 0 {
		return fmt.Errorf("%d of %d confined module(s) cannot be statically verified (--strict)", s.Warnings, len(reports))
	}
	return nil
}

// profileSource records where the policy came from, for output formats that
// point back at it (SARIF anchors each finding to the confined module's
// require line in go.mod — the line whose annotation a reviewer would edit).
type profileSource struct {
	// GoMod is the --go-mod path, "" when the policy came from --policy only.
	GoMod string
	// ModuleLine maps a module path to its require line in GoMod.
	ModuleLine map[string]int
}

// loadProfile builds the policy from --go-mod (when set) and applies --policy
// overrides, mirroring the `run` command so the two stay interchangeable.
func loadProfile(flags *pflag.FlagSet) (*profile.Profile, *profileSource, error) {
	prof := profile.New()
	src := &profileSource{ModuleLine: make(map[string]int)}
	goMod, err := flags.GetString("go-mod")
	if err != nil {
		return nil, nil, err
	}
	if goMod != "" {
		b, err := os.ReadFile(goMod)
		if err != nil {
			return nil, nil, err
		}
		mf, err := modfile.Parse(goMod, b, nil)
		if err != nil {
			return nil, nil, err
		}
		if err = fromgomod.FromGoMod(mf, prof); err != nil {
			return nil, nil, fmt.Errorf("failed to read profile from %q: %w", goMod, err)
		}
		src.GoMod = goMod
		for _, req := range mf.Require {
			if req.Syntax != nil {
				src.ModuleLine[req.Mod.Path] = req.Syntax.Start.Line
			}
		}
	}
	overrides, err := flags.GetStringToString("policy")
	if err != nil {
		return nil, nil, err
	}
	for k, v := range overrides {
		if old, ok := prof.Modules[k]; ok && old != v {
			slog.Warn("Overwriting policy", "module", k, "old", old, "new", v)
		}
		prof.Modules[k] = v
	}
	return prof, src, nil
}

func confinedModules(prof *profile.Profile) []string {
	var mods []string
	for mod, pol := range prof.Modules {
		if pol == profile.PolicyConfined {
			mods = append(mods, mod)
		}
	}
	sort.Strings(mods)
	return mods
}

type summary struct {
	OK         int `json:"ok"`
	Warnings   int `json:"warnings"`
	Violations int `json:"violations"`
	Unused     int `json:"unused"`
}

func summarize(reports []policy.ModuleReport) summary {
	var s summary
	for _, r := range reports {
		switch {
		case len(r.Violations) > 0:
			s.Violations++
		case len(r.Caveats) > 0:
			s.Warnings++
		default:
			s.OK++
			if r.Unused {
				s.Unused++
			}
		}
	}
	return s
}

type reportOptions struct {
	// Strict adjusts the hint text (warnings are about to fail the gate).
	Strict bool
	// Explain prints witness paths for warnings too.
	Explain bool
}

// printer accumulates the first write error so the report code can stay
// linear; subsequent writes after an error are no-ops.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// report prints one verdict line per confined module: violations first, then
// warnings, then ok. Witness call paths are printed for violations (one per
// denied capability, rooted at a module-owned function) and, with Explain,
// for warnings as well.
func report(w io.Writer, reports []policy.ModuleReport, opts reportOptions) error {
	ordered := make([]policy.ModuleReport, 0, len(reports))
	for _, pick := range []func(*policy.ModuleReport) bool{
		func(r *policy.ModuleReport) bool { return len(r.Violations) > 0 },
		func(r *policy.ModuleReport) bool { return len(r.Violations) == 0 && len(r.Caveats) > 0 },
		func(r *policy.ModuleReport) bool { return len(r.Violations) == 0 && len(r.Caveats) == 0 },
	} {
		for _, r := range reports {
			if pick(&r) {
				ordered = append(ordered, r)
			}
		}
	}

	p := &printer{w: w}
	for _, r := range ordered {
		switch {
		case len(r.Violations) > 0:
			p.printf("FAIL %s: reaches %s\n", r.Module, capabilityList(r.Violations))
			for _, v := range r.Violations {
				printPath(p, v)
			}
			if len(r.Caveats) > 0 {
				p.printf("     also uses %s (cannot be statically verified)\n", capabilityList(r.Caveats))
			}
		case len(r.Caveats) > 0:
			hint := "verified except for these; use --explain for paths, --strict to fail"
			if opts.Strict {
				hint = "failing due to --strict"
			}
			p.printf("WARN %s: uses %s (%s)\n", r.Module, capabilityList(r.Caveats), hint)
			if opts.Explain {
				for _, c := range r.Caveats {
					printPath(p, c)
				}
			}
		case r.Unused:
			p.printf("ok   %s (unused: no packages in this build)\n", r.Module)
		default:
			p.printf("ok   %s\n", r.Module)
		}
	}

	s := summarize(reports)
	p.printf("\ngomodjail: %d confined module(s): %d ok, %d warning(s), %d violation(s)\n",
		len(reports), s.OK, s.Warnings, s.Violations)
	if s.Violations == 0 && s.Warnings == 0 {
		p.printf("gomodjail: ok, no policy violations\n")
	}
	return p.err
}

func capabilityList(ws []policy.Witness) string {
	caps := make([]string, 0, len(ws))
	for _, w := range ws {
		caps = append(caps, w.Capability)
	}
	return strings.Join(caps, ", ")
}

// printPath prints one witness call path, indented under its verdict line.
// The path is already rooted at a function the confined module owns.
func printPath(p *printer, wit policy.Witness) {
	p.printf("     [%s]\n", wit.Capability)
	for _, fr := range wit.Path {
		name := fr.Name
		if name == "" {
			name = fr.Package
		}
		loc := ""
		if fr.Filename != "" {
			loc = fmt.Sprintf("  (%s:%d)", fr.Filename, fr.Line)
		}
		p.printf("       %s%s\n", name, loc)
	}
}

func reportJSON(w io.Writer, reports []policy.ModuleReport, strict bool) error {
	out := struct {
		Modules []policy.ModuleReport `json:"modules"`
		Summary summary               `json:"summary"`
		Strict  bool                  `json:"strict"`
	}{Modules: reports, Summary: summarize(reports), Strict: strict}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
