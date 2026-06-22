// Package analyze implements `gomodjail analyze`, the static-analysis gate that
// replaces dynamic runtime confinement as gomodjail's default. It reads the
// // gomodjail:confined policy from go.mod, runs the Capslock-backed capability
// analysis over the target packages, and exits non-zero if any confined module
// can reach a disallowed capability.
package analyze

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"

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
	flags.String("goos", "", "GOOS to analyze (default: host)")
	flags.String("goarch", "", "GOARCH to analyze (default: host)")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	prof, err := loadProfile(flags)
	if err != nil {
		return err
	}
	if err = prof.Validate(); err != nil {
		return err
	}
	if countConfined(prof) == 0 {
		return errors.New("no confined modules in policy (Hint: annotate go.mod with `// gomodjail:confined`, or pass --policy=MODULE=confined)")
	}

	patterns := args
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	goos, _ := flags.GetString("goos")
	goarch, _ := flags.GetString("goarch")

	slog.DebugContext(ctx, "running capability analysis", "patterns", patterns, "goos", goos, "goarch", goarch)
	res, err := capslock.Analyze(capslock.Options{
		Patterns: patterns,
		GOOS:     goos,
		GOARCH:   goarch,
	})
	if err != nil {
		return err
	}

	violations := policy.Check(prof, res.Findings, policy.Strict())
	report(cmd.OutOrStdout(), violations)
	if len(violations) > 0 {
		return fmt.Errorf("found %d policy violation(s) across %d confined module(s)",
			len(violations), countViolatingModules(violations))
	}
	return nil
}

// loadProfile builds the policy from --go-mod (when set) and applies --policy
// overrides, mirroring the `run` command so the two stay interchangeable.
func loadProfile(flags *pflag.FlagSet) (*profile.Profile, error) {
	prof := profile.New()
	goMod, err := flags.GetString("go-mod")
	if err != nil {
		return nil, err
	}
	if goMod != "" {
		b, err := os.ReadFile(goMod)
		if err != nil {
			return nil, err
		}
		mf, err := modfile.Parse(goMod, b, nil)
		if err != nil {
			return nil, err
		}
		if err = fromgomod.FromGoMod(mf, prof); err != nil {
			return nil, fmt.Errorf("failed to read profile from %q: %w", goMod, err)
		}
	}
	overrides, err := flags.GetStringToString("policy")
	if err != nil {
		return nil, err
	}
	for k, v := range overrides {
		if old, ok := prof.Modules[k]; ok && old != v {
			slog.Warn("Overwriting policy", "module", k, "old", old, "new", v)
		}
		prof.Modules[k] = v
	}
	return prof, nil
}

func countConfined(prof *profile.Profile) int {
	n := 0
	for _, pol := range prof.Modules {
		if pol != profile.PolicyUnconfined {
			n++
		}
	}
	return n
}

func countViolatingModules(violations []policy.Violation) int {
	mods := make(map[string]struct{}, len(violations))
	for _, v := range violations {
		mods[v.Module] = struct{}{}
	}
	return len(mods)
}

// report prints a human-readable summary of the violations. Each entry names
// the confined module and the disallowed capability, then the call path from a
// queried entrypoint down to the sink, marking the frame that the module owns.
func report(w io.Writer, violations []policy.Violation) {
	if len(violations) == 0 {
		fmt.Fprintln(w, "gomodjail: ok, no policy violations")
		return
	}
	for _, v := range dedupe(violations) {
		hatch := ""
		if policy.IsEscapeHatch(v.Capability) {
			hatch = " (unanalyzable: escape hatch)"
		}
		fmt.Fprintf(w, "\n%s: confined module reaches %s%s\n", v.Module, v.Capability, hatch)
		for i, fr := range v.Path {
			marker := "    "
			if i == v.OwnerIndex {
				marker = "  > " // the confined-module frame
			}
			name := fr.Name
			if name == "" {
				name = fr.Package
			}
			loc := ""
			if fr.Filename != "" {
				loc = fmt.Sprintf("  (%s:%d)", fr.Filename, fr.Line)
			}
			fmt.Fprintf(w, "%s%s%s\n", marker, name, loc)
		}
	}
}

// dedupe collapses violations that share the same module, capability, and call
// path so the report does not repeat identical findings.
func dedupe(violations []policy.Violation) []policy.Violation {
	seen := make(map[string]struct{}, len(violations))
	out := make([]policy.Violation, 0, len(violations))
	for _, v := range violations {
		key := v.Module + "\x00" + v.Capability + "\x00"
		for _, fr := range v.Path {
			key += fr.Name + ">"
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Capability < out[j].Capability
	})
	return out
}
