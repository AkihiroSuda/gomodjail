// Package fix implements `gomodjail fix`, which rewrites go.mod so that
// `gomodjail analyze` passes: every confined module that reaches a denied
// capability (a FAIL verdict) has its annotation downgraded to
// // gomodjail:unconfined. With --strict, warning-only modules (reflect,
// unsafe, unanalyzable paths) are downgraded too, matching the stricter gate.
//
// Downgrading is the only safe automated fix: a FAIL means the module's own
// code (or its own dependency cone) can reach the capability, which no edit
// to the depender can prevent. The rewritten annotation keeps the decision
// visible and reviewable in go.mod rather than silently dropping the line.
//
// A fix that would unconfine every confined module is refused: analyze
// treats a policy with no confined modules as a hard error, so the
// postcondition (the gate passes afterwards) could not hold.
package fix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/fromgomod"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/gomodedit"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

func Example() string {
	return `  # Analyze the current module and unconfine the modules that fail the gate:
  gomodjail fix ./...

  # Show the edits without writing go.mod:
  gomodjail fix --dry-run ./...

  # Also unconfine warning-only modules (reflect, unsafe, ...):
  gomodjail fix --strict ./...

  # Reuse a saved report instead of re-running the analysis:
  gomodjail analyze --format=json ./... > report.json; gomodjail fix --from-report=report.json`
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "fix [flags] [packages]",
		Short:                 "Rewrite go.mod so that `gomodjail analyze` passes, by unconfining the modules that fail it",
		Example:               Example(),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("go-mod", "go.mod", "go.mod file to analyze and rewrite")
	flags.Bool("strict", false, "also unconfine modules with warnings (reflect, unsafe, unanalyzable paths)")
	flags.Bool("dry-run", false, "print the edits without writing go.mod")
	flags.String("from-report", "", "read a `gomodjail analyze --format=json` report (\"-\" for stdin) instead of re-running the analysis")
	flags.String("goos", "", "GOOS to analyze (default: host)")
	flags.String("goarch", "", "GOARCH to analyze (default: host)")
	flags.Int("parallel", 0, "maximum number of modules analyzed concurrently (0: number of CPUs; memory use grows with this)")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	goMod, _ := flags.GetString("go-mod")
	strict, _ := flags.GetBool("strict")
	dryRun, _ := flags.GetBool("dry-run")
	fromReport, _ := flags.GetString("from-report")
	goos, _ := flags.GetString("goos")
	goarch, _ := flags.GetString("goarch")
	parallel, _ := flags.GetInt("parallel")

	if goMod == "" {
		return errors.New("fix requires a go.mod file (--go-mod)")
	}
	if filepath.Base(goMod) != "go.mod" {
		// go/packages always reads the directory's literal go.mod; silently
		// analyzing a different module graph than the file being rewritten
		// would make the edits meaningless.
		return fmt.Errorf("--go-mod must point at a file named go.mod (got %q)", goMod)
	}
	// Keep the raw bytes the edit is based on: the analysis below can take
	// minutes, and go.mod must not be overwritten if something else (an
	// editor, `go mod tidy`) changed it in the meantime — see writeGoMod.
	goModBytes, err := os.ReadFile(goMod)
	if err != nil {
		return err
	}
	mf, prof, err := fromgomod.Parse(goMod, goModBytes)
	if err != nil {
		return err
	}
	if err = prof.Validate(); err != nil {
		return err
	}
	confined := prof.ConfinedModules()
	if len(confined) == 0 {
		return errors.New("no confined modules in " + goMod + " (Hint: annotate go.mod with `// gomodjail:confined`)")
	}

	patterns := args
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	var reports []policy.ModuleReport
	if fromReport != "" {
		var md *reportMetadata
		if reports, md, err = loadReport(cmd.InOrStdin(), fromReport); err != nil {
			return err
		}
		if err := verifyReportMetadata(md, fromReport, goMod, goModBytes, goos, goarch, patterns); err != nil {
			return err
		}
		// The report must cover every currently confined module (analyze
		// emits an entry even for unused ones): a module confined after the
		// report was saved would otherwise be skipped silently, and the
		// postcondition — `gomodjail analyze` passes after the fix — would
		// not hold. Duplicate entries are rejected for the same reason:
		// analyze never emits them, and picking one of two conflicting
		// entries would make the outcome ordering-dependent.
		reported := make(map[string]struct{}, len(reports))
		for _, r := range reports {
			if _, dup := reported[r.Module]; dup {
				return fmt.Errorf("analyze report %q contains duplicate entries for module %q (malformed report?)",
					fromReport, r.Module)
			}
			reported[r.Module] = struct{}{}
		}
		var missing []string
		for _, mod := range confined {
			if _, ok := reported[mod]; !ok {
				missing = append(missing, mod)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("analyze report %q does not cover confined module(s) %v (stale report? re-run `gomodjail analyze --format=json`)",
				fromReport, missing)
		}
	} else {
		res, err := capslock.Analyze(capslock.Options{
			// The analysis must load the module whose go.mod is being
			// rewritten, not whatever module the process happens to run in.
			Dir:             filepath.Dir(goMod),
			Patterns:        patterns,
			ConfinedModules: confined,
			GOOS:            goos,
			GOARCH:          goarch,
			Parallel:        parallel,
		})
		if err != nil {
			return err
		}
		reports = policy.Evaluate(confined, res, policy.Default())
	}

	confinedSet := make(map[string]struct{}, len(confined))
	for _, mod := range confined {
		confinedSet[mod] = struct{}{}
	}
	type edit struct {
		module string
		reason string
	}
	var edits []edit
	warnOnly := 0
	for _, r := range reports {
		if _, ok := confinedSet[r.Module]; !ok {
			// Only possible with --from-report: the report and go.mod
			// disagree about what is confined. Failing entries must not be
			// dropped silently — the gate would still fail after the "fix".
			if len(r.Violations) > 0 {
				slog.Warn("Skipping a failing module from the report: not confined in go.mod (stale report?)",
					"module", r.Module)
			}
			continue
		}
		witnesses, verb := r.Violations, "reaches"
		if len(witnesses) == 0 {
			if len(r.Caveats) == 0 {
				continue
			}
			if !strict {
				warnOnly++
				continue
			}
			witnesses, verb = r.Caveats, "uses"
		}
		edits = append(edits, edit{r.Module, verb + " " + policy.CapabilityList(witnesses)})
	}

	fixed := 0
	lines := make([]string, 0, len(edits))
	verb := "unconfined"
	if dryRun {
		verb = "would unconfine"
	}
	for _, e := range edits {
		changed, err := gomodedit.SetPolicy(mf, e.module, profile.PolicyUnconfined)
		if err != nil {
			return err
		}
		if !changed {
			continue
		}
		fixed++
		lines = append(lines, fmt.Sprintf("fix  %s: %s (%s)", e.module, verb, e.reason))
	}

	// Unconfining every confined module would leave `gomodjail analyze`
	// hard-erroring ("no confined modules"), so the promised postcondition —
	// the gate passes after the fix — cannot hold. Refuse instead of writing
	// a go.mod that fails open; the SetPolicy edits above were in memory
	// only, so go.mod is untouched. --dry-run gets the same error, since it
	// predicts what applying would do.
	if fixed > 0 && fixed == len(confined) {
		return fmt.Errorf("refusing to unconfine all %d confined module(s): `gomodjail analyze` would then fail with \"no confined modules\"; edit go.mod manually if this is really intended",
			len(confined))
	}

	p := &printer{w: cmd.OutOrStdout()}
	if fixed == 0 {
		p.printf("gomodjail: nothing to fix in %s (%d confined module(s))\n", goMod, len(confined))
	} else {
		// Write before printing: the per-module lines assert edits, so they
		// must not appear when the write fails.
		if !dryRun {
			if err := writeGoMod(goMod, mf, goModBytes); err != nil {
				return err
			}
		}
		for _, l := range lines {
			p.printf("%s\n", l)
		}
		if dryRun {
			p.printf("\ngomodjail: would unconfine %d of %d confined module(s) (dry-run, %s left unchanged)\n",
				fixed, len(confined), goMod)
		} else {
			p.printf("\ngomodjail: unconfined %d of %d confined module(s) in %s\n", fixed, len(confined), goMod)
		}
	}
	if warnOnly > 0 {
		p.printf("gomodjail: %d module(s) with warnings kept confined (use --strict to unconfine them too)\n", warnOnly)
	}
	return p.err
}

// printer latches the first write error, so the output code stays linear.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// reportMetadata mirrors the metadata header of `gomodjail analyze
// --format=json` (see newReportMetadata in the analyze command).
type reportMetadata struct {
	GoModSHA256 string   `json:"goModSHA256"`
	GoVersion   string   `json:"goVersion"`
	GoFlags     string   `json:"goFlags"`
	GOOS        string   `json:"goos"`
	GOARCH      string   `json:"goarch"`
	Patterns    []string `json:"patterns"`
}

// goToolchainVersion returns the version of the Go toolchain that package
// loading uses in dir (`go env GOVERSION`, which honors any GOTOOLCHAIN
// selection there).
func goToolchainVersion(dir string) (string, error) {
	v, err := goEnv(dir, "GOVERSION")
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("`go env GOVERSION` returned an empty version")
	}
	return v, nil
}

// goEnv returns the effective value of one `go env` key, resolved in dir.
func goEnv(dir, key string) (string, error) {
	cmd := exec.Command("go", "env", key)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolving `go env %s`: %w", key, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// loadReport reads the JSON emitted by `gomodjail analyze --format=json`.
func loadReport(stdin io.Reader, path string) ([]policy.ModuleReport, *reportMetadata, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close() //nolint:errcheck
		r = f
	}
	var report struct {
		Metadata *reportMetadata       `json:"metadata"`
		Modules  []policy.ModuleReport `json:"modules"`
	}
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, nil, fmt.Errorf("failed to decode analyze report %q: %w", path, err)
	}
	if report.Modules == nil {
		return nil, nil, fmt.Errorf("analyze report %q has no \"modules\" (expected `gomodjail analyze --format=json` output)", path)
	}
	return report.Modules, report.Metadata, nil
}

// verifyReportMetadata checks that a saved report still describes the build
// fix is about to edit: same go.mod contents, same target platform, same
// package patterns. Dependency version changes edit go.mod, so the digest
// catches them; edits to local source under a replace directive are not
// detectable and remain the user's responsibility.
func verifyReportMetadata(md *reportMetadata, path, goMod string, goModBytes []byte, goos, goarch string, patterns []string) error {
	if md == nil {
		return fmt.Errorf("analyze report %q has no \"metadata\" (expected `gomodjail analyze --format=json` output)", path)
	}
	sum := sha256.Sum256(goModBytes)
	if md.GoModSHA256 != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("analyze report %q was generated from a different go.mod (stale report? re-run `gomodjail analyze --format=json`)", path)
	}
	// The analyzed standard library belongs to the toolchain, so findings
	// are only comparable within the same version (e.g. Go 1.27 relocated
	// the http2 code bundled into net/http).
	goVersion, err := goToolchainVersion(filepath.Dir(goMod))
	if err != nil {
		return err
	}
	if md.GoVersion != goVersion {
		return fmt.Errorf("analyze report %q was generated with Go toolchain %q, not %q", path, md.GoVersion, goVersion)
	}
	// go/packages inherits GOFLAGS (e.g. -tags changes the analyzed build).
	goFlags, err := goEnv(filepath.Dir(goMod), "GOFLAGS")
	if err != nil {
		return err
	}
	if md.GoFlags != goFlags {
		return fmt.Errorf("analyze report %q was generated with GOFLAGS %q, not %q", path, md.GoFlags, goFlags)
	}
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	if md.GOOS != goos || md.GOARCH != goarch {
		return fmt.Errorf("analyze report %q was generated for %s/%s, not %s/%s", path, md.GOOS, md.GOARCH, goos, goarch)
	}
	if !slices.Equal(md.Patterns, patterns) {
		return fmt.Errorf("analyze report %q was generated for package patterns %v, not %v", path, md.Patterns, patterns)
	}
	return nil
}

// writeGoMod atomically replaces goMod with the formatted edit (temp file +
// rename in the same directory), keeping its permission bits: a crash or a
// full disk must not leave a truncated go.mod behind.
//
// It refuses to overwrite a go.mod that no longer matches orig, the bytes
// the edit was computed from: the analysis can run for minutes, and an
// editor or `go mod tidy` may have changed the file in the meantime. The
// check-then-rename window is not atomic, but it closes the long analysis
// window.
func writeGoMod(goMod string, mf *modfile.File, orig []byte) error {
	cur, err := os.ReadFile(goMod)
	if err != nil {
		return err
	}
	if !bytes.Equal(cur, orig) {
		return fmt.Errorf("%s changed while the analysis was running; re-run `gomodjail fix`", goMod)
	}
	perm := fs.FileMode(0o644)
	if fi, err := os.Stat(goMod); err == nil {
		perm = fi.Mode().Perm()
	}
	dir, base := filepath.Split(goMod)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".gomodjail*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	_, werr := tmp.Write(modfile.Format(mf.Syntax))
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if err := os.Chmod(tmp.Name(), perm); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), goMod)
}
