package fix

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/cmd/gomodjail/commands/analyze"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/fromgomod"
)

// mixedFixture writes a three-module fixture into a temp dir: app confines
// both execdep (execs a process — the golden FAIL) and jsondep (pure JSON
// round-trip — WARN via reflect). `fix` must unconfine execdep and keep
// jsondep confined, so that `analyze` then passes.
func mixedFixture(t *testing.T) (appDir string) {
	t.Helper()
	root := t.TempDir()
	appDir = filepath.Join(root, "app")
	write := func(dir, name, content string) {
		t.Helper()
		assert.NilError(t, os.MkdirAll(dir, 0o755))
		assert.NilError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	execDir := filepath.Join(root, "execdep")
	write(execDir, "go.mod", "module example.com/execdep\n\ngo 1.23\n")
	write(execDir, "dep.go", `package execdep

import "os/exec"

func Run() error { return exec.Command("true").Run() }
`)
	jsonDir := filepath.Join(root, "jsondep")
	write(jsonDir, "go.mod", "module example.com/jsondep\n\ngo 1.23\n")
	write(jsonDir, "dep.go", `package jsondep

import "encoding/json"

func Roundtrip(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
`)
	write(appDir, "go.mod", `module example.com/app

go 1.23

require (
	example.com/execdep v0.0.0-00010101000000-000000000000 // gomodjail:confined
	example.com/jsondep v0.0.0-00010101000000-000000000000 // gomodjail:confined
)

replace (
	example.com/execdep => ../execdep
	example.com/jsondep => ../jsondep
)
`)
	write(appDir, "main.go", `package main

import (
	"example.com/execdep"
	"example.com/jsondep"
)

func main() {
	_ = execdep.Run()
	_, _ = jsondep.Roundtrip([]byte("{}"))
}
`)
	return appDir
}

func withWorkdir(t *testing.T, dir string, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	assert.NilError(t, err)
	assert.NilError(t, os.Chdir(dir))
	defer func() { assert.NilError(t, os.Chdir(orig)) }()
	fn()
}

func runFix(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func runAnalyze(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := analyze.New()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func readGoMod(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	assert.NilError(t, err)
	return string(b)
}

// TestFixUnconfinesFailingModule is the headline test: `analyze` fails on the
// fixture, `fix` unconfines exactly the failing module, and `analyze` passes
// afterwards (with the warning-only module still confined).
func TestFixUnconfinesFailingModule(t *testing.T) {
	appDir := mixedFixture(t)
	withWorkdir(t, appDir, func() {
		out, err := runAnalyze(t, "./...")
		assert.Assert(t, err != nil, "analyze must fail before the fix; out=%q", out)

		out, err = runFix(t, "./...")
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "fix  example.com/execdep"), "out=%q", out)
		assert.Assert(t, strings.Contains(out, "unconfined 1 of 2"), "out=%q", out)
		assert.Assert(t, strings.Contains(out, "kept confined"), "out=%q", out)

		goMod := readGoMod(t, appDir)
		assert.Assert(t, strings.Contains(goMod, "example.com/execdep v0.0.0-00010101000000-000000000000 // gomodjail:unconfined"), "got %q", goMod)
		assert.Assert(t, strings.Contains(goMod, "example.com/jsondep v0.0.0-00010101000000-000000000000 // gomodjail:confined"), "got %q", goMod)

		out, err = runAnalyze(t, "./...")
		assert.NilError(t, err, "analyze must pass after the fix; out=%q", out)
		assert.Assert(t, strings.Contains(out, "WARN example.com/jsondep"), "out=%q", out)

		out, err = runFix(t, "./...")
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "nothing to fix"), "fix must be idempotent; out=%q", out)
	})
}

// TestFixDryRun: --dry-run prints the plan but leaves go.mod untouched.
func TestFixDryRun(t *testing.T) {
	appDir := mixedFixture(t)
	withWorkdir(t, appDir, func() {
		before := readGoMod(t, appDir)
		out, err := runFix(t, "--dry-run", "./...")
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "would unconfine"), "out=%q", out)
		assert.Equal(t, readGoMod(t, appDir), before, "dry-run must not write go.mod")
	})
}

// TestFixStrictRefusesToUnconfineAll: --strict would unconfine both of the
// fixture's confined modules (the FAIL one and the WARN one), after which
// `gomodjail analyze` would hard-error with "no confined modules". fix must
// refuse before writing rather than exit 0 with a broken postcondition.
func TestFixStrictRefusesToUnconfineAll(t *testing.T) {
	appDir := mixedFixture(t)
	withWorkdir(t, appDir, func() {
		before := readGoMod(t, appDir)
		out, err := runFix(t, "--strict", "./...")
		assert.ErrorContains(t, err, "refusing to unconfine all 2 confined module(s)", "out=%q", out)
		assert.Assert(t, !strings.Contains(out, "fix  "), "no edit lines when refused; out=%q", out)
		assert.Equal(t, readGoMod(t, appDir), before, "go.mod must be untouched")
	})
}

// TestFixStrictKeepsRemainingConfined: --strict unconfines the FAIL and
// WARN modules, and succeeds as long as at least one module stays confined.
func TestFixStrictKeepsRemainingConfined(t *testing.T) {
	dir := t.TempDir()
	goMod := `module example.com/app

go 1.23

require (
	example.com/execdep v1.0.0 // gomodjail:confined
	example.com/jsondep v1.0.0 // gomodjail:confined
	example.com/puredep v1.0.0 // gomodjail:confined
)
`
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep", "caveats": [{"capability": "REFLECT"}]},
		{"module": "example.com/puredep"}
	]}`)
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report, "--strict")
	assert.NilError(t, err, "out=%q", out)
	assert.Assert(t, strings.Contains(out, "unconfined 2 of 3"), "out=%q", out)
	goModOut := readGoMod(t, dir)
	assert.Assert(t, strings.Contains(goModOut, "example.com/puredep v1.0.0 // gomodjail:confined"), "got %q", goModOut)
}

// TestFixFromReport: fix consumes a saved `analyze --format=json` report
// instead of re-running the analysis. This is the fast path for large
// programs where the analysis takes minutes.
func TestFixFromReport(t *testing.T) {
	appDir := mixedFixture(t)
	withWorkdir(t, appDir, func() {
		report := filepath.Join(t.TempDir(), "report.json")
		out, err := runAnalyze(t, "--format=json", "./...")
		assert.Assert(t, err != nil, "analyze must fail on the fixture; out=%q", out)
		// Keep only the first JSON value (on error, cobra appends usage text).
		var jsonOut json.RawMessage
		assert.NilError(t, json.NewDecoder(strings.NewReader(out)).Decode(&jsonOut))
		assert.NilError(t, os.WriteFile(report, jsonOut, 0o644))

		out, err = runFix(t, "--from-report="+report)
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "fix  example.com/execdep"), "out=%q", out)

		goMod := readGoMod(t, appDir)
		assert.Assert(t, strings.Contains(goMod, "example.com/execdep v0.0.0-00010101000000-000000000000 // gomodjail:unconfined"), "got %q", goMod)
	})
}

// reportFixture writes a go.mod with two confined modules into a temp dir.
// --from-report runs never load packages, so no source files are needed.
func reportFixture(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	goMod := `module example.com/app

go 1.23

require (
	example.com/execdep v1.0.0 // gomodjail:confined
	example.com/jsondep v1.0.0 // gomodjail:confined
)
`
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))
	return dir
}

// writeReport writes a report with a metadata header matching the go.mod
// in goModDir, the host platform, and the default patterns — i.e. a report
// `gomodjail analyze --format=json` would have produced there.
func writeReport(t *testing.T, goModDir, modules string) (path string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goModDir, "go.mod"))
	assert.NilError(t, err)
	sum := sha256.Sum256(b)
	goVersion, err := goToolchainVersion(goModDir)
	assert.NilError(t, err)
	goFlags, err := goEnv(goModDir, "GOFLAGS")
	assert.NilError(t, err)
	content := fmt.Sprintf(`{"metadata": {"goModSHA256": %q, "goVersion": %q, "goFlags": %q, "goos": %q, "goarch": %q, "patterns": ["./..."]}, %s`,
		hex.EncodeToString(sum[:]), goVersion, goFlags, runtime.GOOS, runtime.GOARCH, strings.TrimPrefix(strings.TrimSpace(modules), "{"))
	path = filepath.Join(t.TempDir(), "report.json")
	assert.NilError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// TestFixFromReportStale: entries for modules that are not confined in
// go.mod (a stale report) are skipped with a warning; the covered modules
// are fixed normally.
func TestFixFromReportStale(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/stale", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep", "caveats": [{"capability": "REFLECT"}]}
	]}`)
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.NilError(t, err, "out=%q", out)
	assert.Equal(t, strings.Count(out, "fix  example.com/execdep"), 1, "out=%q", out)
	assert.Assert(t, strings.Contains(out, "unconfined 1 of 2"), "out=%q", out)
	assert.Assert(t, strings.Contains(out, "1 module(s) with warnings kept confined"), "out=%q", out)

	goMod := readGoMod(t, dir)
	assert.Assert(t, strings.Contains(goMod, "example.com/execdep v1.0.0 // gomodjail:unconfined"), "got %q", goMod)
	assert.Assert(t, strings.Contains(goMod, "example.com/jsondep v1.0.0 // gomodjail:confined"), "got %q", goMod)
}

// TestFixFromReportDuplicates: analyze never emits duplicate module
// entries, and accepting them would make the outcome ordering-dependent (a
// clean first entry could mask a later one carrying a violation), so a
// report with duplicates is rejected before any edit.
func TestFixFromReportDuplicates(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep"},
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep"}
	]}`)
	before := readGoMod(t, dir)
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.ErrorContains(t, err, `duplicate entries for module "example.com/execdep"`, "out=%q", out)
	assert.Equal(t, readGoMod(t, dir), before, "go.mod must be untouched")
}

// TestFixFromReportMissingModule: a report that does not cover every
// currently confined module (e.g. saved before a new dependency was
// confined) must be rejected — silently skipping the uncovered module would
// break the postcondition that `gomodjail analyze` passes after the fix.
func TestFixFromReportMissingModule(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]}
	]}`)
	before := readGoMod(t, dir)
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.ErrorContains(t, err, "does not cover confined module(s) [example.com/jsondep]", "out=%q", out)
	assert.Equal(t, readGoMod(t, dir), before, "go.mod must be untouched")
}

// TestFixFromReportDryRunRefusal: --dry-run predicts what applying would
// do, so an edit set that would unconfine every confined module is refused
// there too, with the same error as an actual run.
func TestFixFromReportDryRunRefusal(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep", "violations": [{"capability": "FILES/READ"}]}
	]}`)
	before := readGoMod(t, dir)
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report, "--dry-run")
	assert.ErrorContains(t, err, "refusing to unconfine all 2 confined module(s)", "out=%q", out)
	assert.Equal(t, readGoMod(t, dir), before, "dry-run must not write go.mod")
}

// TestFixWriteFailurePrintsNoEdits: when go.mod cannot be written, the output
// must not assert edits that never happened, and go.mod must be intact (the
// write is temp-file + rename, never an in-place truncate).
func TestFixWriteFailurePrintsNoEdits(t *testing.T) {
	dir := reportFixture(t)
	before := readGoMod(t, dir)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep"}
	]}`)
	assert.NilError(t, os.Chmod(dir, 0o555))
	defer func() { assert.NilError(t, os.Chmod(dir, 0o755)) }()
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.Assert(t, err != nil, "out=%q", out)
	assert.Assert(t, !strings.Contains(out, "fix  "), "no edit lines on a failed write; out=%q", out)
	assert.Equal(t, readGoMod(t, dir), before, "go.mod must be intact after a failed write")
}

func TestFixNoConfinedModules(t *testing.T) {
	appDir := mixedFixture(t)
	goMod := filepath.Join(appDir, "go.mod")
	b, err := os.ReadFile(goMod)
	assert.NilError(t, err)
	assert.NilError(t, os.WriteFile(goMod, bytes.ReplaceAll(b, []byte(" // gomodjail:confined"), nil), 0o644))
	withWorkdir(t, appDir, func() {
		_, err := runFix(t, "./...")
		assert.ErrorContains(t, err, "no confined modules")
	})
}

// TestFixFromReportNoMetadata: a report without the metadata header cannot
// be verified against the current build and is rejected.
func TestFixFromReportNoMetadata(t *testing.T) {
	dir := reportFixture(t)
	report := filepath.Join(t.TempDir(), "report.json")
	assert.NilError(t, os.WriteFile(report, []byte(`{"modules": [
		{"module": "example.com/execdep"},
		{"module": "example.com/jsondep"}
	]}`), 0o644))
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.ErrorContains(t, err, `no "metadata"`, "out=%q", out)
}

// TestFixFromReportStaleGoMod: module paths alone do not prove a report
// still describes the current build — a dependency can change version under
// the same path. The report is bound to the go.mod contents by digest, so
// any go.mod edit after the report was saved is rejected.
func TestFixFromReportStaleGoMod(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep"}
	]}`)
	goMod := filepath.Join(dir, "go.mod")
	b, err := os.ReadFile(goMod)
	assert.NilError(t, err)
	assert.NilError(t, os.WriteFile(goMod, bytes.Replace(b, []byte("v1.0.0"), []byte("v1.0.1"), 1), 0o644))
	before := readGoMod(t, dir)
	out, err := runFix(t, "--go-mod="+goMod, "--from-report="+report)
	assert.ErrorContains(t, err, "generated from a different go.mod", "out=%q", out)
	assert.Equal(t, readGoMod(t, dir), before, "go.mod must be untouched")
}

// TestFixFromReportToolchainMismatch: the analyzed standard library belongs
// to the toolchain that produced the report (Go 1.27 moved net/http's
// bundled http2 code, for example), so a report from a different toolchain
// is rejected.
func TestFixFromReportToolchainMismatch(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep"}
	]}`)
	b, err := os.ReadFile(report)
	assert.NilError(t, err)
	goVersion, err := goToolchainVersion(dir)
	assert.NilError(t, err)
	assert.NilError(t, os.WriteFile(report, bytes.Replace(b, []byte(goVersion), []byte("go0.0.0"), 1), 0o644))
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.ErrorContains(t, err, `generated with Go toolchain "go0.0.0"`, "out=%q", out)
}

// TestFixRejectsNonGoModBasename mirrors the analyze-side check.
func TestFixRejectsNonGoModBasename(t *testing.T) {
	dir := t.TempDir()
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "policy.mod"),
		[]byte("module example.com/app\n\ngo 1.23\n\nrequire example.com/dep v1.0.0 // gomodjail:confined\n"), 0o644))
	_, err := runFix(t, "--go-mod="+filepath.Join(dir, "policy.mod"))
	assert.ErrorContains(t, err, "must point at a file named go.mod")
}

// TestFixWriteGoModDetectsConcurrentEdit: the analysis can run for minutes;
// if go.mod changed in the meantime (an editor, `go mod tidy`), writing the
// stale syntax tree would silently discard those changes, so writeGoMod
// must refuse.
func TestFixWriteGoModDetectsConcurrentEdit(t *testing.T) {
	dir := reportFixture(t)
	goMod := filepath.Join(dir, "go.mod")
	orig, err := os.ReadFile(goMod)
	assert.NilError(t, err)
	mf, _, err := fromgomod.Parse(goMod, orig)
	assert.NilError(t, err)

	edited := bytes.Replace(orig, []byte("v1.0.0"), []byte("v1.0.1"), 1)
	assert.NilError(t, os.WriteFile(goMod, edited, 0o644))
	err = writeGoMod(goMod, mf, orig)
	assert.ErrorContains(t, err, "changed while the analysis was running")
	assert.Equal(t, readGoMod(t, dir), string(edited), "the concurrent edit must survive")
}

// TestFixFromReportGoFlagsMismatch: go/packages inherits GOFLAGS (e.g.
// -tags changes the analyzed build), so a report generated under different
// effective GOFLAGS is rejected.
func TestFixFromReportGoFlagsMismatch(t *testing.T) {
	dir := reportFixture(t)
	report := writeReport(t, dir, `{"modules": [
		{"module": "example.com/execdep", "violations": [{"capability": "EXEC"}]},
		{"module": "example.com/jsondep"}
	]}`)
	t.Setenv("GOFLAGS", "-tags=somethingelse")
	out, err := runFix(t, "--go-mod="+filepath.Join(dir, "go.mod"), "--from-report="+report)
	assert.ErrorContains(t, err, `generated with GOFLAGS ""`, "out=%q", out)
}
