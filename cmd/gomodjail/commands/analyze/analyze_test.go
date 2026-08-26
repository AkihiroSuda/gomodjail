package analyze

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/policy"
)

const poisonedMod = "github.com/AkihiroSuda/gomodjail/examples/poisoned"

func execViolationReport() policy.ModuleReport {
	return policy.ModuleReport{
		Module:   poisonedMod,
		Packages: []string{poisonedMod},
		Violations: []policy.Witness{{
			Capability: policy.CapExec,
			Path: []capslock.FuncRef{
				{Name: poisonedMod + ".Add", Package: poisonedMod, Filename: "poisoned.go", Line: 19},
				{Name: "os/exec.Command", Package: "os/exec"},
			},
		}},
	}
}

func reflectCaveatReport(module string) policy.ModuleReport {
	return policy.ModuleReport{
		Module:   module,
		Packages: []string{module},
		Caveats: []policy.Witness{{
			Capability: policy.CapReflect,
			Path: []capslock.FuncRef{
				{Name: module + ".Unmarshal", Package: module},
				{Name: "reflect.ValueOf", Package: "reflect"},
			},
		}},
	}
}

func TestReportAllOK(t *testing.T) {
	var buf bytes.Buffer
	assert.NilError(t, report(&buf, []policy.ModuleReport{{Module: "example.com/pure", Packages: []string{"example.com/pure"}}}, reportOptions{}))
	out := buf.String()
	assert.Assert(t, strings.Contains(out, "ok   example.com/pure"), "got %q", out)
	assert.Assert(t, strings.Contains(out, "no policy violations"), "got %q", out)
}

func TestReportViolation(t *testing.T) {
	var buf bytes.Buffer
	assert.NilError(t, report(&buf, []policy.ModuleReport{execViolationReport()}, reportOptions{}))
	out := buf.String()
	assert.Assert(t, strings.Contains(out, "FAIL "+poisonedMod), "got %q", out)
	assert.Assert(t, strings.Contains(out, policy.CapExec), "got %q", out)
	assert.Assert(t, strings.Contains(out, "os/exec.Command"), "the witness path must be printed; got %q", out)
	assert.Assert(t, strings.Contains(out, "1 violation"), "got %q", out)
}

// TestReportCaveatIsWarning: caveat-only modules print as WARN without call
// paths by default; --explain adds the paths.
func TestReportCaveatIsWarning(t *testing.T) {
	r := reflectCaveatReport("sigs.k8s.io/yaml")

	var buf bytes.Buffer
	assert.NilError(t, report(&buf, []policy.ModuleReport{r}, reportOptions{}))
	out := buf.String()
	assert.Assert(t, strings.Contains(out, "WARN sigs.k8s.io/yaml"), "got %q", out)
	assert.Assert(t, strings.Contains(out, policy.CapReflect), "got %q", out)
	assert.Assert(t, !strings.Contains(out, "reflect.ValueOf"), "paths only with --explain; got %q", out)

	buf.Reset()
	assert.NilError(t, report(&buf, []policy.ModuleReport{r}, reportOptions{Explain: true}))
	assert.Assert(t, strings.Contains(buf.String(), "reflect.ValueOf"), "got %q", buf.String())
}

// TestReportOrdersBySeverity: violations print before warnings before ok, so
// the actionable lines are at the top on a large program.
func TestReportOrdersBySeverity(t *testing.T) {
	reports := []policy.ModuleReport{
		{Module: "a.example.com/ok"},
		reflectCaveatReport("b.example.com/warn"),
		execViolationReport(),
	}
	var buf bytes.Buffer
	assert.NilError(t, report(&buf, reports, reportOptions{}))
	out := buf.String()
	fail := strings.Index(out, "FAIL ")
	warn := strings.Index(out, "WARN ")
	ok := strings.Index(out, "ok   ")
	assert.Assert(t, fail >= 0 && warn >= 0 && ok >= 0, "got %q", out)
	assert.Assert(t, fail < warn && warn < ok, "expected FAIL < WARN < ok; got %q", out)
}

func TestReportUnused(t *testing.T) {
	var buf bytes.Buffer
	assert.NilError(t, report(&buf, []policy.ModuleReport{{Module: "example.com/stale", Unused: true}}, reportOptions{}))
	assert.Assert(t, strings.Contains(buf.String(), "unused"), "got %q", buf.String())
}

// TestReportSARIF: results carry one rule per capability class, violations
// are errors, caveats are warnings (errors under strict), and each finding is
// anchored to the module's require line in go.mod.
func TestReportSARIF(t *testing.T) {
	src := &profileSource{
		GoMod:      "go.mod",
		ModuleLine: map[string]int{poisonedMod: 5},
	}
	reports := []policy.ModuleReport{execViolationReport(), reflectCaveatReport("sigs.k8s.io/yaml")}

	var buf bytes.Buffer
	assert.NilError(t, reportSARIF(&buf, reports, src, false))
	var log sarifLog
	assert.NilError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Equal(t, log.Version, "2.1.0")
	assert.Equal(t, len(log.Runs), 1)
	run := log.Runs[0]
	assert.Equal(t, run.Tool.Driver.Name, "gomodjail")
	assert.Equal(t, len(run.Tool.Driver.Rules), 2) // EXEC, REFLECT
	assert.Equal(t, len(run.Results), 2)

	exec := run.Results[0]
	assert.Equal(t, exec.RuleID, policy.CapExec)
	assert.Equal(t, exec.Level, "error")
	assert.Assert(t, strings.Contains(exec.Message.Text, poisonedMod), "got %q", exec.Message.Text)
	assert.Assert(t, strings.Contains(exec.Message.Text, "os/exec.Command"), "got %q", exec.Message.Text)
	assert.Equal(t, len(exec.Locations), 1)
	assert.Equal(t, exec.Locations[0].PhysicalLocation.ArtifactLocation.URI, "go.mod")
	assert.Equal(t, exec.Locations[0].PhysicalLocation.Region.StartLine, 5)

	caveat := run.Results[1]
	assert.Equal(t, caveat.RuleID, policy.CapReflect)
	assert.Equal(t, caveat.Level, "warning")
	// A module missing from ModuleLine still gets the go.mod artifact, just
	// without a region.
	assert.Equal(t, len(caveat.Locations), 1)
	assert.Assert(t, caveat.Locations[0].PhysicalLocation.Region == nil)

	buf.Reset()
	assert.NilError(t, reportSARIF(&buf, reports, src, true))
	assert.NilError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Equal(t, log.Runs[0].Results[1].Level, "error", "--strict must promote caveats")
}

// withWorkdir runs fn with the process working directory temporarily set to
// dir. The analyze command (and Capslock) load packages relative to cwd, so
// the end-to-end tests must run from the target module root.
func withWorkdir(t *testing.T, dir string, fn func()) {
	t.Helper()
	orig, err := os.Getwd()
	assert.NilError(t, err)
	assert.NilError(t, os.Chdir(dir))
	defer func() { assert.NilError(t, os.Chdir(orig)) }()
	fn()
}

func victimDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "examples", "victim"))
	assert.NilError(t, err)
	return dir
}

func runAnalyze(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// TestAnalyzeVictimFails is the headline regression: analyzing examples/victim,
// whose go.mod confines the poisoned module, must fail with the EXEC violation
// attributed to poisoned.
func TestAnalyzeVictimFails(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		out, err := runAnalyze(t, "./...")
		assert.Assert(t, err != nil, "analyze must fail; out=%q", out)
		assert.Assert(t, strings.Contains(out, "FAIL "+poisonedMod), "out=%q", out)
		assert.Assert(t, strings.Contains(out, policy.CapExec), "out=%q", out)
	})
}

// runAnalyzeStdout is runAnalyze with stderr kept separate, for asserting on
// machine-readable stdout (cobra prints the returned error to stderr).
func runAnalyzeStdout(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestAnalyzeVictimSARIF: the end-to-end SARIF run over examples/victim
// anchors the EXEC finding to poisoned's require line in go.mod.
func TestAnalyzeVictimSARIF(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		out, err := runAnalyzeStdout(t, "--format=sarif", "./...")
		assert.Assert(t, err != nil, "analyze must fail; out=%q", out)
		var log sarifLog
		// Decode only the first JSON value: on error cobra appends usage text
		// to the output stream.
		assert.NilError(t, json.NewDecoder(strings.NewReader(out)).Decode(&log))
		assert.Equal(t, len(log.Runs), 1)
		var exec *sarifResult
		for i := range log.Runs[0].Results {
			if log.Runs[0].Results[i].RuleID == policy.CapExec {
				exec = &log.Runs[0].Results[i]
				break
			}
		}
		assert.Assert(t, exec != nil, "expected an EXEC result; out=%q", out)
		assert.Equal(t, exec.Level, "error")
		assert.Equal(t, exec.Locations[0].PhysicalLocation.ArtifactLocation.URI, "go.mod")
		// poisoned's require line in examples/victim/go.mod.
		assert.Equal(t, exec.Locations[0].PhysicalLocation.Region.StartLine, 5)
	})
}

// benignFixture writes a two-module fixture into a temp dir: app depends on
// dep, and dep only round-trips JSON — no filesystem, exec, network or
// syscalls, but (like nearly every real-world marshaling module) it reaches
// reflect through encoding/json. This is the golden negative for the tiered
// severity model: dynamic mode would confine dep happily, so the static gate
// must pass it too, with a warning rather than a violation.
func benignFixture(t *testing.T) (appDir string) {
	t.Helper()
	root := t.TempDir()
	appDir = filepath.Join(root, "app")
	depDir := filepath.Join(root, "dep")
	assert.NilError(t, os.MkdirAll(appDir, 0o755))
	assert.NilError(t, os.MkdirAll(depDir, 0o755))

	write := func(path, content string) {
		t.Helper()
		assert.NilError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	write(filepath.Join(depDir, "go.mod"), "module example.com/dep\n\ngo 1.23\n")
	write(filepath.Join(depDir, "dep.go"), `package dep

import "encoding/json"

// Roundtrip is pure computation: no filesystem, exec, network or syscalls.
func Roundtrip(b []byte) (string, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	out, err := json.Marshal(v)
	return string(out), err
}
`)
	write(filepath.Join(appDir, "go.mod"), `module example.com/app

go 1.23

require example.com/dep v0.0.0-00010101000000-000000000000 // gomodjail:confined

replace example.com/dep => ../dep
`)
	write(filepath.Join(appDir, "main.go"), `package main

import "example.com/dep"

func main() {
	s, _ := dep.Roundtrip([]byte("{}"))
	_ = s
}
`)
	return appDir
}

// TestAnalyzeBenignModulePassesWithWarning: the fixture's confined dep passes
// the default gate (exit 0) with a REFLECT warning, and fails under --strict.
func TestAnalyzeBenignModulePassesWithWarning(t *testing.T) {
	appDir := benignFixture(t)
	withWorkdir(t, appDir, func() {
		out, err := runAnalyze(t, "./...")
		assert.NilError(t, err, "caveats must not fail the default gate; out=%q", out)
		assert.Assert(t, strings.Contains(out, "WARN example.com/dep"), "out=%q", out)
		assert.Assert(t, strings.Contains(out, policy.CapReflect), "out=%q", out)

		out, err = runAnalyze(t, "--strict", "./...")
		assert.Assert(t, err != nil, "--strict must promote warnings to failures; out=%q", out)
	})
}

// TestAnalyzeUnusedConfinedModule: confining a module that is not part of the
// build passes, but is called out as unused rather than silently verified.
func TestAnalyzeUnusedConfinedModule(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		out, err := runAnalyze(t, "--go-mod=", "--policy=example.com/not-a-dependency=confined", "./...")
		assert.NilError(t, err, "out=%q", out)
		assert.Assert(t, strings.Contains(out, "unused"), "out=%q", out)
	})
}

// TestAnalyzeNoConfinedModules errors helpfully rather than silently passing
// when nothing is confined — a security gate should not no-op on
// misconfiguration.
func TestAnalyzeNoConfinedModules(t *testing.T) {
	withWorkdir(t, victimDir(t), func() {
		_, err := runAnalyze(t, "--go-mod=", "./...")
		assert.ErrorContains(t, err, "no confined modules")
	})
}

// TestAnalyzeGoModOutsideWorkdir: --go-mod pointing at another module's
// go.mod must analyze that module, not whatever module the process happens
// to run in — otherwise every confined module would be reported unused and
// the gate would pass vacuously.
func TestAnalyzeGoModOutsideWorkdir(t *testing.T) {
	appDir := benignFixture(t)
	out, err := runAnalyze(t, "--go-mod="+filepath.Join(appDir, "go.mod"), "./...")
	assert.NilError(t, err, "out=%q", out)
	assert.Assert(t, strings.Contains(out, "WARN example.com/dep"), "out=%q", out)
	assert.Assert(t, !strings.Contains(out, "unused"), "out=%q", out)
}

// TestReportEscapesControlChars: witness-path filenames originate in
// analyzed source and can be freely chosen via a //line directive, so a
// malicious confined dependency could embed ANSI escape sequences to forge
// or hide terminal output. The text reporter must escape them.
func TestReportEscapesControlChars(t *testing.T) {
	r := policy.ModuleReport{
		Module:   "example.com/evil",
		Packages: []string{"example.com/evil"},
		Violations: []policy.Witness{{
			Capability: policy.CapExec,
			Path: []capslock.FuncRef{
				{Name: "example.com/evil.F", Package: "example.com/evil",
					Filename: "ok\x1b[2J\x1b[1;1Hfake.go", Line: 1},
				{Name: "os/exec.Command", Package: "os/exec"},
			},
		}},
	}
	var buf bytes.Buffer
	assert.NilError(t, report(&buf, []policy.ModuleReport{r}, reportOptions{}))
	out := buf.String()
	assert.Assert(t, !strings.ContainsRune(out, '\x1b'), "raw escape byte in output: %q", out)
	assert.Assert(t, strings.Contains(out, `ok\x1b[2J\x1b[1;1Hfake.go`), "got %q", out)
}

// TestAnalyzeJSONMetadata: the JSON report must identify the inputs it was
// generated from (go.mod digest, target platform, patterns), so that
// `gomodjail fix --from-report` can verify it is not stale.
func TestAnalyzeJSONMetadata(t *testing.T) {
	appDir := benignFixture(t)
	goMod := filepath.Join(appDir, "go.mod")
	out, err := runAnalyze(t, "--go-mod="+goMod, "./...")
	assert.NilError(t, err, "out=%q", out)

	out, err = runAnalyze(t, "--go-mod="+goMod, "--format=json", "./...")
	assert.NilError(t, err, "out=%q", out)
	var report struct {
		Metadata struct {
			GoModSHA256 string   `json:"goModSHA256"`
			GoVersion   string   `json:"goVersion"`
			GoFlags     string   `json:"goFlags"`
			GOOS        string   `json:"goos"`
			GOARCH      string   `json:"goarch"`
			Patterns    []string `json:"patterns"`
		} `json:"metadata"`
	}
	assert.NilError(t, json.Unmarshal([]byte(out), &report))
	b, err := os.ReadFile(goMod)
	assert.NilError(t, err)
	sum := sha256.Sum256(b)
	assert.Equal(t, report.Metadata.GoModSHA256, hex.EncodeToString(sum[:]))
	goVersion, err := goToolchainVersion(appDir)
	assert.NilError(t, err)
	assert.Equal(t, report.Metadata.GoVersion, goVersion)
	goFlags, err := goEnv(appDir, "GOFLAGS")
	assert.NilError(t, err)
	assert.Equal(t, report.Metadata.GoFlags, goFlags)
	assert.Equal(t, report.Metadata.GOOS, runtime.GOOS)
	assert.Equal(t, report.Metadata.GOARCH, runtime.GOARCH)
	assert.DeepEqual(t, report.Metadata.Patterns, []string{"./..."})
}

// TestAnalyzeRejectsNonGoModBasename: go/packages always loads the
// directory's literal go.mod, so an alternate --go-mod file name would read
// policy from one file while silently analyzing another module graph.
func TestAnalyzeRejectsNonGoModBasename(t *testing.T) {
	dir := t.TempDir()
	assert.NilError(t, os.WriteFile(filepath.Join(dir, "policy.mod"),
		[]byte("module example.com/app\n\ngo 1.23\n\nrequire example.com/dep v1.0.0 // gomodjail:confined\n"), 0o644))
	_, err := runAnalyze(t, "--go-mod="+filepath.Join(dir, "policy.mod"), "./...")
	assert.ErrorContains(t, err, "must point at a file named go.mod")
}

// TestReportMetadataStaleGoMod: the metadata digest must describe the
// go.mod the findings came from; if the file changed during the analysis,
// report generation is refused rather than stamping a digest for contents
// that were never analyzed.
func TestReportMetadataStaleGoMod(t *testing.T) {
	goMod := filepath.Join(t.TempDir(), "go.mod")
	orig := []byte("module example.com/app\n\ngo 1.23\n")
	assert.NilError(t, os.WriteFile(goMod, orig, 0o644))
	assert.NilError(t, os.WriteFile(goMod, append(orig, []byte("// edited\n")...), 0o644))
	_, err := newReportMetadata(goMod, orig, "", "", []string{"./..."})
	assert.ErrorContains(t, err, "changed while the analysis was running")
}

// TestPathURI: SARIF artifactLocation.uri must be a URI reference, not a
// raw filesystem path — spaces and other reserved characters need
// percent-encoding.
func TestPathURI(t *testing.T) {
	for path, want := range map[string]string{
		"go.mod":           "go.mod",
		"my dir/go.mod":    "my%20dir/go.mod",
		"/abs path/go.mod": "/abs%20path/go.mod",
	} {
		assert.Equal(t, pathURI(path), want)
	}
}

// TestSARIFCleanScanEmitsEmptyResults: SARIF defines results as an array;
// a clean scan must emit [] rather than null, which some code-scanning
// consumers reject — and a clean scan is exactly the report worth uploading.
func TestSARIFCleanScanEmitsEmptyResults(t *testing.T) {
	var buf bytes.Buffer
	reports := []policy.ModuleReport{{Module: "example.com/pure", Packages: []string{"example.com/pure"}}}
	assert.NilError(t, reportSARIF(&buf, reports, nil, false))
	assert.Assert(t, strings.Contains(buf.String(), `"results": []`), "got %q", buf.String())
}
