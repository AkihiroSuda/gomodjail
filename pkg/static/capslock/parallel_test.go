package capslock_test

import (
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
)

// parallelFixture builds a multi-module program whose three confined modules
// all import a shared module that uses the call shapes Capslock rewrites in
// place (sort.Sort/sort.Slice/(*sync.Once).Do). The shared package is the
// contended AST when the per-module analyses run concurrently, so this
// fixture exercises the warm-up rewrite path; run with -race to verify the
// analyses really stop mutating shared state.
func parallelFixture(t *testing.T) (appDir string, confined []string) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		assert.NilError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		assert.NilError(t, os.WriteFile(path, []byte(content), 0o644))
	}

	write("shared/go.mod", "module example.com/shared\n\ngo 1.23\n")
	write("shared/shared.go", `package shared

import (
	"sort"
	"sync"
)

var once sync.Once

func Sorted(xs []int) []int {
	once.Do(func() {})
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	sort.Sort(sort.IntSlice(xs))
	return xs
}
`)
	depGoMod := func(name string) string {
		return "module example.com/" + name + "\n\ngo 1.23\n\nrequire example.com/shared v0.0.0\n"
	}
	write("depexec/go.mod", depGoMod("depexec"))
	write("depexec/depexec.go", `package depexec

import (
	"os/exec"

	"example.com/shared"
)

func Run() error {
	shared.Sorted([]int{2, 1})
	return exec.Command("true").Run()
}
`)
	write("depread/go.mod", depGoMod("depread"))
	write("depread/depread.go", `package depread

import (
	"os"

	"example.com/shared"
)

func Read() ([]byte, error) {
	shared.Sorted([]int{2, 1})
	return os.ReadFile("f")
}
`)
	write("deppure/go.mod", depGoMod("deppure"))
	write("deppure/deppure.go", `package deppure

import "example.com/shared"

func Max(xs []int) int {
	xs = shared.Sorted(xs)
	return xs[len(xs)-1]
}
`)
	write("app/go.mod", `module example.com/app

go 1.23

require (
	example.com/depexec v0.0.0
	example.com/deppure v0.0.0
	example.com/depread v0.0.0
)

require example.com/shared v0.0.0 // indirect

replace (
	example.com/depexec => ../depexec
	example.com/deppure => ../deppure
	example.com/depread => ../depread
	example.com/shared => ../shared
)
`)
	write("app/main.go", `package main

import (
	"example.com/depexec"
	"example.com/deppure"
	"example.com/depread"
)

func main() {
	_ = depexec.Run()
	_, _ = depread.Read()
	_ = deppure.Max([]int{1, 2})
}
`)
	return filepath.Join(root, "app"),
		[]string{"example.com/depexec", "example.com/deppure", "example.com/depread", "example.com/shared"}
}

// TestParallelAnalysisMatchesSequential: analyzing the confined modules
// concurrently must produce exactly the sequential result — same findings,
// same witness paths, same attribution.
func TestParallelAnalysisMatchesSequential(t *testing.T) {
	appDir, confined := parallelFixture(t)
	seq, err := capslock.Analyze(capslock.Options{Dir: appDir, ConfinedModules: confined, Parallel: 1})
	assert.NilError(t, err)
	assert.Assert(t, hasCapability(seq.Findings, capEXEC),
		"expected %s from depexec; got %v", capEXEC, capabilities(seq.Findings))

	par, err := capslock.Analyze(capslock.Options{Dir: appDir, ConfinedModules: confined, Parallel: 4})
	assert.NilError(t, err)
	assert.DeepEqual(t, par, seq)
}

// TestParallelAnalysisResidualRewriteFallback: sort.Sort(nil) type-checks
// but its rewrite cannot succeed (an untyped nil has no method set), so
// Capslock's own rewrite pass re-writes shared type information for the
// site on every visit — such a site is never read-only. Analyze must detect
// the residue during warm-up and fall back to sequential analysis; under
// -race this test fails without the fallback. The site lives in dead code
// on purpose: that is where it survives in real dependencies (it would
// panic if ever executed).
func TestParallelAnalysisResidualRewriteFallback(t *testing.T) {
	appDir, confined := parallelFixture(t)
	residual := filepath.Join(appDir, "..", "shared", "residual.go")
	assert.NilError(t, os.WriteFile(residual, []byte(`package shared

import "sort"

func deadResidual() {
	sort.Sort(nil)
}
`), 0o644))

	seq, err := capslock.Analyze(capslock.Options{Dir: appDir, ConfinedModules: confined, Parallel: 1})
	assert.NilError(t, err)
	par, err := capslock.Analyze(capslock.Options{Dir: appDir, ConfinedModules: confined, Parallel: 4})
	assert.NilError(t, err)
	assert.DeepEqual(t, par, seq)
}
