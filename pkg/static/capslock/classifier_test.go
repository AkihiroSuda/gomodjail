package capslock_test

import (
	"go/types"
	"os"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/static/capslock"
)

// TestClassifierPinning pins the classification of the sinks gomodjail's
// severity tiers are calibrated against (design v2 §11, "classifier-pinning
// test"). It covers both directions:
//
//   - gomodjail.cm overrides took effect (FD-I/O parity, the FILES
//     read/write split, VTA-pollution fixes);
//   - the pinned Capslock's builtin map still classifies the canonical
//     dangerous sinks the way the policy tiers assume.
//
// If a Capslock version bump changes any of these, this test fails and the
// change becomes a reviewable event instead of a silent policy shift.
func TestClassifierPinning(t *testing.T) {
	classifier, err := capslock.LoadClassifierForTest()
	assert.NilError(t, err)

	for _, tc := range []struct {
		pkg, fn, want string
	}{
		// gomodjail.cm: I/O on already-held handles is SAFE.
		{"os", "(*os.File).Write", "SAFE"},
		// gomodjail.cm: the higher-order FD methods stay traversable so a
		// malicious callback surfaces (as an UNANALYZED caveat at io.Copy);
		// only their FD-to-FD fast paths and pure helpers are SAFE.
		{"os", "(*os.File).ReadFrom", ""},
		{"os", "(*os.File).WriteTo", ""},
		{"os", "os.genericReadFrom", ""},
		{"os", "(*os.File).readFrom", "SAFE"},
		{"os", "(*os.File).checkValid", "SAFE"},
		{"os", "(*os.File).Read", "SAFE"},
		{"os", "(*os.File).Close", "SAFE"},
		{"os", "(*os.File).Stat", "SAFE"},
		{"os", "(*os.fileStat).IsDir", "SAFE"},
		{"os", "os.SameFile", "SAFE"},
		{"os", "os.Pipe", "SAFE"},
		// gomodjail.cm: VTA-pollution fixes.
		{"net/http", "(*net/http.timeoutError).Is", "SAFE"},
		{"net/http", "(net/http.eofReader).ReadByte", "SAFE"},
		// gomodjail.cm: the FILES read/write split.
		{"os", "os.Open", "FILES/READ"},
		{"os", "os.ReadFile", "FILES/READ"},
		{"os", "os.Lstat", "FILES/READ"},
		{"os", "(*os.File).Readdirnames", "FILES/READ"},
		{"os", "(*os.Root).Open", "FILES/READ"},
		{"os/exec", "os/exec.LookPath", "FILES/READ"},
		{"os", "os.Create", "FILES/WRITE"},
		{"os", "os.OpenFile", "FILES/WRITE"},
		{"os", "os.Remove", "FILES/WRITE"},
		{"os", "os.Rename", "FILES/WRITE"},
		{"os", "(*os.File).Chmod", "FILES/WRITE"},
		{"os", "(*os.Root).WriteFile", "FILES/WRITE"},
		// Deliberately unsplit.
		{"runtime/debug", "runtime/debug.WriteHeapDump", "FILES"},
		// Capslock builtin sinks the Deny tier is calibrated against.
		{"os/exec", "os/exec.Command", "EXEC"},
		{"os/exec", "(*os/exec.Cmd).Run", "EXEC"},
		{"net", "net.Dial", "NETWORK"},
		{"os", "os.Setenv", "MODIFY_SYSTEM_STATE/ENV"},
		{"os", "os.StartProcess", "EXEC"},
		// Functions without an individual entry inherit their package's
		// classification; for package os that is OPERATING_SYSTEM.
		{"os", "(*os.Process).Kill", "OPERATING_SYSTEM"},
		{"syscall", "syscall.Syscall", "SYSTEM_CALLS"},
		// gomodjail.cm: syscall-backed members of READ_SYSTEM_STATE (an
		// Allow tier) are reclassified to what they do; the rest need no
		// syscall or only ones dynamic mode always allowed.
		{"os", "os.Executable", "FILES/READ"},
		{"os", "os.FindProcess", "OPERATING_SYSTEM"},
		{"net", "net.Interfaces", "NETWORK"},
		{"os/user", "os/user.Current", "FILES/READ"},
		{"os", "os.Getenv", "READ_SYSTEM_STATE"},
		{"os", "os.Getwd", "READ_SYSTEM_STATE"},
		{"os", "os.Getpid", "READ_SYSTEM_STATE"},
	} {
		assert.Equal(t, classifier.FunctionCategory(tc.pkg, tc.fn), tc.want,
			"classification of %s", tc.fn)
	}
}

// TestClassifierOverridesEffective enumerates every entry of gomodjail.cm
// and asserts the merged classifier actually returns that classification:
// an entry the loader silently ignored, or one whose symbol fell back to
// its package's builtin category, fails here. (TestClassifierPinning above
// stays as the semantic calibration set, including Capslock builtin sinks
// that gomodjail.cm does not touch.)
func TestClassifierOverridesEffective(t *testing.T) {
	classifier, err := capslock.LoadClassifierForTest()
	assert.NilError(t, err)
	b, err := os.ReadFile("gomodjail.cm")
	assert.NilError(t, err)
	entries := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// Every entry is currently "func <symbol> <capability>"; a new entry
		// kind must extend this test before it can be used.
		assert.Equal(t, len(fields), 3, "unexpected gomodjail.cm line %q", line)
		assert.Equal(t, fields[0], "func", "unexpected gomodjail.cm line %q", line)
		name := fields[1]
		want := strings.TrimPrefix(fields[2], "CAPABILITY_")
		if want == "UNSPECIFIED" {
			// The loader stores UNSPECIFIED as an empty category: the
			// function-level entry still takes precedence over the package
			// fallback, which is exactly what makes the function traversable.
			want = ""
		}
		got := classifier.FunctionCategory(packageOf(t, name), name)
		assert.Equal(t, got, want, "gomodjail.cm override for %s is not effective", name)
		entries++
	}
	assert.Assert(t, entries > 0, "no entries parsed from gomodjail.cm")
	t.Logf("verified %d gomodjail.cm overrides", entries)
}

// packageOf extracts the package path from a capability-map symbol name,
// e.g. "(*os.File).Read" -> "os", "(net/http.eofReader).Read" -> "net/http",
// "os/exec.LookPath" -> "os/exec". Passing the right package matters: it is
// the fallback FunctionCategory uses when the symbol has no entry of its
// own, which is exactly the case this test must detect, not mask.
func packageOf(t *testing.T, name string) string {
	t.Helper()
	s := strings.TrimPrefix(strings.TrimPrefix(name, "(*"), "(")
	if i := strings.Index(s, ")"); i >= 0 {
		s = s[:i]
	}
	i := strings.LastIndex(s, ".")
	assert.Assert(t, i > 0, "cannot derive package from symbol %q", name)
	return s[:i]
}

// TestClassifierOverrideSymbolsExist resolves every gomodjail.cm symbol
// against the real standard library: the package must exist, and so must
// the function or the (possibly unexported) receiver type and method. This
// is the other half of override pinning: TestClassifierOverridesEffective
// proves each entry is loaded, but a misspelled symbol name would load fine
// while the real symbol silently keeps its builtin classification.
func TestClassifierOverrideSymbolsExist(t *testing.T) {
	// goVersionDependent lists gomodjail.cm symbols that exist only on some
	// Go versions: Go 1.27 moved the http2 code bundled into net/http
	// (h2_bundle.go, http2-prefixed symbols) to net/http/internal/http2.
	// The entries stay in gomodjail.cm for older toolchains — the analyzed
	// stdlib is the user's — and are dead but harmless on newer ones (with
	// no exact package-category entry for the new location, Capslock just
	// analyzes the relocated helpers, which are pure). A missing symbol on
	// this list is logged instead of failed; anything else must resolve.
	goVersionDependent := map[string]struct{}{
		"(net/http.http2eofReader).Read":     {},
		"(net/http.http2eofReader).ReadByte": {},
	}

	b, err := os.ReadFile("gomodjail.cm")
	assert.NilError(t, err)
	type sym struct {
		name         string // the gomodjail.cm spelling
		pkg, typ, fn string // typ == "" for a package-scope function
	}
	var syms []sym
	pkgSet := make(map[string]struct{})
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		orig := strings.Fields(line)[1]
		// "os.CopyFS$1" is Capslock's SSA name for a function literal inside
		// os.CopyFS; the closure itself has no scope entry, so resolve the
		// enclosing function instead.
		name, _, _ := strings.Cut(orig, "$")
		s := sym{name: orig}
		if recv, method, ok := strings.Cut(name, ")."); ok {
			recv = strings.TrimPrefix(strings.TrimPrefix(recv, "(*"), "(")
			i := strings.LastIndex(recv, ".")
			assert.Assert(t, i > 0, "cannot parse symbol %q", name)
			s.pkg, s.typ, s.fn = recv[:i], recv[i+1:], method
		} else {
			i := strings.LastIndex(name, ".")
			assert.Assert(t, i > 0, "cannot parse symbol %q", name)
			s.pkg, s.fn = name[:i], name[i+1:]
		}
		syms = append(syms, s)
		pkgSet[s.pkg] = struct{}{}
	}

	patterns := make([]string, 0, len(pkgSet))
	for p := range pkgSet {
		patterns = append(patterns, p)
	}
	// The listed packages must be type-checked from source (NeedSyntax):
	// export data omits unexported package-level types such as
	// net/http.timeoutError, and most of the VTA-pollution overrides target
	// exactly those.
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports |
		packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, patterns...)
	assert.NilError(t, err)
	assert.Equal(t, packages.PrintErrors(pkgs), 0)
	byPath := make(map[string]*packages.Package, len(pkgs))
	for _, p := range pkgs {
		byPath[p.PkgPath] = p
	}

	for _, s := range syms {
		exists := false
		if p := byPath[s.pkg]; p != nil {
			if s.typ == "" {
				exists = p.Types.Scope().Lookup(s.fn) != nil
			} else if obj := p.Types.Scope().Lookup(s.typ); obj != nil {
				// The pointer method set contains both pointer- and
				// value-receiver methods; Lookup needs the package for
				// unexported names.
				ms := types.NewMethodSet(types.NewPointer(obj.Type()))
				exists = ms.Lookup(p.Types, s.fn) != nil
			}
		}
		if !exists {
			if _, ok := goVersionDependent[s.name]; ok {
				t.Logf("skipping %s: not in this Go version's standard library", s.name)
				continue
			}
			t.Errorf("gomodjail.cm names %s, which does not exist in the standard library", s.name)
		}
	}
	t.Logf("resolved %d gomodjail.cm symbols against %d packages", len(syms), len(pkgs))
}
