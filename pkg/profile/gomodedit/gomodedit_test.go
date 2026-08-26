package gomodedit

import (
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"gotest.tools/v3/assert"

	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile"
	"github.com/AkihiroSuda/gomodjail/v2/pkg/profile/fromgomod"
)

// setPolicy parses goMod, applies SetPolicy, and returns the formatted file
// plus the policies fromgomod reads back from it — the round-trip through the
// real parser is the property that matters.
func setPolicy(t *testing.T, goMod, module, policy string) (out string, policies map[string]string, changed bool) {
	t.Helper()
	mf, err := modfile.Parse("go.mod", []byte(goMod), nil)
	assert.NilError(t, err)
	changed, err = SetPolicy(mf, module, policy)
	assert.NilError(t, err)
	out = string(modfile.Format(mf.Syntax))

	mf2, err := modfile.Parse("go.mod", []byte(out), nil)
	assert.NilError(t, err)
	prof := profile.New()
	assert.NilError(t, fromgomod.FromGoMod(mf2, prof))
	return out, prof.Modules, changed
}

func TestSetPolicyRewritesSuffixAnnotation(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

require example.com/dep v1.0.0 // gomodjail:confined
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "// gomodjail:unconfined"), "got %q", out)
	assert.Assert(t, !strings.Contains(out, "gomodjail:confined"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
}

func TestSetPolicyPreservesSurroundingCommentText(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

require example.com/dep v1.0.0 // reviewed 2025-01-02  gomodjail:confined  (see issue 42)
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "// reviewed 2025-01-02  gomodjail:unconfined  (see issue 42)"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
}

func TestSetPolicyRewritesBeforeComment(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

require (
	// gomodjail:confined
	example.com/dep v1.0.0
	example.com/other v1.0.0
)
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "// gomodjail:unconfined"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
	assert.Equal(t, policies["example.com/other"], "")
}

// TestSetPolicyOverridesBlockDefault: an annotation on the require block
// applies to every line in it; the fix must not touch the block comment (that
// would flip the other modules) but add a per-line override instead.
func TestSetPolicyOverridesBlockDefault(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

// gomodjail:confined
require (
	example.com/dep v1.0.0
	example.com/other v1.0.0
)
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "example.com/dep v1.0.0 // gomodjail:unconfined"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
	assert.Equal(t, policies["example.com/other"], "confined")
}

// TestSetPolicyOverridesFileDefault: same for a default set on the module
// directive.
func TestSetPolicyOverridesFileDefault(t *testing.T) {
	const goMod = `// gomodjail:confined
module example.com/app

go 1.23

require (
	example.com/dep v1.0.0
	example.com/other v1.0.0
)
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "example.com/dep v1.0.0 // gomodjail:unconfined"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
	assert.Equal(t, policies["example.com/other"], "confined")
}

// TestSetPolicyKeepsIndirectMarker: the `// indirect` suffix is parsed by the
// go command and other toolchains, so it must stay byte-for-byte intact; the
// annotation goes on its own line above the require instead.
func TestSetPolicyKeepsIndirectMarker(t *testing.T) {
	const goMod = `// gomodjail:confined
module example.com/app

go 1.23

require example.com/dep v1.0.0 // indirect
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "//gomodjail:unconfined\nrequire example.com/dep v1.0.0 // indirect"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")

	mf, err := modfile.Parse("go.mod", []byte(out), nil)
	assert.NilError(t, err)
	assert.Assert(t, mf.Require[0].Indirect, "the indirect marker must survive; got %q", out)
}

// TestSetPolicyIndirectInBlock: same for an indirect require inside a
// require block — the annotation line is indented with the block, and the
// per-line Before annotation overrides the block default without touching
// the sibling line.
func TestSetPolicyIndirectInBlock(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

// gomodjail:confined
require (
	example.com/dep v1.0.0 // indirect
	example.com/other v1.0.0 // indirect
)
`
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "\t//gomodjail:unconfined\n\texample.com/dep v1.0.0 // indirect"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")
	assert.Equal(t, policies["example.com/other"], "confined")

	mf, err := modfile.Parse("go.mod", []byte(out), nil)
	assert.NilError(t, err)
	for _, req := range mf.Require {
		assert.Assert(t, req.Indirect, "the indirect marker must survive on %s; got %q", req.Mod.Path, out)
	}
}

// TestSetPolicyMatchesParserGrammar: the rewrite grammar must be exactly the
// parser's — an extra "//" or non-ASCII whitespace still counts as an
// annotation. If the rewrite missed one, SetPolicy would append a second
// annotation that loses to the first on reparse, and fix would report success
// while the module stays confined.
func TestSetPolicyMatchesParserGrammar(t *testing.T) {
	for _, suffix := range []string{
		"////gomodjail:confined",
		"// //gomodjail:confined",
		"// gomodjail:confined", // NBSP is Unicode whitespace
	} {
		goMod := "module example.com/app\n\ngo 1.23\n\nrequire example.com/dep v1.0.0 " + suffix + "\n"
		out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
		assert.Assert(t, changed, "suffix %q: got %q", suffix, out)
		assert.Equal(t, policies["example.com/dep"], "", "suffix %q: got %q", suffix, out)
		assert.Assert(t, !strings.Contains(out, "gomodjail:confined"), "suffix %q: got %q", suffix, out)
	}
}

// TestSetPolicyIndirectWithExistingAnnotation: an annotation already present
// in the indirect suffix ("// indirect; gomodjail:confined") is rewritten in
// place, which keeps the marker's "// indirect; <text>" form valid.
func TestSetPolicyIndirectWithExistingAnnotation(t *testing.T) {
	const goMod = "module example.com/app\n\ngo 1.23\n\nrequire example.com/dep v1.0.0 // indirect; gomodjail:confined\n"
	out, policies, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, changed)
	assert.Assert(t, strings.Contains(out, "// indirect; gomodjail:unconfined"), "got %q", out)
	assert.Equal(t, policies["example.com/dep"], "")

	mf, err := modfile.Parse("go.mod", []byte(out), nil)
	assert.NilError(t, err)
	assert.Assert(t, mf.Require[0].Indirect, "the indirect marker must survive; got %q", out)
}

func TestSetPolicyNoChangeWhenAlreadySet(t *testing.T) {
	const goMod = `module example.com/app

go 1.23

require example.com/dep v1.0.0 // gomodjail:unconfined
`
	out, _, changed := setPolicy(t, goMod, "example.com/dep", "unconfined")
	assert.Assert(t, !changed, "got %q", out)
}

func TestSetPolicyUnknownModule(t *testing.T) {
	mf, err := modfile.Parse("go.mod", []byte("module example.com/app\n\ngo 1.23\n"), nil)
	assert.NilError(t, err)
	_, err = SetPolicy(mf, "example.com/dep", "unconfined")
	assert.ErrorContains(t, err, "no require line")
}
