package profile

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestProfile(t *testing.T) {
	prof := New()
	const mainMod = "example.com/blah/v2"
	prof.Module = mainMod
	prof.Modules["example.com/foo"] = PolicyConfined
	prof.Modules["example.com/foobaz"] = PolicyConfined
	assert.NilError(t, prof.Validate())
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined(mainMod, "example.com/foo"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined(mainMod, "example.com/foo/bar"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined(mainMod, "example.com/foo.fn"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined(mainMod, "example.com/foo/bar.fn"))
	assert.Assert(t, prof.Confined(mainMod, "example.com/foobar.fn") == nil)
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foobaz",
		Policy: PolicyConfined,
	}, prof.Confined(mainMod, "example.com/foobaz.fn"))
	assert.Assert(t, prof.Confined(mainMod, "example.com/baz.fn") == nil)
}
