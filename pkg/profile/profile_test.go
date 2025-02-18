package profile

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestProfile(t *testing.T) {
	prof := New()
	prof.Modules["example.com/foo"] = PolicyConfined
	prof.Modules["example.com/foobaz"] = PolicyConfined
	assert.NilError(t, prof.Validate())
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined("example.com/foo"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined("example.com/foo/bar"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined("example.com/foo.fn"))
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foo",
		Policy: PolicyConfined,
	}, prof.Confined("example.com/foo/bar.fn"))
	assert.Assert(t, prof.Confined("example.com/foobar.fn") == nil)
	assert.DeepEqual(t, &Confinment{
		Module: "example.com/foobaz",
		Policy: PolicyConfined,
	}, prof.Confined("example.com/foobaz.fn"))
	assert.Assert(t, prof.Confined("example.com/baz.fn") == nil)
}
