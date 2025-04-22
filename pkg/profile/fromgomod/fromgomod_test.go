package fromgomod

import (
	"testing"

	"github.com/AkihiroSuda/gomodjail/pkg/profile"
	"golang.org/x/mod/modfile"
	"gotest.tools/v3/assert"
)

func TestFromGoMod(t *testing.T) {
	type testCase struct {
		name     string
		goMod    string
		expected map[string]profile.Policy
	}
	testCases := []testCase{
		{
			name: "basic",
			goMod: `
module example.com/foo

go 1.23

require (
	example.com/mod100 v1.2.3 // gomodjail:confined
	example.com/mod101 v1.2.3
	// gomodjail:confined
	example.com/mod102 v1.2.3
	example.com/mod103 v1.2.3
	example.com/mod104 v1.2.3 //gomodjail:confined
)

require (
	example.com/mod200 v1.2.3 // indirect
	example.com/mod201 v1.2.3 // indirect; gomodjail:confined
	example.com/mod202 v1.2.3 // indirect // gomodjail:confined
	// gomodjail:confined
	example.com/mod203 v1.2.4 // indirect
	example.com/mod204 v1.2.3 // indirect //gomodjail:confined
)
`,
			expected: map[string]string{
				"example.com/mod100": "confined",
				"example.com/mod102": "confined",
				"example.com/mod104": "confined",
				"example.com/mod201": "confined",
				"example.com/mod202": "confined",
				"example.com/mod203": "confined",
				"example.com/mod204": "confined",
			},
		},

		{
			name: "global",
			goMod: `
// gomodjail:confined
module example.com/foo

go 1.23

require (
	example.com/mod100 v1.2.3
	example.com/mod101 v1.2.3 // gomodjail:unconfined
	example.com/mod102 v1.2.3
	// gomodjail:unconfined
	example.com/mod103 v1.2.3
)

require (
	// gomodjail:unconfined
	example.com/mod200 v1.2.3 // indirect
	example.com/mod201 v1.2.3 // indirect
	example.com/mod202 v1.2.3 // indirect
)

// policy cannot be specified here because the parser ignores
// the comment lines here
require (
)
`,
			expected: map[string]string{
				"example.com/mod100": "confined",
				"example.com/mod102": "confined",
				"example.com/mod201": "confined",
				"example.com/mod202": "confined",
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mod, err := modfile.Parse(tc.name, []byte(tc.goMod), nil)
			assert.NilError(t, err)
			prof := profile.New()
			assert.NilError(t, FromGoMod(mod, prof))
			assert.DeepEqual(t, "example.com/foo", prof.Module)
			assert.DeepEqual(t, tc.expected, prof.Modules)
		})
	}
}
