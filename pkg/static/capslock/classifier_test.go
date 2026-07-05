package capslock_test

import (
	"testing"

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
		{"os", "os.Getenv", "READ_SYSTEM_STATE"},
	} {
		assert.Equal(t, classifier.FunctionCategory(tc.pkg, tc.fn), tc.want,
			"classification of %s", tc.fn)
	}
}
