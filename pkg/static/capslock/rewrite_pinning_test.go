package capslock_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

// TestRewritePinning pins the upstream Capslock sources that rewrite.go is
// copied from. rewrite.go must stay behaviorally identical to the pinned
// Capslock's own rewrite pass (see the comment there for why); this test
// makes a Capslock bump that touches those sources a visible, reviewable
// event instead of a silent divergence.
//
// When it fails: diff the new upstream analyzer/rewrite.go (all of it) and
// analyzer/util.go (only the declarations rewrite.go copies: the
// functionsToRewrite list, the matcher types and their match methods,
// mayHaveSideEffects, forEachPackageIncludingDependencies) against
// pkg/static/capslock/rewrite.go, re-sync the copy, then update the hashes.
func TestRewritePinning(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/google/capslock").Output()
	assert.NilError(t, err, "locating the capslock module in the module cache")
	dir := strings.TrimSpace(string(out))
	for file, want := range map[string]string{
		"analyzer/rewrite.go": "83035a79a1e6ce79e146235e3f221ab2dc6b4fa7a3e0d47704af58e806f6866a",
		"analyzer/util.go":    "4c1a719de8b74ebc684086c8f68c2a94c757a0eaad2abab8d9463cdb264f737f",
	} {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file)))
		assert.NilError(t, err)
		sum := sha256.Sum256(b)
		assert.Equal(t, hex.EncodeToString(sum[:]), want,
			"capslock %s changed; re-sync pkg/static/capslock/rewrite.go (see the comment on this test)", file)
	}
}
