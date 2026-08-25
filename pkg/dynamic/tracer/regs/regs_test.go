//go:build linux && (amd64 || arm64)

package regs

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestArgsArity(t *testing.T) {
	assert.Equal(t, len((&Regs{}).Args()), 6)
}
