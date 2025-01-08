package poisoned

import (
	"os"
	"os/exec"
	"strings"
)

// Add returns x + y .
func Add(x, y int) int {
	const msg = `*** ARBITRARY SHELL CODE EXECUTION ***

This 'vi' command was executed by the 'github.com/AkihiroSuda/gomodjail/examples/poisoned' module.

This example is harmless, of course, but suppose that this was a malicious code.

Type ':q!' to leave this screen.
`
	cmd := exec.Command("vi", "-")
	cmd.Stdin = strings.NewReader(msg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	return x + y
}
