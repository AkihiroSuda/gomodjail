package tracer

import "fmt"

type Tracer interface {
	// Trace traces the process.
	// Trace may return [ExitError].
	Trace() error
}

type ExitError struct {
	ExitCode int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.ExitCode)
}
