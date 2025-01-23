package tracer

type Tracer interface {
	// Trace traces the process.
	// Trace may call [os.Exit].
	Trace() error
}
