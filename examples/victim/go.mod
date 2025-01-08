module github.com/AkihiroSuda/gomodjail/examples/victim

go 1.23

require github.com/AkihiroSuda/gomodjail/examples/poisoned v0.0.0-00010101000000-000000000000 // gomodjail:confined

replace github.com/AkihiroSuda/gomodjail/examples/poisoned => ../poisoned
