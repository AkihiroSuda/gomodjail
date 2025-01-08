package main

import (
	"fmt"

	p "github.com/AkihiroSuda/gomodjail/examples/poisoned"
)

func main() {
	const x, y = 42, 43
	fmt.Printf("%d + %d = %d\n", x, y, p.Add(x, y))
}
