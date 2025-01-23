#!/bin/sh

# Usage:
# GO111MODULE=off GO="$(go env GOPATH)"/src/go.googlesource.com/go/bin/go ./offset.sh

set -eux -o pipefail

: "${GO:=go}"

GOROOT="$("$GO" env GOROOT)"

cat <<EOF >"${GOROOT}"/src/runtime/gomodjail_offset.go
package runtime

import "unsafe"

var (
        GOMODJAIL_OFFSET_G_M= unsafe.Offsetof(g{}.m)
        GOMODJAIL_OFFSET_M_LIBCALLPC = unsafe.Offsetof(m{}.libcallpc)
        GOMODJAIL_OFFSET_M_LIBCALLSP = unsafe.Offsetof(m{}.libcallsp)
)
EOF

cat <<EOF >gomodjail_offset_print.go
package main

import (
        "fmt"
        "runtime"
)

func main() {
        fmt.Printf("/* %s */\n", runtime.Version())
        fmt.Printf("#define GOMODJAIL_OFFSET_G_M %d\n", runtime.GOMODJAIL_OFFSET_G_M)
        fmt.Printf("#define GOMODJAIL_OFFSET_M_LIBCALLPC %d\n", runtime.GOMODJAIL_OFFSET_M_LIBCALLPC)
        fmt.Printf("#define GOMODJAIL_OFFSET_M_LIBCALLSP %d\n", runtime.GOMODJAIL_OFFSET_M_LIBCALLSP)
}
EOF

"$GO" run ./gomodjail_offset_print.go

rm -f "${GOROOT}"/src/runtime/gomodjail_offset.go gomodjail_offset_print.go
