[[📂**Profiles**]](./examples/profiles)

# gomodjail: jail for Go modules

gomodjail imposes syscall restrictions on a specific set of Go modules,
so as to mitigate their potential vulnerabilities and supply chain attack vectors.

In other words, gomodjail is a "container" (as in Docker containers) for Go modules.

gomodjail can be applied just in the following two steps:

**Step 1**: add `gomodjail:confined` comment to `go.mod`:
```go-module
require (
        example.com/module v1.0.0 // gomodjail:confined
)
```

**Step2**: run the program with `gomodjail run --go-mod=go.mod`:
```bash
gomodjail run --go-mod=FILE -- PROG [ARGS]...
```

> [!IMPORTANT]
>
> See [Caveats](#caveats).

## Requirements
Runtime dependencies:
- Linux (4.8 or later) or macOS
- x86\_64 (aka "amd64") or aarch64 ("arm64")

Build dependencies:
- [Go](https://go.dev/dl/)

## Install
```bash
make
sudo make install
```

Makefile variables:
- `PREFIX`: installation prefix (default: `/usr/local`)

## Example
An example program is located in [`./examples/victim`](./examples/victim):
```bash
cd ./examples/victim
go build
./victim
```

Confirm the "malicious" vi screen:

```
*** ARBITRARY SHELL CODE EXECUTION ***

This 'vi' command was executed by the 'github.com/AkihiroSuda/gomodjail/examples/poisoned' module.

This example is harmless, of course, but suppose that this was a malicious code.

Type ':q!' to leave this screen.
```

Run the program again with `gomodjail run --go-mod=go.mod`, and confirm that the execution of the "malicious" `vi` command is blocked.

```bash
gomodjail run --go-mod=go.mod -- ./victim
level=WARN msg=***Blocked*** syscall=pidfd_open module=github.com/AkihiroSuda/gomodjail/examples/poisoned
```

### More examples

[`examples/profiles`](./examples/profiles) has several example profiles:
- `docker.mod`: for `docker` (not `dockerd`)
- ...

## Caveats
- Not applicable to a Go binary built by non-trustworthy thirdparty, as the symbol information might be faked.
- Not applicable to a Go module that use:
  - [`unsafe`](https://pkg.go.dev/unsafe)
  - [`reflect`](https://pkg.go.dev/reflect)
  - [`plugin`](https://pkg.go.dev/plugin)
  - [`go:linkname`](https://tip.golang.org/doc/go1.23#linker)
  - [C](https://pkg.go.dev/cmd/cgo)
  - [Assembly](https://go.dev/doc/asm)
- No isolation of file descriptors across modules.
  A confined module can still read/write an existing file descriptor, although it cannot open a new file descriptor.
- The target binary file must not be replaced during execution.
- The `gomodjail:confined` policy is not well defined and still subject to change.
- This is not a panacea; there can be other loopholes too.

macOS:
- The protection can be arbitraliry disabled by unsetting an environment variable `DYLD_INSERT_LIBRARIES`.
- Only works with the following versions of Go:
  - 1.22
  - 1.23
  - 1.24 (excluding 1.24.0-1.24.5)
  - 1.25
  - 1.26 (tested with rc1)
- Not applicable to a Go module that use:
  - [`syscall.Syscall`, `syscall.RawSyscall`, etc.](https://pkg.go.dev/syscall)

macOS on Intel:
- Not applicable to a Go binary built with `-ldflags="-s"` (disable symbol table)

## Advanced topics
### Advanced usage
- To create a self-extract archive of gomodjail with a target program, run `gomodjail pack --go-mod=go.mod PROGRAM`.
  The self-extract archive is created as `<PROGRAM>.gomodjail`.

### How it works
Linux:
- [`SECCOMP_RET_TRACE`](https://man7.org/linux/man-pages/man2/seccomp.2.html) is used for conditionally
  allowing trusted Go modules to execute the syscall.
  `SECCOMP_RET_USER_NOTIF` is not used because it cannot access all the CPU registers,
  due to the [lack of `struct pt_regs` in `struct seccomp_data`](https://github.com/torvalds/linux/blob/v6.12/kernel/seccomp.c#L242-L266).
- [Stack unwinding](https://www.grant.pizza/blog/go-stack-traces-bpf/) is used for analyzing the call stack to determine the Go module.

macOS:
- `DYLD_INSERT_LIBRARIES` is used to hook `libSystem` (`libc`) calls.
- In addition to the frame pointer (AArch64 register X29), `struct g` in the TLS and `g->m.libcallsp` are parsed to analyze the CGO call stack.
  This analysis is not robust and only works with specific versions of Go. (See [Caveats](#caveats)).

### Future works
- Automatically detect non-applicable modules (explained in [Caveats](#caveats)).
- Apply landlock in addition to seccomp. Depends on `SECCOMP_IOCTL_NOTIF_ADDFD`.
- Modify the source code of the Go runtime, so as to remove necessity of using `seccomp` (Linux) and `DYLD_INSERT_LIBRARIES` (macOS).

## Additional documents
- [`docs/syntax.md`](./docs/syntax.md): syntax
- [`examples/profiles/README.md`](./examples/profiles/README.md): profiles
