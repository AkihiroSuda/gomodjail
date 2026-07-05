[[📂**Profiles**]](./examples/profiles)

# gomodjail: jail for Go modules

gomodjail confines a specific set of Go modules, so as to mitigate their
potential vulnerabilities and supply chain attack vectors.

In other words, gomodjail is a "container" (as in Docker containers) for Go modules.

gomodjail can be applied just in the following two steps:

**Step 1**: add `gomodjail:confined` comment to `go.mod`:
```go-module
require (
        example.com/module v1.0.0 // gomodjail:confined
)
```

**Step 2**: statically verify the confinement with `gomodjail analyze`:
```bash
gomodjail analyze ./...
```

The build fails (non-zero exit) if a confined module's code can reach a
denied capability: filesystem, network, process execution, raw syscalls,
OS state modification, or cgo.

The legacy *dynamic* mode (`gomodjail run`), which enforces the same policy
at runtime via syscall interception, is still available — see
[Dynamic mode](#dynamic-mode-legacy).

## Requirements
- [Go](https://go.dev/dl/) (build and analysis)

The static analyzer runs anywhere Go runs. The legacy dynamic mode
additionally requires Linux (4.8 or later) or macOS, on x86\_64 ("amd64") or
aarch64 ("arm64").

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

The `poisoned` module is marked `gomodjail:confined` in victim's `go.mod`,
so `gomodjail analyze` catches the exec statically, with the witness call
path, before the program ever runs:

```console
$ gomodjail analyze ./...
FAIL github.com/AkihiroSuda/gomodjail/examples/poisoned: reaches EXEC
     [EXEC]
       github.com/AkihiroSuda/gomodjail/examples/poisoned.Add
       os/exec.Command  (poisoned.go:19)

gomodjail: 1 confined module(s): 0 ok, 0 warning(s), 1 violation(s)
```

## Verdicts
`gomodjail analyze` prints one verdict per confined module:

- **FAIL** — the module (or one of its own dependencies) can reach a denied
  capability: `FILES/READ`, `FILES/WRITE`, `NETWORK`, `EXEC`,
  `SYSTEM_CALLS`, `OPERATING_SYSTEM`, `MODIFY_SYSTEM_STATE`, or `CGO`.
  The exit code is non-zero.
- **WARN** — no denied capability is reachable, but the module uses
  constructs the analyzer cannot follow (`reflect`, `unsafe`, assembly,
  unresolvable dynamic calls), so the verdict is best-effort. Warnings do
  not fail the gate unless `--strict` is set. Nearly every real-world
  module that marshals, hashes, or logs earns at least one warning; this is
  expected.
- **ok** — no denied capability is reachable from the module's code.
  A confined module that contributes no packages to the build is reported
  `ok (unused)` so stale annotations stay visible.

Reading or writing an `io.Writer`/`io.Reader`/`*os.File` **handed to the
module by your program** is not a violation: the capability was granted when
your code handed over the handle. Opening a new file, dialing, or execing is.

Useful flags:
- `--strict`: treat warnings as violations
- `--explain`: print witness call paths for warnings too
- `--format=json`: machine-readable full report
- `--format=sarif`: SARIF 2.1.0 for code-scanning integrations (findings are
  anchored to the module's `require` line in `go.mod`)
- `--goos`, `--goarch`: analyze a different target platform

### More examples

[`examples/profiles`](./examples/profiles) has several example profiles:
- `docker.mod`: for `docker` (not `dockerd`)
- ...

## Caveats
- A **WARN** verdict is a real soundness concession: code hidden behind
  `reflect`, `unsafe`, assembly, etc. cannot be statically verified.
  Use `--strict` to reject it.
- Capabilities injected by the host program (e.g. your code hands a confined
  module a live network connection) are attributed to the host, not the
  module. The dynamic mode is stronger for this specific threat.
- Modules that probe the environment at init time (e.g. CPU-feature
  detection reading `/proc`) fail on `FILES/READ` by design; they were never
  confineable at runtime either.
- The `gomodjail:confined` policy is not well defined and still subject to change.
- This is not a panacea; there can be other loopholes too.

## Advanced topics
### Dynamic mode (legacy)
The original runtime enforcement is still available:

```bash
gomodjail run --go-mod=go.mod -- ./victim
level=WARN msg=***Blocked*** syscall=pidfd_open module=github.com/AkihiroSuda/gomodjail/examples/poisoned
```

It imposes syscall restrictions on the confined modules by intercepting
syscalls and attributing them to modules via stack unwinding. It needs no
source code (only symbols), and it catches host-injected capability abuse,
but it is slower and considerably more fragile than the static gate.

How it works:
- Linux: [`SECCOMP_RET_TRACE`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
  is used for conditionally allowing trusted Go modules to execute the
  syscall. `SECCOMP_RET_USER_NOTIF` is not used because it cannot access all
  the CPU registers, due to the
  [lack of `struct pt_regs` in `struct seccomp_data`](https://github.com/torvalds/linux/blob/v6.12/kernel/seccomp.c#L242-L266).
  [Stack unwinding](https://www.grant.pizza/blog/go-stack-traces-bpf/) is
  used for analyzing the call stack to determine the Go module.
- macOS: `DYLD_INSERT_LIBRARIES` is used to hook `libSystem` (`libc`) calls.
  In addition to the frame pointer (AArch64 register X29), `struct g` in the
  TLS and `g->m.libcallsp` are parsed to analyze the CGO call stack.

Dynamic-mode caveats:
- Not applicable to a Go binary built by non-trustworthy thirdparty, as the
  symbol information might be faked.
- Not applicable to a Go module that imports `unsafe`, `reflect`, `plugin`,
  etc. (`gomodjail analyze` reports these as warnings.)
- No isolation of file descriptors across modules.
  A confined module can still read/write an existing file descriptor,
  although it cannot open a new file descriptor.
- The target binary file must not be replaced during execution.

macOS:
- The protection can be arbitraliry disabled by unsetting an environment
  variable `DYLD_INSERT_LIBRARIES`.
- Only works with the following versions of Go:
  - 1.22
  - 1.23
  - 1.24 (excluding 1.24.0-1.24.5)
  - 1.25
  - 1.26
  - 1.27rc1
- Not applicable to a Go module that use:
  - [`syscall.Syscall`, `syscall.RawSyscall`, etc.](https://pkg.go.dev/syscall)

macOS on Intel:
- Not applicable to a Go binary built with `-ldflags="-s"` (disable symbol table)

### Self-extract archive
To create a self-extract archive of gomodjail with a target program, run
`gomodjail pack --go-mod=go.mod PROGRAM`.
The self-extract archive is created as `<PROGRAM>.gomodjail`.
The packed program runs under the dynamic mode.

### How the static analysis works
`gomodjail analyze` reuses [Capslock](https://github.com/google/capslock)
(pinned) as its capability-analysis engine. Each confined module is analyzed
in its own dependency slice — the module's packages plus their transitive
imports, with the query rooted at the module's own functions — so a module
is blamed only for what its own code and its own dependency cone can do,
not for values the host program hands it. Capability classes map to three
severity tiers (deny / caveat / allow) calibrated against what the dynamic
mode's seccomp filter actually blocked; unknown classes are denied (fail
closed).

### Future works
- Per-module capability scoping (e.g. allowing `FILES/READ` for a
  config-loading module).
- Parallelize the per-module analyses.
- GitHub Action and golangci-lint integrations.
- Apply landlock in addition to seccomp (dynamic mode). Depends on
  `SECCOMP_IOCTL_NOTIF_ADDFD`.

## Additional documents
- [`docs/syntax.md`](./docs/syntax.md): syntax
- [`examples/profiles/README.md`](./examples/profiles/README.md): profiles
