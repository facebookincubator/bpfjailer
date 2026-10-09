# BpfJailer

eBPF based Mandatory Access Control for Linux.

**This project is a full rewrite of the closed source BpfJailer and is
completely experimental. It leverages newer features like bpf arena that were
not available when the internal BpfJailer was written. Issues are expected and
are not eligible for bug bounty or considered security findings. Once properly
evaluated it will replace the internal closed source version.**

BpfJailer uses eBPF LSM programs to put processes into jails, called pods, each
bound to a role from a TOML policy. A pod is inherited across `fork` and
`exec`. Optional policy features:

- **Signed binaries** — binaries executed must enable fs-verity and a
  signature from a named set of certificates.
- **`kill` and `ptrace`** — target roles/pods this may signal or attach to.
- **`bpf`** — which roles' eBPF maps and programs a role may open, or whether it
  may call `bpf(2)` at all.
- **`keyring`** — which roles' fs-verity keyrings a role may add certificates
  to, or whether it may write keyrings at all.
- **Filesystem paths** — read and write access to filesystem paths.
- **Executable code** — what paths can be execed or used as dlls.
- **Kernel loading** — kernel module and kexec loading.
- **IPC** — ownership-aware System V and POSIX message queues and shared
  memory, and variable-expanded name patterns for POSIX objects.
- **Unix sockets** — pathname and abstract-name policy for bind, connect and
  datagram destinations.
- **Mounts** — destination and filesystem-type rules.

Denials and lifecycle events are written to pinned ring buffers. `bpfjlog`
prints the human-readable BPF diagnostics and structured events and follows
the ring buffers across a live policy replacement.

A binary can claim a role through the `user.bpfj.policy.exec` xattr and is
enrolled in it at exec time. Running processes can also be enrolled directly,
and an unprivileged process can enroll itself through `bpfjsrv`/`bpfjclient`.

## Components

| Directory | Binary        | Purpose |
|-----------|---------------|---------|
| `bpfj/`   |               | The core library and BPF programs: jailer, enforcers, policy parser, libbpf C++ helpers. |
| `ctl/`    | `bpfjctl`     | General purpose tool for attaching, reloading, inspecting and detaching the jailer, and for enrolling processes. |
| `cmd/`    | `bpfjcmd`     | `bpfjctl` with its arguments, and optionally its policy, compiled in. It ignores `argv`, so it can be statically linked and fs-verity signed as a single unit. |
| `srv/`    | `bpfjsrv`     | Socket activated server that enrolls unprivileged callers into roles that allow it. |
| `client/` | `bpfjclient`  | Minimal client for `bpfjsrv`, with no libbpf or BPF-toolchain dependency. |
| `log/`    | `bpfjlog`     | Consumer for the pinned diagnostic and structured-event ring buffers. |
| `tests/`  | `bpfjtest`    | Test suite. |

## Requirements

- Linux 6.16 or newer with BPF LSM enabled (`CONFIG_BPF_LSM=y` and `bpf` in
  the `lsm=` boot parameter). BpfJailer is only tested on 6.16+, and older
  kernels are not supported.
- clang 22 or newer for BPF codegen, `bpftool`, and a C++20 compiler. clang 20
  and 21 emit no `addr_space_cast` for a `__builtin_memcpy` from arena memory,
  so the verifier rejects the jailer they build.
- A kernel with btrfs built in, `CONFIG_BTRFS_FS=y` rather than a module. The
  BPF programs read btrfs inode types from vmlinux.h, which the Makefile
  generates from the running kernel's BTF.
- libbpf
- A checkout of [libarena](https://github.com/libbpf/libarena), which provides
  the arena spin lock the BPF programs use. 
- For signed builds: `openssl`, `fsverity` and `setfattr`, plus the static
  archives listed in the `Makefile` (`STATIC=1`).

Set `LIBBPF_CFLAGS` / `LIBBPF_LIBS` if pkg-config cannot find libbpf. Point
`LIBARENA` at the libarena checkout on every build:

## Building

Every `make` below also needs `LIBARENA` (see Requirements), set on the
command line or exported in the environment.

```
make                # build/bpfjctl
make STATIC=1       # bpfjctl with no shared object dependencies
make client         # build/bpfjclient, no BPF toolchain needed
make log            # build/bpfjlog
make signing-key    # generate a development signing key and certificate
make signed SIGNING_KEY=... SIGNING_CERT=...   # static, fs-verity signed bpfjctl
make srv  SIGNING_KEY=... SIGNING_CERT=...     # static, signed bpfjsrv
make cmd  SIGNING_KEY=... SIGNING_CERT=... \
     CMD_ARGS="replace-compiled" CMD_POLICY=policy.toml CMD_ROLE=bpfjailer
make clean
```

All output goes under `build/`. Set `BUILD=` to build somewhere else, for
example `make BUILD=build-asan SANITIZE=address,undefined`.

## Testing

```
make test
```

The tests have to run as root, because each one creates a mount namespace and
mounts a bpffs. `make test` builds as the invoking user and runs only the test
binary under `sudo`.

Tests run serially by default because concurrent BPF LSM detach can panic
affected kernels. Use `make test TEST_ARGS=Suite.Test` for a focused case, and
only opt into `-j N` or `BPFJTEST_JOBS=N` inside a disposable VM.

## Usage

```
sudo bpfjctl check  policy.toml          # parse a policy and report what it holds
sudo bpfjctl attach policy.toml          # load and pin the jailer
sudo bpfjctl replace policy.toml         # reload without releasing jailed tasks
sudo bpfjctl wrap ROLE USER_ID -- CMD    # run CMD in a new pod
sudo bpfjctl enroll ROLE USER_ID PID [NAME=VALUE...] # enroll with variables
sudo bpfjctl show PID                    # pods a process is in
sudo bpfjctl list                        # every pod and its processes
sudo bpfjctl detach                      # unpin and unload
```

The programs are pinned under `/sys/fs/bpf/bpfj-pins` by default. Use
`--bpffs-path` and `--pin-dir` to change this. They stay loaded until `detach`
runs.

`bpfjctl wrap` without `--drop-cap` and a non-root `--uid` leaves the command
able to remove itself from the jail. See `bpfjctl wrap --help`.

Run `sudo build/bpfjlog` while the jailer is attached to observe it. BPF
diagnostics are written to stderr and structured events to stdout. The logger
automatically reconnects when `replace` swaps in a new set of pinned maps.

`replace` loads a complete second jailer beside the active one, migrates pod
membership, variables and tracked resource ownership, then atomically swaps
the pin trees. Both trees remain attached during the handoff, forks and
enrollment are coordinated with the migration, and ownership changes are
journaled and replayed. Replacement fails closed if persisted layout versions
are incompatible or the state cannot be copied safely.

## Policy

```toml
base-role = "floor"           # optional: enroll every process on the host
vars = ["vm_uuid"]            # known variable names

[certs]
corp-ca = "MIIDXTCCAkWgAwIBAgIJAK..." # PEM or base64 DER certificate

[roles.floor]
any = true                    # open tracking-only base role

[roles.webserver]
enforce-binary-certs = ["corp-ca"] # execs must be signed by one of these
kill-roles = ["floor"]        # may signal its own pod, plus these roles
ptrace-pod = true             # its own pod only
proc-roles = ["floor"]        # may open proc files for these roles
bpf-pod = true                # only BPF objects from its own pod
lkm-any = false               # deny module and kexec loading
mq-sysv-pod = true            # only SysV queues from its own pod
mq-posix-pod = true           # only POSIX queues from its own pod
shm-sysv-pod = true           # only SysV SHM from its own pod
shm-posix-pod = true          # only POSIX SHM from its own pod
keyring-own = true            # only its own role's keyring

[[roles.webserver.mq-posix-pattern]]
name = "/service-${vm_uuid}-*"
allow = true

[[roles.webserver.shm-posix-pattern]]
name = "/service-${vm_uuid}-*"
allow = true

[[roles.webserver.exec-paths]]
path = "/usr/bin/webserver"
allow = true
permissions = ["exec"]

[[roles.webserver.exec-paths]]
path = "/usr/lib"
allow = true
permissions = ["shared-object"]

[[roles.webserver.paths]]     # cached path policy
path = "/"
allow = false

[[roles.webserver.paths]]
path = "/usr"
allow = true
access = "read-only"

[[roles.webserver.paths]]
path = "/etc"
allow = true
access = "read-only"

[[roles.webserver.paths]]
path = "/srv/web"
allow = true
access = "read-write"

[[roles.webserver.unix-bind]] # pathname bind rule
path = "/run/webserver"
allow = true

[[roles.webserver.unix-connect]]
name = "@control-${vm_uuid}"
allow = true

[[roles.webserver.unix-dgram]]
path = "/dev/log"
allow = true

[[roles.webserver.mount]]     # destination and permitted filesystem types
path = "/srv/data"
allow = true
filesystems = ["ext4", "xfs"]

[[roles.webserver.mount]]
path = "/run/webserver"
allow = true
filesystems = ["any"]         # every filesystem type at this destination

[[roles.webserver.umount]]
path = "/"
allow = false

[[roles.webserver.umount]]
path = "/srv/data"
allow = true

[roles.sandbox]
unpriv-enroll = true          # every unspecified operation remains denied
override-stacked = true       # answers alone, ignoring roles stacked below
```

Most operation gates are denied when a role has no corresponding option. The
`*-pod` options allow resources from the same pod, `*-roles` adds the named
owner roles, and `*-any` opens that operation completely. `keyring-own` is the
role-scoped counterpart because fs-verity keyrings belong to roles rather than
pods. `enroll-roles` names the only roles bpfjsrv may add; without it enrollment
through bpfjsrv is denied. Unix pathname, mount, and unmount operations are
denied when their option is absent or no path matches. Abstract Unix-socket
names remain opt-in filters, so an unconfigured or unmatched abstract name is
allowed.

The fully open proc option is `proc-any`, following the same `*-any` order as
the other ownership families.

`any = true` opens every operation that has no more specific option. This is
useful for a pod used only for attribution. A scoped option such as `bpf-pod`,
`kill-roles`, `paths`, or `enforce-binary-certs` overrides `any` for that
operation. `lkm-any`, `fs-any`, `verity-any`, `mount-any`, and `umount-any`
are operation-specific fully-open forms.

A process holding several roles is allowed an operation only if every role
agrees. Roles are consulted newest first, and an `override-stacked` role
answers for the roles under it. The target side of `kill` and `ptrace` ignores
override: every role the target holds has to be listed. The full semantics are
documented in `bpfj/policy/Policy.h`.

`vars` is an allowlist. An enrollment setting a variable the policy does not
list is refused, and with no `vars` at all no pod carries any. A `replace`
carries each pod's variables across by name, and fails if the new policy no
longer lists one a pod is carrying.

Various policy options take paths and globs. These all follow a common matcher.
Variables are indicated with ${NAME} and wildcard ? and * are supported. This
allows for matching options that are scoped to the variables within a specific
pod, allowing for say, two containers, to have different filesystem permissions
and isolation rules from eachother. All filesystem operations are currently
performed in systemd's mount namespace to prevent mount manipulations from
impacting the matcher. Files that cannot be resolved in that namespace are
allowed. Choosing the matching namespace will come soon.

See [POLICY.md](POLICY.md) for the complete option matrix, matching semantics
and replacement behavior.

## Examples

- [`examples/signed-attach`](examples/signed-attach/README.md): a signed
  `bpfjcmd` that is the only binary on the host allowed to update BpfJailer's
  own BPF programs.
- [`examples/unpriv-enroll`](examples/unpriv-enroll/README.md): a non-root
  process jailing itself through `bpfjsrv`.

## License

BpfJailer is MIT licensed, as found in the [LICENSE](LICENSE) file. The BPF
programs are licensed `Dual MIT/GPL`, so that the kernel treats them as GPL
compatible.

`toml/toml.hpp` is vendored from
[toml++](https://github.com/marzer/tomlplusplus) and keeps its own MIT license
notice.
