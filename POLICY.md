# BpfJailer policy reference

A policy is a TOML document containing a `roles` table and, optionally,
`base-role`, `certs`, and `vars`. Role options are keys in each role's table;
path, socket, and mount maps are nested tables.

```toml
base-role = "floor"
vars = ["service"]

[certs]
release = "<PEM or base64 DER certificate>"

[roles.floor]
any = true

[roles.worker]
kill-pod = true

[[roles.worker.paths]]
path = "/"
allow = false

[[roles.worker.paths]]
path = "/usr"
allow = true
access = "read-only"

[[roles.worker.paths]]
path = "/etc"
allow = true
access = "read-only"

[[roles.worker.paths]]
path = "/srv/${service}"
allow = true
access = "read-write"
```

`base-role` is applied to every process that exists when the jailer attaches;
descendants inherit it. A binary can claim another role at exec through the
`user.bpfj.policy.exec` xattr, and explicit enrollment can stack more roles on
a task. `vars` is the allowlist of variable names an enrollment may set.

## General authorization

Most resource families use one of three mutually exclusive scopes:

| Scope | Meaning |
|---|---|
| `*-pod: true` | The actor may access resources owned by its own pod. |
| `*-roles` | Own pod plus resources owned by the listed roles. |
| `*-any: true` | No ownership restriction for that resource family. |

Leaving a scoped family unconfigured denies it. `any: true` supplies the open
form for every family not configured more narrowly. `keyring-own` is the
role-owned equivalent of `*-pod`.

A task holding several roles must be allowed by each role, newest first.
`override-stacked: true` stops that actor-side walk at the marked role. It
never short-circuits the target-role checks for `kill` or `ptrace`.

## Options

| Family | Options | Behavior |
|---|---|---|
| Files | `paths`, `fs-any` | Boolean `{ path, allow }` rules; allowed rules add `access = "read-only"` or `"read-write"`. Mutually exclusive with `fs-any`; leaving both unset denies access. |
| Executable code | `exec-paths`, `exec-any` | `exec-paths` is an array of path rules for exec, set-id exec and executable mappings. `exec-any` opens all three. Leaving both unset denies executable code unless `any: true` applies. |
| Binary integrity | `enforce-binary-certs`, `verity-any`, `min-seq` | Require an fs-verity signature from named certificates, bypass that integrity check, and optionally reject signed binaries below an anti-rollback sequence floor. `min-seq` requires `enforce-binary-certs`. |
| BPF | `bpf-pod`, `bpf-roles`, `bpf-any`, `untracked-bpf` | Gate `bpf(2)` and opening maps/programs by creator ownership. `untracked-bpf` suppresses ownership for objects created by the role and requires a BPF grant. |
| Kernel loading | `lkm-any` | Permit module and kexec image loading; absence denies both. |
| Signals | `kill-pod`, `kill-roles`, `kill-any` | Gate signals by target pod/role. |
| Ptrace | `ptrace-pod`, `ptrace-roles`, `ptrace-any` | Gate attach and `PTRACE_TRACEME`; read-only inspection used by tools such as `ps` is not gated. |
| Process files | `proc-pod`, `proc-roles`, `proc-any` | Gate access to another task through procfs after resolving its pid in that proc mount's pid namespace. |
| Keyrings | `keyring-own`, `keyring-roles`, `keyring-any` | Gate writes to role fs-verity keyrings. |
| System V queues | `mq-sysv-pod`, `mq-sysv-roles`, `mq-sysv-any` | Gate lookup, control, send and receive by tracked owner. |
| POSIX queues | `mq-posix-pod`, `mq-posix-roles`, `mq-posix-any`, `mq-posix-pattern` | Gate open, descriptor receipt and queue operations by owner or name pattern. |
| System V shared memory | `shm-sysv-pod`, `shm-sysv-roles`, `shm-sysv-any` | Gate lookup, control and attach by tracked owner. |
| POSIX shared memory | `shm-posix-pod`, `shm-posix-roles`, `shm-posix-any`, `shm-posix-pattern` | Gate open, receipt, mapping, protection, truncation and unlink by owner or name pattern. |
| Unix sockets | `unix-bind`, `unix-connect`, `unix-dgram` | `{ path, allow }` rules with boolean `allow` values for pathname or abstract socket names. Missing or unmatched pathname policy denies; unmatched abstract names are allowed. |
| Mounts | `mount`, `mount-any`, `umount`, `umount-any` | Boolean `{ path, allow }` rules; allowed mount rules add `filesystems`. Missing or unmatched policy denies; the `*-any` options open the corresponding operation. |
| Enrollment | `unpriv-enroll`, `enroll-roles`, `enroll-any` | Open a role to a non-root caller and constrain which further roles a caller may request through `bpfjsrv`. |

Role and certificate references are validated when the policy is parsed.
Unknown role options, duplicate entries and mutually exclusive scopes are
errors. A task may hold at most eight pods, and each pod may carry at most 16
variables with values of at most 62 bytes.

## Paths and patterns

File, pathname Unix-socket and mount matching is evaluated against the global
snapshot of PID 1's mount namespace. Results are cached by mount identity and
pod variable bindings and are invalidated by relevant filesystem changes.

Every path-based policy is an array of rule tables with a `path` and boolean
`allow`. `paths` rules apply recursively and the longest matching path wins.
They support literal components, a `*` component, and `${NAME}` components with
an optional glob suffix. `*` matches one component; recursive `**` is not
supported because a directory rule already covers its subtree. The variable
must be declared by top-level `vars` and present on the pod for the dependent
pattern to match. Allowed rules require `access = "read-only"` or
`access = "read-write"`; denied rules omit `access`.

`exec-paths` uses the same cached path matching, independently of `paths` and
fs-verity. It is an array of rule tables with a `path` and boolean `allow`.
Allowed rules require a nonempty `permissions` array containing `exec`,
`set-id`, or `shared-object`; denied rules omit it. Set-user-ID and set-group-ID
binaries need both `exec` and `set-id`, while executable mmap or mprotect needs
`shared-object`.
The longest matching path wins. At equal depth, the rule with more non-wildcard
components wins; a bound `${NAME}` component is specific, while `*` is not. An
equally specific denial wins a tie. `exec-any = true`
opens all three operations and is mutually exclusive with `exec-paths`;
`any: true` supplies the same open behavior only when neither narrower option
is present.

```toml
[[roles.worker.exec-paths]]
path = "/usr/bin/worker"
allow = true
permissions = ["exec"]

[[roles.worker.exec-paths]]
path = "/usr/lib"
allow = true
permissions = ["shared-object"]
```

Unix pathname rules use `{ path, allow }`; paths begin with `/` and apply
recursively. Abstract socket rules use `{ name, allow }`; names begin with `@`
and use glob matching. The most specific matching rule wins and an equally
specific denial wins a tie. Missing or unmatched pathname policy denies, so a
`true` rule opens its subtree. Unmatched abstract names are allowed, so an
abstract-name allowlist needs a catch-all denial plus more specific grants.
`any: true` opens pathname operations that have no explicit Unix operation
table. Already-connected, inherited or transferred Unix socket descriptors
remain capabilities and are not dynamically revoked.

For `mount`, `allow` is boolean. An allowed rule requires a nonempty
`filesystems` array; `any` permits every filesystem type at that destination.
A denied rule omits `filesystems`. Missing and unmatched mount policy denies,
and `mount-any` permits every destination and type. For `umount`, `allow` is
the complete boolean decision. Its rules apply recursively and the longest
match wins; missing or unmatched policy denies. `umount-any` permits every
source. `mount` and `mount-any`, and `umount` and `umount-any`, are mutually
exclusive.

`move_mount` requires mount permission at the destination and, for an attached
source mount, unmount permission at the source. Moving a detached tree checks
only its destination. `pivot_root` applies the same pair. A standalone
new-mount-API reconfigure has no destination in its LSM hook and requires
`mount-any`. Legacy bind/move operations at a typed destination are denied
because their LSM hook exposes no source type, and legacy `MS_MOVE` requires
`umount-any` because its source path is unavailable to the hook.

POSIX queue and shared-memory name policies are arrays of `{ name, allow }`
rules. Names start with `/`, matching the argument accepted by `mq_open` and
`shm_open`, and support literals, `?`, `*`, and `${NAME}`. The most specific
matching rule wins and an equally specific denial wins a tie; an unmatched
name is denied. An allowed match grants access regardless of owner. Name rules
cannot be combined with the corresponding `*-any`. Backslash escapes a
metacharacter. System V IPC is not name-matched.

Variable-expanded matchers inspect only the first four variables carried by a
pod, and a bound value may be at most 39 bytes to match. Longer values and the
remaining variables are valid pod metadata but do not satisfy `${NAME}`
references.

## Resource ownership and capabilities

BPF maps/programs, message queues and shared-memory objects created by a
jailed task are associated with its newest pod and role. POSIX IPC uses the
filesystem device and inode as identity, which distinguishes separate
mqueuefs instances and `/dev/shm` mounts.

File descriptors held before enrollment or inherited within a pod remain
capabilities. Descriptor receipt is checked where the LSM exposes it, but an
accepted descriptor is not revoked later. Existing shared-memory mappings are
also capabilities because direct loads and stores do not cross an LSM hook.
`memfd_create` is not POSIX shared memory and is outside `shm-posix`.

## Live replacement

`bpfjctl replace` keeps enforcement attached while it constructs a new pin
tree. It snapshots task membership and pod state with a BPF iterator, rebuilds
pods and variable bindings in the new arena, translates role-policy pointers,
copies BPF and IPC ownership, and replays ownership mutations recorded during
the copy. It then atomically exchanges the pin trees and retires the old one.

Replacement preserves pod UUIDs, users, enrollment sources, ages, variables,
task membership, BPF ownership, queue ownership, shared-memory ownership and
registered `/dev/shm` mounts. It rejects incompatible persisted layout
versions and policies that remove a variable still carried by a pod. A failed
replacement leaves the active tree in place rather than silently dropping
authorization state.
