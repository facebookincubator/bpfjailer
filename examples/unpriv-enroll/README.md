# Unprivileged enrollment

A process jails itself without being able to jail anything else.

Attaching the jailer needs root, and so does writing its maps. Enrolling
through `bpfjsrv` does not: the server does the privileged half, reads the
caller's pid off the connection with `SO_PEERCRED`, and decides what it is
allowed to ask for from the role's policy. So `run.sh` takes no `sudo` and
still ends up in a jail it cannot leave.

## Running it

```
./build.sh     # bpfjctl, bpfjsrv, bpfjclient
./attach.sh    # sudo: attach the jailer, start bpfjsrv
./run.sh       # no sudo: a jailed shell
./detach.sh    # sudo: stop bpfjsrv, unload the jailer
```

`attach.sh` loads BPF LSM programs for the whole host, so run `detach.sh`
when you are done. Nothing here survives it.

`run.sh` with no arguments gives a shell; with arguments it runs those
instead, the same way `bpfjctl wrap` takes a command:

```
./run.sh id
./run.sh bash -c 'echo in the jail'
```

## What it shows

`policy.toml` has one role, `sandbox`:

```toml
[roles.sandbox]
unpriv-enroll = true
fs-any = true
verity-any = true
kill-pod = true
ptrace-pod = true
proc-pod = true
mq-sysv-pod = true
mq-posix-pod = true
shm-sysv-pod = true
shm-posix-pod = true

[[roles.sandbox.mq-posix-pattern]]
name = "/bpfj-example-*"
allow = true

[[roles.sandbox.shm-posix-pattern]]
name = "/bpfj-example-*"
allow = true

[[roles.sandbox.exec-paths]]
path = "/"
allow = true
permissions = ["exec", "shared-object"]

[[roles.sandbox.unix-bind]]
path = "/"
allow = false

[[roles.sandbox.unix-bind]]
name = "@*"
allow = false

[[roles.sandbox.unix-bind]]
name = "@bpfj-sandbox-demo"
allow = true
```

`unpriv-enroll: true` is the only reason a non-root caller may take this role.
Leave it out and `bpfjsrv` refuses with `role sandbox is not open to
unprivileged callers`, which is what every other role gets by default.

BPF is omitted because absence is the load-bearing denial: a jailed process
holding `CAP_BPF` cannot delete its own entry from the jailer's maps and walk
out. `bpf-pod: true` would instead permit BPF objects from its own pod.

The process options confine signalling, ptrace, and `/proc` access to the pod.
The four IPC pod options do the same for System V and POSIX message queues and
shared memory; the POSIX patterns show how a deliberately shared naming
convention can be admitted without opening every object. `fs-any` and
`verity-any` keep ordinary file access and unsigned executables open so the
shell can run. The executable-path rule allows code and shared objects but
denies setuid transitions.

Unix pathname binds are denied, as are arbitrary abstract names. The one exact
abstract name `@bpfj-sandbox-demo` is allowed, demonstrating control over a
namespace that normal file permissions cannot cover. Module loading, keyring
writes, and further enrollment remain denied. Mount and unmount policy
is omitted: this unprivileged example leaves those to normal kernel
credentials rather than pretending a `CAP_SYS_ADMIN` failure demonstrates the
jailer.

To watch the jail refuse something, start a process outside it and try to
signal it from inside:

```
sleep 300 &        # another terminal, same user
./run.sh
  kill <that pid>  # Operation not permitted
```

The same `kill` from outside the jail succeeds. Same user, same command, so
it is the `kill-pod:` policy refusing and not file permissions — which is the
point, since an example that only shows root-only operations being denied to
a non-root process would demonstrate nothing.

The `/proc` rule is visible without another tool:

```
cat /proc/self/status  # allowed: this pod
cat /proc/1/status     # denied: another pod
```

Abstract Unix sockets are similarly independent of filesystem permissions:

```
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.bind("\0outside")'
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.bind("\0bpfj-sandbox-demo")'
```

The first bind is denied and the second is allowed by `unix-bind`.

`bpfjctl` does not work inside the jail either: the role denies `bpf(2)`, so
the jail will not even be inspected from within. Use `sudo bpfjctl list` from
outside.

## The pieces

`bpfjclient`, built from `client/Main.cpp`, is the unprivileged counterpart to
`bpfjctl wrap`: the same `ROLE POD_ID -- COMMAND`
shape, except it enrolls over the socket instead of writing the maps, then
execs. Jail membership survives exec, so the command inherits the pod.
Pass `-V NAME=VALUE` repeatedly to set up to 16 variables declared by the
policy.

It is also the smallest demonstration of what `srv/Client.h` costs a caller:

```
$ ldd build/bpfjclient
    libstdc++.so.6 ... libc.so.6 ...
```

No libbpf, no BPF skeletons. `build.sh` builds it on its own line for that
reason — a service that wants to jail itself needs only a C++ toolchain and
the usual C/C++ runtime.

## systemd

In a real deployment `bpfjsrv` is socket activated by the units in `srv/`:
`bpfjsrv.socket` binds `@bpfj` with `Accept=yes`, and `bpfjsrv@.service`
handles one connection per instance.

`attach.sh` uses `systemd-socket-activate` instead, which does the same thing
without installing anything. The one difference is where the connection
arrives: the tool passes it as fd 3 with `LISTEN_FDS=1`, while the unit's
`StandardInput=socket` puts it on stdin. `bpfjsrv` accepts either and checks
the descriptor is a connected socket rather than trusting the environment.

The sandbox has no enrollment permission, so both further server enrollment
and exec-time enrollment through `user.bpfj.policy.exec` are denied, including
another sandbox pod. An executable carrying that xattr fails with `EACCES`.
To permit a specific target, add `enroll-roles = ["worker"]` to the sandbox
role and define the worker role; successful exec keeps sandbox and adds a new
worker pod. `unpriv-enroll` only opens server requests to non-root callers.
