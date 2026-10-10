#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail

src=${1:?usage: run-tests.sh SRC PREFIX}
prefix=${2:?usage: run-tests.sh SRC PREFIX}
trap 'echo "bpfj-ci: exit $?"' EXIT

export PATH="$prefix/bin:$PATH"

if ! mountpoint -q /sys/kernel/security; then
  mount -t securityfs securityfs /sys/kernel/security
fi
echo "kernel $(uname -r), LSMs $(cat /sys/kernel/security/lsm)"
if ! grep -qw bpf /sys/kernel/security/lsm; then
  echo "::error::The BPF LSM is not active in the guest."
  exit 1
fi

mount -t tmpfs -o mode=1777 tmpfs /tmp
work=$(mktemp -d /tmp/bpfjailer-ci.XXXXXX)
cp -a "$src/." "$work/"

make -C "$work" -j"$(nproc)" \
  LIBARENA="$prefix/libarena" \
  LIBBPF_CFLAGS="-I$prefix/libbpf/include" \
  LIBBPF_LIBS="-L$prefix/libbpf/lib -Wl,-rpath,$prefix/libbpf/lib -lbpf" \
  SUDO= \
  test
