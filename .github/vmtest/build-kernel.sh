#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail

version=${1:?usage: build-kernel.sh VERSION OUT}
out=${2:?usage: build-kernel.sh VERSION OUT}
out=$(realpath -m "$out")
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src=
rc=
for sig in 1 2 3 13 15; do eval "trap 'exit $((sig + 128))' $sig"; done
trap 'rc=$?; set +e; rm -rf "$src"; exit "$rc"' EXIT

if [[ -n "${KERNEL_SRC:-}" ]]; then
  cd "$KERNEL_SRC"
else
  src=$(mktemp -d)
  curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x/linux-$version.tar.xz" |
    tar -xJ -C "$src" --strip-components=1
  cd "$src"
fi

configs=()
# Lockdep and full preemption in config.x86_64 slow BPF trampoline detach.
for fragment in tools/testing/selftests/bpf/config tools/testing/selftests/bpf/config.vm; do
  if [[ -f "$fragment" ]]; then
    configs+=(--config "$fragment")
  fi
done
configs+=(--config "$here/kernel.config")
vng --kconfig "${configs[@]}"

# Kconfig silently drops options with unmet dependencies.
missing=0
while IFS= read -r line; do
  if [[ "$line" == CONFIG_* ]] && ! grep -qxF "$line" .config; then
    echo "kernel.config: '$line' is not in the final .config" >&2
    missing=1
  fi
done <"$here/kernel.config"
if ((missing)); then
  exit 1
fi

make -j"$(nproc)" bzImage

mkdir -p "$out"
cp arch/x86/boot/bzImage "$out/bzImage"
cp .config "$out/config"
echo "$version" >"$out/version"
