#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail

prefix=${1:?usage: install-deps.sh PREFIX}

# clang 20 and 21 omit address space casts when copying from arena memory.
llvm_version=22

libbpf_commit=85c0d575a447651bbeb8e2376eacd64c30dce9a6
bpftool_commit=83f764e01d7f0cefe1fe3b3405594ed931ed2d37
libarena_commit=b6968918620807fcc7fdf2a7b165a06ca7a92c1c
virtme_ng_version=1.41

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/apt.llvm.org.gpg
echo "deb [signed-by=/usr/share/keyrings/apt.llvm.org.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-$llvm_version main" \
  >/etc/apt/sources.list.d/apt.llvm.org.list
apt-get update
apt-get install -y --no-install-recommends \
  attr bc binutils bison build-essential "clang-$llvm_version" cpio dwarves \
  e2fsprogs flex git jq libcap-dev libelf-dev libkeyutils-dev libssl-dev \
  libzstd-dev "llvm-$llvm_version" make openssl pkg-config python3-venv \
  qemu-system-x86 virtiofsd xxd zlib1g-dev zstd

mkdir -p "$prefix/bin" "$prefix/src"
ln -sf "/usr/bin/clang-$llvm_version" "$prefix/bin/clang"
ln -sf "/usr/bin/llvm-strip-$llvm_version" "$prefix/bin/llvm-strip"
export PATH="$prefix/bin:$PATH"

fetch() {
  local repo=$1 commit=$2 dir=$3
  git init -q "$dir"
  git -C "$dir" fetch -q --depth 1 "https://github.com/$repo" "$commit"
  git -C "$dir" checkout -q FETCH_HEAD
}

fetch libbpf/libbpf "$libbpf_commit" "$prefix/src/libbpf"
make -C "$prefix/src/libbpf/src" -j"$(nproc)" \
  PREFIX="$prefix/libbpf" LIBDIR="$prefix/libbpf/lib" install install_uapi_headers

fetch libbpf/bpftool "$bpftool_commit" "$prefix/src/bpftool"
git -C "$prefix/src/bpftool" submodule update -q --init --depth 1
make -C "$prefix/src/bpftool/src" -j"$(nproc)"
install -m 0755 "$prefix/src/bpftool/src/bpftool" "$prefix/bin/bpftool"

fetch libbpf/libarena "$libarena_commit" "$prefix/libarena"

python3 -m venv "$prefix/venv"
"$prefix/venv/bin/pip" install --quiet "virtme-ng==$virtme_ng_version"
# vng finds its helpers through PATH.
ln -sf "$prefix"/venv/bin/vng "$prefix"/venv/bin/virtme-* "$prefix/bin/"

bpftool version
clang --version | sed -n '1p'
vng --version
