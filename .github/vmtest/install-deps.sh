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

# Hosted runners default to an Azure mirror that flakes, so use the main archive and retry.
cat >/etc/apt/apt.conf.d/99bpfj-ci <<'EOF'
Acquire::Retries "3";
Acquire::ForceIPv4 "true";
Acquire::Queue-Mode "access";
Acquire::http::Pipeline-Depth "0";
Acquire::Languages "none";
Dpkg::Use-Pty "0";
EOF
if [[ -f /etc/apt/apt-mirrors.txt ]]; then
  echo 'http://archive.ubuntu.com/ubuntu/' >/etc/apt/apt-mirrors.txt
fi
sed -i -E \
  -e 's|https?://([a-z0-9-]+\.)*archive\.ubuntu\.com/ubuntu/?|http://archive.ubuntu.com/ubuntu/|g' \
  -e 's|https?://security\.ubuntu\.com/ubuntu/?|http://archive.ubuntu.com/ubuntu/|g' \
  /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true

apt_install() {
  local attempt
  for attempt in 1 2 3; do
    if timeout 300 apt-get update && timeout 900 apt-get install -y --no-install-recommends "$@"; then
      return 0
    fi
    echo "::warning::apt attempt $attempt of 3 failed"
    sleep 10
  done
  return 1
}

apt_install ca-certificates curl gnupg
curl -fsSL --retry 3 https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/apt.llvm.org.gpg
echo "deb [signed-by=/usr/share/keyrings/apt.llvm.org.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-$llvm_version main" \
  >/etc/apt/sources.list.d/apt.llvm.org.list
apt_install \
  attr bc binutils bison build-essential "clang-$llvm_version" cpio dwarves \
  e2fsprogs flex git jq libcap-dev libelf-dev libkeyutils-dev libprotobuf-dev \
  libssl-dev libzstd-dev "llvm-$llvm_version" make openssl pkg-config \
  protobuf-compiler python3-venv qemu-system-x86 virtiofsd xxd zlib1g-dev zstd

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
