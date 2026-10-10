#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail

case "${1:?usage: kernel-version.sh X.Y|stable}" in
  stable)
    version=$(curl -fsSL https://www.kernel.org/releases.json | jq -er '.latest_stable.version')
    ;;
  [0-9]*.[0-9]*)
    if [[ ! "$1" =~ ^[0-9]+\.[0-9]+$ ]]; then
      echo "unknown kernel '$1'" >&2
      exit 1
    fi
    version=$(git ls-remote --tags --refs \
      https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
      "refs/tags/v$1" "refs/tags/v$1.*" |
      sed 's|.*refs/tags/v||' | sort -V | tail -n 1)
    if [[ -z "$version" ]]; then
      echo "kernel.org has no release tagged v$1" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown kernel '$1'" >&2
    exit 1
    ;;
esac

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "invalid kernel.org release '$version'" >&2
  exit 1
fi
echo "$version"
