#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.

set -euo pipefail

kernel=${1:?usage: vm.sh KERNEL PREFIX}
prefix=${2:?usage: vm.sh KERNEL PREFIX}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
log=
rc=
for sig in 1 2 3 13 15; do eval "trap 'exit $((sig + 128))' $sig"; done
trap 'rc=$?; set +e; rm -f "$log"; exit "$rc"' EXIT
log=$(mktemp)
printf -v command 'bash %q %q %q' "$repo/.github/vmtest/run-tests.sh" "$repo" "$prefix"

# Spectre mitigations slow the verifier in this disposable guest.
set +e
timeout --kill-after=1m 120m vng --run "$kernel" --user root --cpus 4 --memory 8G --verbose --append "panic=-1 mitigations=off" \
  --exec "$command" 2>&1 | tee "$log"
statuses=("${PIPESTATUS[@]}")
set -e
for status in "${statuses[@]}"; do
  if ((status != 0)); then
    exit "$status"
  fi
done

# A guest panic can leave vng without a test result.
result=$(sed -n 's/.*bpfj-ci: exit \([0-9][0-9]*\).*/\1/p' "$log" | tail -n 1)
if [[ -z "$result" ]]; then
  echo "::error::The VM exited without a test result. The kernel log above shows why."
  exit 1
fi
exit "$result"
