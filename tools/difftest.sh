#!/bin/sh
#
# tools/difftest.sh — differential trace harness (Phase 3, L3d)
#
# Usage: tools/difftest.sh <guest-binary> [guest-args...]
#
# Runs the guest twice under the i686rt runner — I686RT_ENGINE=interp
# and I686RT_ENGINE=dbt, both with I686RT_TRACE=1 — capturing each run's
# stderr (the trace stream) and stdout separately, then compares the two
# traces with tools/difftrace.py.
#
# Today engine=dbt falls back to the interpreter (src/main.c prints a
# warning and continues), so the two traces must compare EQUAL; that is
# the harness self-test.  Once the DBT is wired into main.c (S3 merge)
# the same invocation becomes the real interp-vs-dbt differential.
#
# The i686rt runner is located via, in order: $I686RT_BIN, a binary
# named i686rt next to this script (docker /w layout), ../_build/i686rt
# (repo layout), ./_build/i686rt, then $PATH.  Plain POSIX sh; runs
# inside the aarch64 docker VM with the tree mounted at /w (python3
# must be installed in the VM image).
#
# Output: guest stdout is passed through, the verdict goes to stdout
# ("DIFFTEST: EQUAL" or the divergence report from difftrace.py).
# Exit status: 0 equal, 1 divergence, 2 harness/parse error.  Trace and
# stdout captures are kept in a mktemp directory on divergence and
# removed on equality.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: difftest.sh <guest-binary> [guest-args...]" >&2
    exit 2
fi

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
difftrace=${DIFFTRACE:-$self_dir/difftrace.py}
python=${PYTHON3:-python3}

if [ -n "${I686RT_BIN:-}" ]; then
    runner=$I686RT_BIN
elif [ -x "$self_dir/i686rt" ]; then
    runner=$self_dir/i686rt
elif [ -x "$self_dir/../_build/i686rt" ]; then
    runner=$self_dir/../_build/i686rt
elif [ -x ./_build/i686rt ]; then
    runner=./_build/i686rt
elif command -v i686rt >/dev/null 2>&1; then
    runner=$(command -v i686rt)
else
    echo "difftest: no i686rt runner found (set I686RT_BIN)" >&2
    exit 2
fi

[ -x "$runner" ] || {
    echo "difftest: runner $runner is not executable" >&2
    exit 2
}
[ -f "$difftrace" ] || {
    echo "difftest: no difftrace.py at $difftrace" >&2
    exit 2
}
command -v "$python" >/dev/null 2>&1 || {
    echo "difftest: $python not found (install python3 in the VM)" >&2
    exit 2
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/difftest.XXXXXX")

echo "difftest: runner=$runner guest=$1" >&2

# Two engine runs of the same guest.  I686RT_* plumbing (WINDOW, SYSROOT,
# CACHE, X87, ...) passes through from the environment to both runs.
set +e
I686RT_ENGINE=interp I686RT_TRACE=1 "$runner" -- "$@" \
    >"$tmp/stdout.interp" 2>"$tmp/trace.interp"
rc_interp=$?
I686RT_ENGINE=dbt I686RT_TRACE=1 "$runner" -- "$@" \
    >"$tmp/stdout.dbt" 2>"$tmp/trace.dbt"
rc_dbt=$?
set -e

echo "difftest: interp rc=$rc_interp, dbt rc=$rc_dbt" >&2

# Guest output of the interp run is passed through; the dbt run's output
# is compared against it below.
cat "$tmp/stdout.interp"

set +e
"$python" "$difftrace" "$tmp/trace.interp" "$tmp/trace.dbt"
status=$?
set -e

if [ "$status" -eq 0 ]; then
    if [ "$rc_interp" -ne "$rc_dbt" ]; then
        echo "DIFFTEST: DIVERGENCE guest exit status: interp=$rc_interp dbt=$rc_dbt"
        echo "difftest: captures kept in $tmp" >&2
        exit 1
    fi
    if ! cmp -s "$tmp/stdout.interp" "$tmp/stdout.dbt"; then
        echo "DIFFTEST: DIVERGENCE guest stdout differs:"
        echo "--- $tmp/stdout.interp"
        cat "$tmp/stdout.interp"
        echo "--- $tmp/stdout.dbt"
        cat "$tmp/stdout.dbt"
        exit 1
    fi
    echo "DIFFTEST: EQUAL"
    rm -rf "$tmp"
    exit 0
fi

if [ "$status" -eq 1 ]; then
    echo "DIFFTEST: DIVERGENCE (first mismatch reported above)"
    echo "difftest: traces kept in $tmp" >&2
else
    echo "difftest: difftrace reported a parse error" >&2
fi
exit "$status"
