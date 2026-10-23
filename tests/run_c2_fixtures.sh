#!/bin/sh
# tests/run_c2_fixtures.sh — fix-campaign C2 dual-oracle fixture harness.
#
# Builds the static i386 musl fixtures under tests/c2_*.c in the
# linux/386 alpine oracle container, then runs EACH binary twice:
#   1. natively in the linux/386 oracle container (the kernel-oracle
#      run of the same binary), and
#   2. under the translator build (_build/i686rt) in a linux/arm64
#      container,
# both wall-clock bounded, and reports PASS when the two outputs and
# exit codes agree and carry the fixture's PASS line.
#
# Container lifecycle: every run gets a unique name, a --cidfile,
# wall-clock timeout and memory/cpu limits; removal is verified after
# every pass/fail/timeout/error (only containers owned by this script
# are touched).
#
# Usage: tests/run_c2_fixtures.sh [fixture-name ...]
#   (no arguments = all tests/c2_*.c fixtures)
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

RUN_BOUND=${C2_RUN_BOUND:-60}
ORACLE_BOUND=${C2_ORACLE_BOUND:-120}
BUILD_BOUND=${C2_BUILD_BOUND:-600}
IMAGE=alpine:3.20
CCPKG="gcc musl-dev"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=$ROOT/_build
OUT=$BUILD/c2-fixtures
CID=$OUT/cids
mkdir -p "$OUT" "$CID"

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
docker ps >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 1; }
[ -x "$BUILD/i686rt" ] || { echo "_build/i686rt missing — make build first" >&2; exit 1; }

c2_clean() { docker rm -f "$1" >/dev/null 2>&1 || true; }

c2_verify_gone() {
    if docker ps -a --format '{{.Names}}' | LC_ALL=C grep -qx "$1"; then
        echo "c2-fixtures: container $1 still exists after run" >&2
        docker rm -f "$1" >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}

# run_bounded <name> <bound-s> <platform> <memory> <cpus> <cmd...>
run_bounded() {
    name=$1; bound=$2; plat=$3; mem=$4; cpus=$5
    shift 5
    c2_clean "$name"
    cidf=$CID/$name.cid
    rm -f "$cidf"
    timeout -s KILL "$bound" \
        docker run --rm --name "$name" --cidfile "$cidf" \
            --platform "$plat" --memory "$mem" --cpus "$cpus" \
            -v "$ROOT":/w -w /w \
            "$IMAGE" "$@"
    rc=$?
    if docker ps -a --format '{{.Names}}' | LC_ALL=C grep -qx "$name"; then
        # --rm removes on exit; a surviving container means a kill race
        c2_clean "$name"
    fi
    rm -f "$cidf"
    return $rc
}

# --- 1. build all requested fixtures in ONE bounded 386 container -----
FIXTURES=${*:-}
if [ -z "$FIXTURES" ]; then
    FIXTURES=$(cd "$ROOT/tests" && LC_ALL=C ls c2_*.c | sed 's/\.c$//')
fi

clean_build() { c2_clean c2-fix-build; }
trap 'clean_build; true' EXIT
clean_build
build_cmd="apk add -q $CCPKG >/dev/null"
for f in $FIXTURES; do
    build_cmd="$build_cmd && cc -std=gnu11 -O1 -static -o /w/_build/c2-fixtures/$f /w/tests/$f.c"
done
echo "c2-fixtures: building $FIXTURES (linux/386 oracle, static musl)"
rm -f "$CID/c2-fix-build.cid"
timeout -s KILL "$BUILD_BOUND" \
    docker run --rm --name c2-fix-build --cidfile "$CID/c2-fix-build.cid" \
        --platform linux/386 --memory 2g --cpus 2 \
        -v "$ROOT":/w -w /w \
        "$IMAGE" sh -c "$build_cmd"
c2_verify_gone c2-fix-build
rm -f "$CID/c2-fix-build.cid"

# --- 2. per fixture: oracle run + translator run, compare -------------
overall=0
for f in $FIXTURES; do
    echo "=== $f ==="
    ob=$OUT/$f.oracle.out; oe=$OUT/$f.oracle.err
    tb=$OUT/$f.rt.out;     te=$OUT/$f.rt.err

    if run_bounded "c2-oracle-$f" "$ORACLE_BOUND" linux/386 2g 2 \
            sh -c "/w/_build/c2-fixtures/$f > /w/_build/c2-fixtures/$f.oracle.out 2> /w/_build/c2-fixtures/$f.oracle.err"; then
        orc_rc=0
    else
        orc_rc=$?
    fi
    c2_verify_gone "c2-oracle-$f" || overall=1

    if run_bounded "c2-rt-$f" "$RUN_BOUND" linux/arm64 2g 2 \
            sh -c "/w/_build/i686rt -- /w/_build/c2-fixtures/$f > /w/_build/c2-fixtures/$f.rt.out 2> /w/_build/c2-fixtures/$f.rt.err"; then
        rt_rc=0
    else
        rt_rc=$?
    fi
    c2_verify_gone "c2-rt-$f" || overall=1

    oracle_line=$(head -n 1 "$ob" 2>/dev/null || echo "")
    rt_line=$(head -n 1 "$tb" 2>/dev/null || echo "")
    echo "  oracle rc=$orc_rc: $oracle_line $(tail -n +2 "$ob" 2>/dev/null | tr '\n' ';')"
    echo "  i686rt rc=$rt_rc: $rt_line"
    if [ -s "$te" ]; then
        echo "  i686rt stderr: $(tail -n 3 "$te" | tr '\n' ';')"
    fi
    # PASS: the translator run must be rc=0 with its PASS line.  The
    # oracle may be unable to run a phase under qemu-user (exit 42 +
    # SKIP line — recorded as an oracle limitation); when it CAN run
    # (rc=0) its first line must match the translator's.
    if [ "$rt_rc" -eq 0 ] && [ "$rt_line" = "$(printf '%s PASS' "${rt_line%% *}")" ] && \
       { [ "$orc_rc" -eq 42 ] || { [ "$orc_rc" -eq 0 ] && [ "$oracle_line" = "$rt_line" ]; }; }; then
        echo "  -> PASS"
    else
        echo "  -> FAIL (oracle rc=$orc_rc, rt rc=$rt_rc)"
        overall=1
    fi
done

if [ "$overall" -eq 0 ]; then
    echo "c2-fixtures: ALL PASS"
else
    echo "c2-fixtures: FAILURES PRESENT"
fi
exit "$overall"
