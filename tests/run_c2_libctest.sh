#!/bin/sh
# tests/run_c2_libctest.sh — fix-campaign C2 per-test runner for the H2
# timeout cluster (the 19 named tests).  Fetches/builds the musl
# libc-test tree like tools/run-libctest.sh (same oracle container),
# then runs ONLY the named tests under the translator build with the
# per-test wall bound, appending TAP-ish rows to
# tests/hardening/results/libctest-c2.tap.
#
# Usage: tests/run_c2_libctest.sh [suite/name ...]
#   (no arguments = the 19 H2 timeout tests: functional/clocale_mbfuncs
#    functional/crypt functional/pthread_cancel functional/pthread_cond
#    functional/pthread_robust regression/pthread_once-deadlock
#    regression/raise-race regression/tls_get_new-dtv math/drem
#    math/dremf math/fmod math/fmodf math/fmodl math/remainder
#    math/remainderf math/remainderl math/remquo math/remquof
#    math/remquol)
#
# Container lifecycle: unique names, --cidfile, wall bounds, memory/cpu
# limits, verified removal (repo test lifecycle rules).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

TEST_TIMEOUT=${C2_TEST_TIMEOUT:-30}
FETCH_TIMEOUT=${C2_FETCH_TIMEOUT:-300}
BUILD_TIMEOUT=${C2_BUILD_TIMEOUT:-3600}
IMAGE=alpine:3.20

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=$ROOT/_build
CT=$BUILD/libc-test
RESULTS=$ROOT/tests/hardening/results
TAP=$RESULTS/libctest-c2.tap
CID=$BUILD/c2-cids
mkdir -p "$BUILD" "$RESULTS" "$CID"

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }
docker ps >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 1; }
[ -x "$BUILD/i686rt" ] || { echo "_build/i686rt missing — make build first" >&2; exit 1; }

c2_clean() { docker rm -f "$1" >/dev/null 2>&1 || true; }

c2_run() {
    # c2_run <name> <bound-s> <platform> <mem> <cpus> <cmd...>
    # (all state in c2_-prefixed vars: sh has no locals and the caller
    # iterates with $name/$rc of its own)
    c2_name=$1; c2_bound=$2; c2_plat=$3; c2_mem=$4; c2_cpus=$5
    shift 5
    c2_clean "$c2_name"
    c2_cidf=$CID/$c2_name.cid
    rm -f "$c2_cidf"
    c2_rc=0
    timeout -s KILL "$c2_bound" \
        docker run --rm --name "$c2_name" --cidfile "$c2_cidf" \
            --platform "$c2_plat" --memory "$c2_mem" --cpus "$c2_cpus" \
            -v "$ROOT":/w -w /w \
            "$IMAGE" "$@" || c2_rc=$?
    if docker ps -a --format '{{.Names}}' | LC_ALL=C grep -qx "$c2_name"; then
        c2_clean "$c2_name"
        c2_rc=125
    fi
    rm -f "$c2_cidf"
    return $c2_rc
}

TESTS=${*:-"functional/clocale_mbfuncs functional/crypt
functional/pthread_cancel functional/pthread_cond functional/pthread_robust
regression/pthread_once-deadlock regression/raise-race
regression/tls_get_new-dtv math/drem math/dremf math/fmod math/fmodf
math/fmodl math/remainder math/remainderf math/remainderl math/remquo
math/remquof math/remquol"}

# --- 1. fetch (cached under _build/) --------------------------------------
if [ ! -d "$CT/.git" ]; then
    rm -rf "$CT"
    fetched=0
    for url in https://git.musl-libc.org/libc-test \
               https://repo.or.cz/libc-test.git \
               https://github.com/AssemblyScript/libc-test
    do
        echo "run_c2_libctest: fetch: trying $url"
        if c2_run c2-ct-fetch "$FETCH_TIMEOUT" linux/arm64 2g 2 sh -c \
            "apk add -q git ca-certificates >/dev/null && git clone --depth 1 $url /w/_build/libc-test"
        then
            fetched=1
            break
        fi
        rm -rf "$CT"
    done
    [ "$fetched" = 1 ] || { echo "fetch failed" >&2; exit 1; }
fi
CT_COMMIT=$(git -C "$CT" rev-parse HEAD 2>/dev/null || echo unknown)
echo "run_c2_libctest: source libc-test @ $CT_COMMIT"

# --- 2. build the named -static.exe binaries (linux/386 oracle) -----------
need_build=0
for t in $TESTS; do
    [ -x "$CT/src/${t}-static.exe" ] || need_build=1
done
if [ "$need_build" = 1 ]; then
    targets=""
    for t in $TESTS; do
        targets="$targets src/${t}-static.exe"
    done
    echo "run_c2_libctest: building $TESTS"
    c2_run c2-ct-build "$BUILD_TIMEOUT" linux/386 2g 2 sh -c \
        "apk add -q gcc musl-dev make >/dev/null &&
         cd /w/_build/libc-test &&
         { [ -f config.mak ] || cp config.mak.def config.mak; } &&
         make -k -j\"\$(nproc)\" $targets"
    for t in $TESTS; do
        [ -x "$CT/src/${t}-static.exe" ] || echo "run_c2_libctest: WARNING: $t did not build"
    done
fi

# --- 3. run under i686rt (arm64 container) --------------------------------
{
    echo "# run_c2_libctest.sh (fix-campaign C2) $(date -u '+%FT%TZ')"
    echo "# source: https://git.musl-libc.org/libc-test @ $CT_COMMIT"
    echo "# engine: ${I686RT_ENGINE:-interp}  per-test-timeout: ${TEST_TIMEOUT}s"
} > "$TAP"

i=0
sum_p=0; sum_f=0; sum_t=0; sum_tot=0
for t in $TESTS; do
    suite=${t%%/*}; name=${t##*/}
    bin="/w/_build/libc-test/src/$suite/$name-static.exe"
    sum_tot=$((sum_tot + 1))
    i=$((i + 1))
    if [ ! -x "$CT/src/$suite/$name-static.exe" ]; then
        printf 'not ok %d - %s # SKIP class=build-fail\n' "$i" "$t" >> "$TAP"
        echo "  $t: build-fail"
        continue
    fi
    # The container always exits 0 and reports the test's exit code via
    # the C2RC= line: a container whose PID1 exits 137 (inner timeout
    # killed the translator) leaves THIS docker client hanging on
    # stream teardown (Docker Desktop), which a host-side `timeout`
    # then punishes — in-container capture avoids the whole class.
    # Verdict: C2RC=0 pass, 137 inner-timeout, anything else fail.
    c2_run "c2-test-$$-$name" "$((TEST_TIMEOUT + 90))" linux/arm64 2g 2 sh -c \
        "cd /tmp && timeout -s KILL $TEST_TIMEOUT /w/_build/i686rt -- $bin >/tmp/c2.out 2>/tmp/c2.err; echo C2RC=\$?; cat /tmp/c2.out" \
        > "$BUILD/c2-cids/out.$name" 2> "$BUILD/c2-cids/err.$name" || rc=$?
    rc=${rc:-0}
    c2_rc_line=$(grep -a '^C2RC=' "$BUILD/c2-cids/out.$name" 2>/dev/null | tail -n 1 | cut -d= -f2)
    [ -n "$c2_rc_line" ] || c2_rc_line="$rc"
    case "$c2_rc_line" in
        137|124) rc=137 ;;
        *) rc=$c2_rc_line ;;
    esac
    grep -av '^C2RC=' "$BUILD/c2-cids/out.$name" > "$BUILD/c2-cids/out.$name.clean" 2>/dev/null || true
    mv "$BUILD/c2-cids/out.$name.clean" "$BUILD/c2-cids/out.$name"
    if [ "$rc" -eq 0 ]; then
        sum_p=$((sum_p + 1))
        printf 'ok %d - %s\n' "$i" "$t" >> "$TAP"
        echo "  $t: PASS ($(head -c 80 "$BUILD/c2-cids/out.$name" | tr '\n' ' '))"
    elif [ "$rc" -eq 137 ]; then
        sum_t=$((sum_t + 1))
        printf 'not ok %d - %s\n# class=timeout\n' "$i" "$t" >> "$TAP"
        echo "  $t: TIMEOUT"
    else
        sum_f=$((sum_f + 1))
        printf 'not ok %d - %s\n# class=rc%d\n' "$i" "$t" "$rc" >> "$TAP"
        echo "  $t: FAIL rc=$rc first: $(head -c 80 "$BUILD/c2-cids/out.$name" | tr '\n' ' ')"
    fi
    if docker ps -a --format '{{.Names}}' | LC_ALL=C grep -qx "c2-test-$$-$name"; then
        echo "run_c2_libctest: WARNING: container c2-test-$$-$name survived" >&2
        c2_clean "c2-test-$$-$name"
    fi
done

printf '# RESULT libctest-c2 pass=%d fail=%d timeout=%d total=%d\n' \
    "$sum_p" "$sum_f" "$sum_t" "$sum_tot" >> "$TAP"
echo "run_c2_libctest: pass=$sum_p fail=$sum_f timeout=$sum_t total=$sum_tot"
echo "run_c2_libctest: TAP -> $TAP"
