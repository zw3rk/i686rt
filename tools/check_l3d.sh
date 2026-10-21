#!/bin/sh
#
# tools/check_l3d.sh — L3d acceptance check (run once, from the lane
# worktree root on the macOS host).
#
# 1. cross-builds the aarch64-musl i686rt runner (nix cross stdenv),
# 2. builds the i386 fixture when _build/test_p1_isa is missing,
# 3. stages difftest.sh, difftrace.py, i686rt and test_p1_isa in a
#    scratch directory (default /tmp/l3d),
# 4. runs the harness inside the aarch64 docker VM (alpine:3.20),
#    asserting:
#      - sh difftest.sh /w/test_p1_isa prints DIFFTEST: EQUAL, RC=0
#      - difftrace.py on a deliberately corrupted trace pair reports a
#        divergence, DIV=1
# 5. prints L3D OK when both hold.
#
# The alpine:3.20 base image ships no python3, so it is apk-installed
# inside the container first (needs container network access).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage=${I686RT_L3D_STAGE:-/tmp/l3d}

nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc \
    -c make -C "$root" build CC=aarch64-unknown-linux-musl-gcc

if [ ! -f "$root/_build/test_p1_isa" ]; then
    make -C "$root" fixtures
fi

rm -rf "$stage"
mkdir -p "$stage"
cp "$root/tools/difftest.sh" "$root/tools/difftrace.py" \
   "$root/_build/i686rt" "$root/_build/test_p1_isa" "$stage/"

log=$stage/check.log
docker run --rm -v "$stage":/w --platform linux/arm64 alpine:3.20 \
    sh -c 'apk add --quiet --no-cache python3 >/dev/null 2>&1 || true;
           cd /w &&
           sh difftest.sh /w/test_p1_isa; echo RC=$?;
           printf "T 1\nT 2\n" > a.txt;
           printf "T 1\nT 9\n" > b.txt;
           python3 difftrace.py a.txt b.txt; echo DIV=$?' > "$log"

cat "$log"

grep -q "DIFFTEST: EQUAL" "$log"
grep -q "^RC=0$" "$log"
grep -q "^DIV=1$" "$log"
echo "L3D OK"
