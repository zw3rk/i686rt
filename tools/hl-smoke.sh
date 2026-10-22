#!/bin/sh
#
# tools/hl-smoke.sh — hl smoke test (Phase 6, L6b)
#
# Usage: tools/hl-smoke.sh [HL [I686RT [BUSYBOX]]]
#
# Runs the i686 busybox `sh -c 'echo ok'` smoke through the hyper-linux
# hl host with the i686rt translator:
#
#   timeout 120 "$HL" --i686rt "$I686RT" "$BUSYBOX" sh -c 'echo ok'
#
# The three arguments default to the Makefile's HL_BIN, I686RT_BIN and
# BUSYBOX_I686 (relative to the repo root).  All three must exist and
# be executable.  Guest stdout is passed through; "HL-SMOKE: OK" is
# printed when the run exits 0 and prints exactly "ok", else the script
# exits non-zero.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

HL=${1:-../hyper-linux/_build/hl}
I686RT=${2:-_build/i686rt}
BUSYBOX=${3:-_build/busybox-i686}

for f in "$HL" "$I686RT" "$BUSYBOX"; do
    [ -x "$f" ] || {
        echo "hl-smoke: $f is missing or not executable" >&2
        exit 2
    }
done

rc=0
out=$(timeout 120 "$HL" --i686rt "$I686RT" "$BUSYBOX" sh -c 'echo ok') || rc=$?

printf '%s\n' "$out"

if [ "$rc" -eq 0 ] && [ "$out" = "ok" ]; then
    echo "HL-SMOKE: OK"
else
    echo "FAIL: hl smoke (rc=$rc; expected exit 0 and output ok)" >&2
    exit 1
fi
