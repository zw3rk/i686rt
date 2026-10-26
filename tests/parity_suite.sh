#!/bin/sh
# tests/parity_suite.sh — Zero-GAP parity gate for Wave U3 lane u3-i686.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the lane's bounded acceptance surface on the host toolchain:
# curated-C11 line limits, the Wave U3 TU compile set, and the portable
# host check (site layout, AOT round-trip, Provider A promotion, regime
# selection, dual-backend smoke). Prints "0 FAIL, 0 GAP" on success.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail=0
gap=0

note() { printf '%s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*"; fail=$((fail + 1)); }
missing() { printf 'GAP: %s\n' "$*"; gap=$((gap + 1)); }

note "== u3-i686 parity: line limits =="
if make -C "$ROOT" --no-print-directory check-line-limits >/dev/null 2>&1; then
  note "line-limits: ok"
else
  bad "check-line-limits failed"
fi

note "== u3-i686 parity: darwin TU set + host check =="
if make -C "$ROOT" --no-print-directory build-darwin >/tmp/u3-darwin.log 2>&1; then
  note "build-darwin: ok"
else
  bad "build-darwin failed (see /tmp/u3-darwin.log)"
fi

note "== u3-i686 parity: host check output =="
if [ -x "$ROOT/_build/test_u3_sites" ]; then
  if "$ROOT/_build/test_u3_sites" > /tmp/u3-sites.log 2>&1; then
    note "test_u3_sites: ok"
  else
    bad "test_u3_sites failed (see /tmp/u3-sites.log)"
  fi
  case "$(cat /tmp/u3-sites.log)" in
    *"0 FAIL, 0 GAP"*) note "host check reports 0 FAIL, 0 GAP" ;;
    *) bad "host check did not report 0 FAIL, 0 GAP" ;;
  esac
else
  missing "_build/test_u3_sites was not built"
fi

note "== u3-i686 parity: lane file ownership =="
for f in src/vm/vm32.c src/vm/vm32.h src/vm/vm_file.c src/vm/vm_file.h \
         src/os/backend.h src/os/backend_linux.c src/os/backend_linux_sys.c \
         src/os/backend_darwin.c src/os/backend_darwin_io.c \
         src/os/backend_darwin_net.c \
         src/dbt/aot/aot.h src/dbt/aot/aot.c tests/unit/test_u3_sites.c \
         tests/parity_suite.sh; do
  if [ ! -f "$ROOT/$f" ]; then
    bad "lane file missing: $f"
  fi
done
if git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null | grep -q 'lane/u3-i686'; then
  note "branch: lane/u3-i686"
else
  bad "not on lane/u3-i686"
fi

if [ "$fail" -eq 0 ] && [ "$gap" -eq 0 ]; then
  printf 'parity_suite: 0 FAIL, 0 GAP\n'
  exit 0
fi
printf 'parity_suite: %d FAIL, %d GAP\n' "$fail" "$gap"
exit 1
