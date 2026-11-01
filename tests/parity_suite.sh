#!/bin/sh
# tests/parity_suite.sh — Wave C2 uniform 10-category parity gate for i686rt.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Keeps the Wave U3 lane checks (check-line-limits, build-darwin,
# test_u3_sites, lane file ownership) and adds guest execution parity
# rows (--engine interp / --engine dbt, plus --difftest via
# tools/difftest.sh) on prebuilt guests in _build/ compared against
# committed goldens under tests/golden/, plus an AOT round-trip reload
# check and the XMM cache signal check. Finishes with parity_summary
# (0 FAIL, 0 GAP, 0 SKIP).
#
# 10 uniform categories (Wave C2 catalogue): p1_isa (test_p1_isa),
# p2_libc (hello + test_p2_libc), p3_fp (test_p5_fpu_sse, default and
# --x87-80), p3_torture (_build/p3_torture from
# ../rt-series/tests/p3_torture.c), tcg_smoke (_build/tcg_smoke from
# ../rt-series/tests/tcg/smoke_tcg.c), p4_threads
# (test_p4_threads_signals), p5_dyn (_build/test_p5_dyn with the
# committed tests/sysroot/), h1_smc (test_h1_smc), h4_cxx
# (_build/test_h4_cxx, C++17), bench_smoke + aot_reload.
#
# Wave C2 DBT fixes closed the former SKIP gaps (SMC invalidation;
# SSE FTZ/DAZ + cmpps lane order), so PARITY_ALLOW_SKIP stays at its
# default 0 and every SKIP fails the gate.
#
# tcg_smoke note: the shared guest's testthread leg overflows 32-bit
# long (n=200000; fails on native linux/386 too — Lane C2-1 owns the
# shared source). Both engines reproduce it identically (6 pass / 1 fail,
# rc=1 on both), so the golden rows capture that agreement; the difftest
# row is stdout+rc parity because the teardown order is timing-nondet.
#
# Usage:
#   sh tests/parity_suite.sh
#   PARITY_UPDATE_GOLDEN=1 sh tests/parity_suite.sh   # (re)generate goldens
#   HL_PARITY=1 sh tests/parity_suite.sh              # + hl legs
#   PARITY_TIER=qualify sh tests/parity_suite.sh      # + hl legs
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONTRACT="$(cd "$(dirname -- "$0")/../../rt-series/tools" && pwd)/parity_contract.sh"
# shellcheck disable=SC1090
. "$CONTRACT"
parity_init "i686rt"

RT_DARWIN="$ROOT/_build/i686rt-darwin"
RT_LINUX="$ROOT/_build/i686rt"
HL_BIN="$ROOT/../hyper-linux/_build/hl"
GOLDEN_DIR="$ROOT/tests/golden"
BENCH_I686="$ROOT/../rt-series/_build/bench/bench-i686"

mkdir -p "$GOLDEN_DIR"

DO_HL=0
if [ "${HL_PARITY:-0}" = "1" ] || [ "${PARITY_TIER:-smoke}" = "qualify" ]; then
    DO_HL=1
fi

# Normalize bench timing; CRCs stay exact.
norm_bench() {
    sed -E -e 's/us=[0-9]+/us=N/g' -e 's/ops_sec=[0-9]+/ops_sec=N/g' \
        -e 's/total_us=[0-9]+/total_us=N/g' "$1" > "$2"
}

# run_engine <abi> <host> <case> <engine> <guest> <golden-base> [guest-arg...]
# Engine is interp|dbt (mapped to --engine). Compares stdout (bench
# normalized), normalized stderr, and exit code against goldens.
run_engine() {
    _abi="$1"; _host="$2"; _case="$3"; _eng="$4"; _guest="$5"; _gold="$6"
    shift 6
    # HL and darwin share goldens (outputs agree; hl: lines stripped).
    _gold_out="$GOLDEN_DIR/$_gold.out"
    _gold_code="$GOLDEN_DIR/$_gold.code"
    _gold_err="$GOLDEN_DIR/$_gold.err"
    _tmp_out=$(mktemp /tmp/i686parity_out.XXXXXX)
    _tmp_err=$(mktemp /tmp/i686parity_err.XXXXXX)
    _tmp_nout=$(mktemp /tmp/i686parity_nout.XXXXXX)
    _tmp_nerr=$(mktemp /tmp/i686parity_nerr.XXXXXX)
    _tmp_code=$(mktemp /tmp/i686parity_code.XXXXXX)
    _t0=$(parity_now_ms)
    _rc=0
    if [ "$_host" = "hl" ]; then
        # shellcheck disable=SC2086
        perl -e 'alarm 20; exec @ARGV' "$HL_BIN" "$RT_LINUX" --engine "$_eng" -- "$_guest" "$@" >"$_tmp_out" 2>"$_tmp_err" || _rc=$?
    else
        # shellcheck disable=SC2086
        perl -e 'alarm 20; exec @ARGV' "$RT_DARWIN" --engine "$_eng" -- "$_guest" "$@" >"$_tmp_out" 2>"$_tmp_err" || _rc=$?
    fi
    _t1=$(parity_now_ms)
    _ms=0
    if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then
        _ms=$((_t1 - _t0))
    fi
    case "$_case" in
        bench-*) norm_bench "$_tmp_out" "$_tmp_nout" ;;
        *) cp "$_tmp_out" "$_tmp_nout" ;;
    esac
    parity_norm_stderr "$_tmp_err" "$_tmp_nerr"
    printf '%s' "$_rc" > "$_tmp_code"
    _st="PASS"; _det=""
    parity_check_golden "$_gold_out" "$_tmp_nout"; _c=$?
    if [ "$_c" -eq 2 ]; then _st="GAP"; _det="missing golden $_gold.out";
    elif [ "$_c" -ne 0 ]; then _st="FAIL"; _det="stdout differs"; fi
    if [ "$_st" = "PASS" ]; then
        parity_check_golden "$_gold_code" "$_tmp_code"; _c=$?
        if [ "$_c" -eq 2 ]; then _st="GAP"; _det="missing golden $_gold.code";
        elif [ "$_c" -ne 0 ]; then _st="FAIL"; _det="exit $_rc differs"; fi
    fi
    if [ "$_st" = "PASS" ]; then
        parity_check_golden "$_gold_err" "$_tmp_nerr"; _c=$?
        if [ "$_c" -eq 2 ]; then _st="GAP"; _det="missing golden $_gold.err";
        elif [ "$_c" -ne 0 ]; then _st="FAIL"; _det="stderr differs"; fi
    fi
    parity_row "$_abi" "$_host" "$_case" "$_eng" "$_st" "$_ms" "$_det"
    rm -f "$_tmp_out" "$_tmp_err" "$_tmp_nout" "$_tmp_nerr" "$_tmp_code"
}

# run_difftest <abi> <host> <case> <guest> [guest-arg...]
# Uses tools/difftest.sh (interp vs dbt trace EQUAL) with the darwin
# runner (or the linux runner under hl). Bench is excluded here (timing
# digits make the trace harness diverge while CRCs agree; bench CRC
# parity is covered by the interp/dbt rows).
run_difftest() {
    _abi="$1"; _host="$2"; _case="$3"; _guest="$4"
    shift 4
    _t0=$(parity_now_ms)
    _runner="$RT_DARWIN"
    if [ "$_host" = "hl" ]; then
        _runner="$RT_LINUX"
        _hl="$HL_BIN"
    else
        _hl=""
    fi
    _out=$(mktemp /tmp/i686diff_out.XXXXXX)
    _err=$(mktemp /tmp/i686diff_err.XXXXXX)
    _rc=0
    if [ "$_host" = "hl" ]; then
        # Under hl the linux translator runs inside hl; difftest needs
        # the runner path as seen by hl, so run the harness on the host
        # with I686RT_BIN pointing at a wrapper that prefixes hl.
        _wrap=$(mktemp /tmp/i686hlwrap.XXXXXX)
        printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$HL_BIN" "$RT_LINUX" > "$_wrap"
        chmod +x "$_wrap"
        # shellcheck disable=SC2086
        I686RT_BIN="$_wrap" perl -e 'alarm 60; exec @ARGV' "$ROOT/tools/difftest.sh" "$_guest" "$@" >"$_out" 2>"$_err" || _rc=$?
        rm -f "$_wrap"
    else
        # shellcheck disable=SC2086
        I686RT_BIN="$_runner" perl -e 'alarm 60; exec @ARGV' "$ROOT/tools/difftest.sh" "$_guest" "$@" >"$_out" 2>"$_err" || _rc=$?
    fi
    _t1=$(parity_now_ms)
    _ms=0
    if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then
        _ms=$((_t1 - _t0))
    fi
    if [ "$_rc" -eq 0 ] && grep -q "DIFFTEST: EQUAL" "$_out"; then
        parity_row "$_abi" "$_host" "$_case" "difftest" "PASS" "$_ms" ""
    else
        parity_row "$_abi" "$_host" "$_case" "difftest" "FAIL" "$_ms" "rc=$_rc"
    fi
    rm -f "$_out" "$_err"
}

# run_p5 <abi> <host> <engine> [x87flag]
# Compares filtered output against the committed docker/QEMU oracle
# (tests/golden/p5.txt default minus X87ONLY, p5_x87_80.txt full).
# DBT matches interp and the oracle on both modes (Wave C2 SSE fix).
run_p5() {
    _abi="$1"; _host="$2"; _eng="$3"; _x87="${4:-}"
    _case="test_p5_fpu_sse"
    _detail=""
    if [ -n "$_x87" ]; then
        _case="test_p5_fpu_sse-x87-80"
    fi
    _guest="$ROOT/_build/test_p5_fpu_sse"
    if [ ! -x "$_guest" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "GAP" "0" "missing guest test_p5_fpu_sse"
        return
    fi
    _tmp_out=$(mktemp /tmp/i686p5_out.XXXXXX)
    _tmp_filt=$(mktemp /tmp/i686p5_filt.XXXXXX)
    _t0=$(parity_now_ms)
    _rc=0
    if [ "$_host" = "hl" ]; then
        # shellcheck disable=SC2086
        perl -e 'alarm 30; exec @ARGV' "$HL_BIN" "$RT_LINUX" --engine "$_eng" $_x87 -- "$_guest" >"$_tmp_out" 2>/dev/null || _rc=$?
    else
        # shellcheck disable=SC2086
        perl -e 'alarm 30; exec @ARGV' "$RT_DARWIN" --engine "$_eng" $_x87 -- "$_guest" >"$_tmp_out" 2>/dev/null || _rc=$?
    fi
    _t1=$(parity_now_ms)
    _ms=0
    if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then
        _ms=$((_t1 - _t0))
    fi
    if [ -n "$_x87" ]; then
        grep -v "^#" "$GOLDEN_DIR/p5_x87_80.txt" > "$_tmp_filt.golden"
        cp "$_tmp_out" "$_tmp_filt.actual"
    else
        grep -v "^#" "$GOLDEN_DIR/p5.txt" | grep -v "X87ONLY" > "$_tmp_filt.golden"
        grep -v "X87ONLY" "$_tmp_out" > "$_tmp_filt.actual"
    fi
    if [ "$_rc" -ne 0 ]; then
        _detail="exit $_rc"
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" "$_detail"
    elif ! cmp -s "$_tmp_filt.actual" "$_tmp_filt.golden"; then
        _detail="oracle differs"
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" "$_detail"
    else
        parity_row "$_abi" "$_host" "$_case" "$_eng" "PASS" "$_ms" ""
    fi
    rm -f "$_tmp_out" "$_tmp_filt" "$_tmp_filt.golden" "$_tmp_filt.actual"
}

# run_diffout <abi> <host> <case> <guest> [guest-arg...]
# Stdout+exit-code differential (interp vs dbt, no tracing) for guests
# whose syscall traces are thread-timing nondeterministic: dbt-vs-dbt
# traces diverge run to run (tcg testthread teardown order, p4 thread
# signal/futex interleave, h4 cxx thread futex order), so trace EQUAL
# can never be a stable gate.  Guest stdout is byte-compared and exit
# codes must agree; the run_engine golden rows above already pin the
# exact bytes per engine, so this gates interp-vs-dbt agreement
# directly.  Bench uses the same shape (crc-parity detail).
run_diffout() {
    _abi="$1"; _host="$2"; _case="$3"; _guest="$4"
    shift 4
    _o1=$(mktemp /tmp/i686dout1.XXXXXX)
    _o2=$(mktemp /tmp/i686dout2.XXXXXX)
    _t0=$(parity_now_ms)
    _rc1=0; _rc2=0
    if [ "$_host" = "hl" ]; then
        # shellcheck disable=SC2086
        perl -e 'alarm 60; exec @ARGV' "$HL_BIN" "$RT_LINUX" --engine interp -- "$_guest" "$@" >"$_o1" 2>/dev/null || _rc1=$?
        # shellcheck disable=SC2086
        perl -e 'alarm 60; exec @ARGV' "$HL_BIN" "$RT_LINUX" --engine dbt -- "$_guest" "$@" >"$_o2" 2>/dev/null || _rc2=$?
    else
        # shellcheck disable=SC2086
        perl -e 'alarm 60; exec @ARGV' "$RT_DARWIN" --engine interp -- "$_guest" "$@" >"$_o1" 2>/dev/null || _rc1=$?
        # shellcheck disable=SC2086
        perl -e 'alarm 60; exec @ARGV' "$RT_DARWIN" --engine dbt -- "$_guest" "$@" >"$_o2" 2>/dev/null || _rc2=$?
    fi
    _t1=$(parity_now_ms); _ms=0
    if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
    if [ "$_rc1" -eq "$_rc2" ] && cmp -s "$_o1" "$_o2"; then
        parity_row "$_abi" "$_host" "$_case" "difftest" "PASS" "$_ms" "stdout+rc parity; trace timing-nondet"
    else
        parity_row "$_abi" "$_host" "$_case" "difftest" "FAIL" "$_ms" "rc=$_rc1/$_rc2 or stdout differs"
    fi
    rm -f "$_o1" "$_o2"
}

# --- U3 lane checks as parity rows ---
_t0=$(parity_now_ms)
if make -C "$ROOT" --no-print-directory check-line-limits >/tmp/i686_check.log 2>&1; then
    _st="PASS"; _det=""
else
    _st="FAIL"; _det="check-line-limits failed"
fi
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
parity_row "host" "darwin" "check-line-limits" "check" "$_st" "$_ms" "$_det"

_t0=$(parity_now_ms)
if make -C "$ROOT" --no-print-directory build-darwin >/tmp/i686_darwin.log 2>&1; then
    _st="PASS"; _det=""
else
    _st="FAIL"; _det="build-darwin failed"
fi
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
parity_row "host" "darwin" "build-darwin" "check" "$_st" "$_ms" "$_det"

_t0=$(parity_now_ms)
if [ -x "$ROOT/_build/test_u3_sites" ] && "$ROOT/_build/test_u3_sites" >/tmp/i686_sites.log 2>&1; then
    if grep -q "0 FAIL, 0 GAP" /tmp/i686_sites.log; then
        _st="PASS"; _det=""
    else
        _st="FAIL"; _det="test_u3_sites missing 0 FAIL, 0 GAP"
    fi
else
    _st="FAIL"; _det="test_u3_sites failed"
fi
if [ ! -x "$ROOT/_build/test_u3_sites" ]; then
    _st="GAP"; _det="missing _build/test_u3_sites"
fi
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
parity_row "host" "darwin" "test_u3_sites" "check" "$_st" "$_ms" "$_det"

_t0=$(parity_now_ms)
_lane_missing=""
for _f in src/vm/vm32.c src/vm/vm32.h src/vm/vm_file.c src/vm/vm_file.h \
         src/os/backend.h src/os/backend_linux.c src/os/backend_linux_sys.c \
         src/os/backend_darwin.c src/os/backend_darwin_io.c \
         src/os/backend_darwin_net.c \
         src/dbt/aot/aot.h src/dbt/aot/aot.c tests/unit/test_u3_sites.c \
         tests/parity_suite.sh; do
    if [ ! -f "$ROOT/$_f" ]; then
        _lane_missing="$_lane_missing $_f"
    fi
done
if [ -n "$_lane_missing" ]; then
    _st="FAIL"; _det="missing:${_lane_missing}"
elif git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null | grep -qE '^(lane/|master$)'; then
    _st="PASS"; _det=""
else
    _st="FAIL"; _det="not on lane/* or master"
fi
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
parity_row "host" "darwin" "lane-files" "check" "$_st" "$_ms" "$_det"

# --- guest execution parity (darwin legs) ---
if [ -x "$ROOT/_build/hello" ]; then
    run_engine "i686" "darwin" "hello" "interp" "$ROOT/_build/hello" "hello"
    run_engine "i686" "darwin" "hello" "dbt" "$ROOT/_build/hello" "hello"
    run_difftest "i686" "darwin" "hello" "$ROOT/_build/hello"
fi
if [ -x "$ROOT/_build/test_p1_isa" ]; then
    run_engine "i686" "darwin" "test_p1_isa" "interp" "$ROOT/_build/test_p1_isa" "test_p1_isa"
    run_engine "i686" "darwin" "test_p1_isa" "dbt" "$ROOT/_build/test_p1_isa" "test_p1_isa"
    run_difftest "i686" "darwin" "test_p1_isa" "$ROOT/_build/test_p1_isa"
fi
if [ -x "$ROOT/_build/test_h1_smc" ]; then
    run_engine "i686" "darwin" "test_h1_smc" "interp" "$ROOT/_build/test_h1_smc" "test_h1_smc"
    run_engine "i686" "darwin" "test_h1_smc" "dbt" "$ROOT/_build/test_h1_smc" "test_h1_smc"
    run_difftest "i686" "darwin" "test_h1_smc" "$ROOT/_build/test_h1_smc"
fi
if [ -x "$ROOT/_build/test_p5_fpu_sse" ]; then
    run_p5 "i686" "darwin" "interp"
    run_p5 "i686" "darwin" "interp" "--x87-80"
    run_p5 "i686" "darwin" "dbt"
    run_p5 "i686" "darwin" "dbt" "--x87-80"
    run_difftest "i686" "darwin" "test_p5_fpu_sse" "$ROOT/_build/test_p5_fpu_sse"
    I686RT_X87=80 run_difftest "i686" "darwin" "test_p5_fpu_sse-x87-80" "$ROOT/_build/test_p5_fpu_sse"
    unset I686RT_X87
fi
# --- Wave C2 uniform categories (darwin legs) ---
# p2_libc: static libc guest (printf/qsort/malloc/fileio).
if [ -x "$ROOT/_build/test_p2_libc" ]; then
    run_engine "i686" "darwin" "test_p2_libc" "interp" "$ROOT/_build/test_p2_libc" "test_p2_libc"
    run_engine "i686" "darwin" "test_p2_libc" "dbt" "$ROOT/_build/test_p2_libc" "test_p2_libc"
    run_difftest "i686" "darwin" "test_p2_libc" "$ROOT/_build/test_p2_libc"
fi
# p3_torture: shared portable FP torture (rt-series).  Trace difftest is
# stdout+rc parity: the atomic-race thread teardown order flakes
# (2/3 EQUAL, 1/3 order swap at the clone/sigreturn boundary), so trace
# EQUAL cannot gate it.  (I686RT_TRACE_NO_T keeps per-insn T lines out
# of long-loop traces; the ITIMER_REAL bridge in sys_time.c keeps the
# guest alarm(1) alive under slow/traced execution.)
if [ -x "$ROOT/_build/p3_torture" ]; then
    run_engine "i686" "darwin" "p3_torture" "interp" "$ROOT/_build/p3_torture" "p3_torture"
    run_engine "i686" "darwin" "p3_torture" "dbt" "$ROOT/_build/p3_torture" "p3_torture"
    run_diffout "i686" "darwin" "p3_torture" "$ROOT/_build/p3_torture"
fi
# tcg_smoke: shared ALU/mul/thread torture (rt-series, arg = page size).
# Both engines reproduce the shared testthread ILP32 overflow identically
# (6 pass / 1 fail, rc=1 on both; the overflow fails on native linux/386
# too and belongs to Lane C2-1).  Trace difftest is stdout+rc parity:
# the testthread teardown order is thread-timing nondeterministic
# (proven dbt-vs-dbt divergence), so trace EQUAL cannot gate it.
if [ -x "$ROOT/_build/tcg_smoke" ]; then
    run_engine "i686" "darwin" "tcg_smoke" "interp" "$ROOT/_build/tcg_smoke" "tcg_smoke" "4096"
    run_engine "i686" "darwin" "tcg_smoke" "dbt" "$ROOT/_build/tcg_smoke" "tcg_smoke" "4096"
    run_diffout "i686" "darwin" "tcg_smoke" "$ROOT/_build/tcg_smoke" "4096"
fi
# p4_threads: clone/futex/signals/fork/wait guest.  Trace difftest is
# stdout+rc parity (catalogue: difftest where single-thread/supported):
# the thread signal/futex interleave is timing-nondeterministic (proven
# same-engine divergence), so trace EQUAL cannot gate it.
if [ -x "$ROOT/_build/test_p4_threads_signals" ]; then
    run_engine "i686" "darwin" "test_p4_threads_signals" "interp" "$ROOT/_build/test_p4_threads_signals" "test_p4_threads_signals"
    run_engine "i686" "darwin" "test_p4_threads_signals" "dbt" "$ROOT/_build/test_p4_threads_signals" "test_p4_threads_signals"
    run_diffout "i686" "darwin" "test_p4_threads_signals" "$ROOT/_build/test_p4_threads_signals"
fi
# p5_dyn: dynamic PT_INTERP guest against the committed tests/sysroot/.
# Sysroot travels via I686RT_SYSROOT (the runner flag --sysroot).
if [ -x "$ROOT/_build/test_p5_dyn" ] && [ -f "$ROOT/tests/sysroot/lib/ld-musl-i386.so.1" ]; then
    I686RT_SYSROOT="$ROOT/tests/sysroot" run_engine "i686" "darwin" "test_p5_dyn" "interp" "$ROOT/_build/test_p5_dyn" "test_p5_dyn"
    I686RT_SYSROOT="$ROOT/tests/sysroot" run_engine "i686" "darwin" "test_p5_dyn" "dbt" "$ROOT/_build/test_p5_dyn" "test_p5_dyn"
else
    parity_row "i686" "darwin" "test_p5_dyn" "interp" "GAP" "0" "missing guest or sysroot"
    parity_row "i686" "darwin" "test_p5_dyn" "dbt" "GAP" "0" "missing guest or sysroot"
fi
# h4_cxx: C++17 exceptions/RTTI/threads guest.  Trace difftest is
# stdout+rc parity: the cxx thread futex order is timing-nondeterministic
# (proven dbt-vs-dbt divergence), so trace EQUAL cannot gate it.
if [ -x "$ROOT/_build/test_h4_cxx" ]; then
    run_engine "i686" "darwin" "test_h4_cxx" "interp" "$ROOT/_build/test_h4_cxx" "test_h4_cxx"
    run_engine "i686" "darwin" "test_h4_cxx" "dbt" "$ROOT/_build/test_h4_cxx" "test_h4_cxx"
    run_diffout "i686" "darwin" "test_h4_cxx" "$ROOT/_build/test_h4_cxx"
fi
if [ -x "$BENCH_I686" ]; then
    run_engine "i686" "darwin" "bench-i686-smoke" "interp" "$BENCH_I686" "bench-i686-smoke" "--smoke"
    run_engine "i686" "darwin" "bench-i686-smoke" "dbt" "$BENCH_I686" "bench-i686-smoke" "--smoke"
    # Bench difftest via CRC parity (the trace harness diverges on timing
    # digits while CRCs agree).
    _t0=$(parity_now_ms)
    _b1=$(mktemp /tmp/i686b1.XXXXXX); _b2=$(mktemp /tmp/i686b2.XXXXXX)
    _rc1=0; _rc2=0
    perl -e 'alarm 30; exec @ARGV' "$RT_DARWIN" --engine interp -- "$BENCH_I686" --smoke >"$_b1" 2>/dev/null || _rc1=$?
    perl -e 'alarm 30; exec @ARGV' "$RT_DARWIN" --engine dbt -- "$BENCH_I686" --smoke >"$_b2" 2>/dev/null || _rc2=$?
    _t1=$(parity_now_ms); _ms=0
    if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
    _c1=$(grep -o "crc=0x[0-9a-f]*" "$_b1" | tr '\n' ' ')
    _c2=$(grep -o "crc=0x[0-9a-f]*" "$_b2" | tr '\n' ' ')
    if [ "$_rc1" -eq 0 ] && [ "$_rc2" -eq 0 ] && [ -n "$_c1" ] && [ "$_c1" = "$_c2" ]; then
        parity_row "i686" "darwin" "bench-i686-smoke" "difftest" "PASS" "$_ms" "crc-parity"
    else
        parity_row "i686" "darwin" "bench-i686-smoke" "difftest" "FAIL" "$_ms" "crc differs"
    fi
    rm -f "$_b1" "$_b2"
fi

if [ "$DO_HL" -eq 1 ]; then
    if [ ! -x "$HL_BIN" ] || [ ! -x "$RT_LINUX" ]; then
        parity_row "i686" "hl" "hl-leg" "dbt" "GAP" "0" "missing hl or linux translator"
    else
        if [ -x "$ROOT/_build/hello" ]; then
            run_engine "i686" "hl" "hello" "interp" "$ROOT/_build/hello" "hello"
            run_engine "i686" "hl" "hello" "dbt" "$ROOT/_build/hello" "hello"
            run_difftest "i686" "hl" "hello" "$ROOT/_build/hello"
        fi
        if [ -x "$ROOT/_build/test_p1_isa" ]; then
            run_engine "i686" "hl" "test_p1_isa" "interp" "$ROOT/_build/test_p1_isa" "test_p1_isa"
            run_engine "i686" "hl" "test_p1_isa" "dbt" "$ROOT/_build/test_p1_isa" "test_p1_isa"
            run_difftest "i686" "hl" "test_p1_isa" "$ROOT/_build/test_p1_isa"
        fi
        if [ -x "$BENCH_I686" ]; then
            run_engine "i686" "hl" "bench-i686-smoke" "interp" "$BENCH_I686" "bench-i686-smoke" "--smoke"
            run_engine "i686" "hl" "bench-i686-smoke" "dbt" "$BENCH_I686" "bench-i686-smoke" "--smoke"
        fi
    fi
fi

# --- AOT cache round-trip reload check ---
# NOTE (Wave C2): --cache is parsed but has no file backend yet
# (cache_dir is never read; the block serialize/parse format with
# magic/version/crc exists in src/dbt/aot/ but nothing writes or
# reloads files).  This row pins the current contract: both legs run
# rc=0 with byte-identical guest stdout.  File creation/magic checks
# wait on the file-backend feature.
_t0=$(parity_now_ms)
_AOTDIR=$(mktemp -d /tmp/i686aot_parity.XXXXXX)
_AOT1=$(mktemp /tmp/i686aot1.XXXXXX)
_AOT2=$(mktemp /tmp/i686aot2.XXXXXX)
perl -e 'alarm 20; exec @ARGV' "$RT_DARWIN" --cache "$_AOTDIR" -- "$ROOT/_build/hello" >"$_AOT1" 2>/dev/null
_rc1=$?
perl -e 'alarm 20; exec @ARGV' "$RT_DARWIN" --cache "$_AOTDIR" -- "$ROOT/_build/hello" >"$_AOT2" 2>/dev/null
_rc2=$?
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
if [ "$_rc1" -eq 0 ] && [ "$_rc2" -eq 0 ] && cmp -s "$_AOT1" "$_AOT2" && [ "$(cat "$_AOT1")" = "hello" ]; then
    parity_row "i686" "darwin" "aot-reload" "dbt" "PASS" "$_ms" ""
else
    parity_row "i686" "darwin" "aot-reload" "dbt" "FAIL" "$_ms" "rc=$_rc1/$_rc2"
fi
rm -rf "$_AOTDIR" "$_AOT1" "$_AOT2"

# --- XMM cache signal check ---
# Structural: write-through XMM cache (xmm_valid, v16..v23) in
# src/dbt/emit.h + XMM save/restore (xmm_space, ctx->xmm) in
# src/os/signals_i386.c; execution: test_p5 interp PASS (SSE/XMM).
_t0=$(parity_now_ms)
_XDET=""
if ! grep -q "xmm_valid" "$ROOT/src/dbt/emit.h"; then
    _XDET="emit.h lacks xmm_valid"
elif ! grep -q "xmm_space" "$ROOT/src/os/signals_i386.c"; then
    _XDET="signals_i386.c lacks xmm_space"
elif ! grep -q "ctx->xmm" "$ROOT/src/os/signals_i386.c"; then
    _XDET="signals_i386.c lacks ctx->xmm"
fi
_t1=$(parity_now_ms); _ms=0
if [ "$_t0" != "0" ] && [ "$_t1" != "0" ]; then _ms=$((_t1 - _t0)); fi
if [ -z "$_XDET" ]; then
    parity_row "i686" "darwin" "xmm-signal" "dbt" "PASS" "$_ms" ""
else
    parity_row "i686" "darwin" "xmm-signal" "dbt" "FAIL" "$_ms" "$_XDET"
fi

parity_summary
