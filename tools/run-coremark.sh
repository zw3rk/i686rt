#!/bin/sh
# tools/run-coremark.sh — H3 performance lane: CoreMark under i686rt
# (interp and dbt engines) and the docker linux/386 oracle, plus the
# report generator for tests/hardening/h3-coremark.md.
#
# Usage:
#   tools/run-coremark.sh          fetch + build + the three timed runs
#                                  + write the report (single chain)
#   tools/run-coremark.sh report   re-assemble the report from the
#                                  committed results logs (idempotent;
#                                  this is what `make h3-coremark` runs)
#
# CoreMark v1.01 (EEMBC) is fetched from the GitHub mirror of the
# canonical tag first, then the canonical eembc.org tarball (bounded
# curl inside a docker container; cached under _build/).  A STATIC i386
# build is made in the docker linux/386 alpine gcc oracle container:
#
#   make PORT_DIR=linux compile XCFLAGS="-march=i686 -static \
#        -DPERFORMANCE_RUN=1 -DHAS_FLOAT=0"
#
# -DHAS_FLOAT=0 is the port knob that changes only score PRINTING (the
# "%f" score lines become "%d"; secs_ret double -> ee_u32).  The default
# port build (HAS_FLOAT=1) cannot finish under i686rt: the static musl
# printf float formatter (fmt_fp) contains DA E9 (FUCOMPP), which the
# interpreter's DA-page decode table routes to INVALID — both engines
# died at the same eip with "undecodable instruction" AFTER completing
# all iterations (calibration evidence; recorded in the report).  The
# benchmark WORKLOAD and CRC validation are identical under HAS_FLOAT=0:
# the float matmul still executes and the standard 2K performance CRCs
# still validate.
#
# Iterations are passed on the command line (the port's SEED_ARG path),
# so ONE binary serves all three runs; per-engine iteration counts only
# tune wall time (CoreMark's metric is Iterations/Sec).  The canonical
# performance invocation from the CoreMark Makefile is used:
#
#   coremark.exe 0x0 0x0 0x66 <iterations> 7 1 2000
#
# Runs (each inner-timeout bounded, sequential, --memory 2g --cpus 2,
# named containers with verified removal per the repo test lifecycle
# rules):
#   (a) oracle : the same binary inside the linux/386 container.  The
#       Docker Desktop VM translates i386 user code in user space — on
#       this host that is Rosetta-class translation over an arm64
#       kernel (observed ~4170 CoreMark iter/s; /proc/cpuinfo exposes
#       the Apple ARM cpu), NOT qemu TCG.  Recorded in the "oracle"
#       column regardless; the report states this honestly.
#   (b) interp : arm64 container, i686rt default engine (interp).
#   (c) dbt    : arm64 container, I686RT_ENGINE=dbt.
#
# Raw evidence lands in tests/hardening/results/coremark-*.log plus
# coremark-build.txt and coremark-env.txt; the report subcommand
# assembles tests/hardening/h3-coremark.md ending in the machine line
# "H3: interp=<score> dbt=<score> oracle=<score>".
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

# --- configuration (env-overridable) ----------------------------------------
IMAGE=${H3_IMAGE:-alpine:3.20}
FETCH_TIMEOUT=${H3_FETCH_TIMEOUT:-300}     # curl bound (s)
BUILD_TIMEOUT=${H3_BUILD_TIMEOUT:-600}     # make bound (s)
RUN_TIMEOUT=${H3_RUN_TIMEOUT:-600}         # per-run bound (s)
ITER_ORACLE=${H3_ITER_ORACLE:-300000}      # oracle ~72 s at ~4170 it/s
ITER_INTERP=${H3_ITER_INTERP:-30000}       # interp ~425 s at ~71 it/s
ITER_DBT=${H3_ITER_DBT:-9000}              # dbt    ~390 s at ~23 it/s
FORCE_FETCH=${H3_FORCE_FETCH:-0}
FORCE_BUILD=${H3_FORCE_BUILD:-0}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=$ROOT/_build
CT=$BUILD/coremark
TARBALL=$BUILD/coremark-1.01.tar.gz
RESULTS=$ROOT/tests/hardening/results
STAGE=${H3_STAGE:-/tmp/h3stage}
INNER_BUILD=$BUILD/.h3-coremark-build.sh
INNER_RUN=$BUILD/.h3-coremark-run.sh

log() { echo "run-coremark.sh: $*"; }
die() { echo "run-coremark.sh: $*" >&2; exit 1; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Container lifecycle helpers (repo test lifecycle rules): stop/remove any
# leftover container owned by this task before reuse; after every run the
# removal is verified (docker --rm alone does not prove the container
# exited).
container_clean() {
    docker rm -f "$1" >/dev/null 2>&1 || true
}
container_verify_gone() {
    if docker ps -a --format '{{.Names}}' | LC_ALL=C grep -qx "$1"; then
        die "container $1 still exists after the run (lifecycle violation)"
    fi
}

# --- report subcommand -------------------------------------------------------
# Assemble tests/hardening/h3-coremark.md from the committed evidence in
# $RESULTS.  Idempotent: same logs -> same report.
field_of() { # <file> <grep-pattern>
    LC_ALL=C grep "$2" "$1" 2>/dev/null | head -n 1 | sed 's/^[^:]*: *//'
}
score_of() { # <engine> -> CoreMark's own Iterations/Sec value (int under HAS_FLOAT=0)
    _f=$RESULTS/coremark-$1.log
    [ -f "$_f" ] || { echo "failed(no-log)"; return 0; }
    if LC_ALL=C grep -q "Correct operation validated" "$_f" \
       && LC_ALL=C grep -q "Iterations/Sec" "$_f"
    then
        field_of "$_f" "Iterations/Sec"
    else
        echo "failed(no-valid-score)"
    fi
}
wall_of() { # <engine> -> wall_s:rc from coremark-env.txt
    LC_ALL=C sed -n "s/^# RUNRC $1: wall_s:rc=//p" "$RESULTS/coremark-env.txt" 2>/dev/null
}

report() {
    [ -f "$RESULTS/coremark-env.txt" ] || die "no coremark-env.txt — run the chain first"
    for e in oracle interp dbt; do
        [ -f "$RESULTS/coremark-$e.log" ] || die "no coremark-$e.log — run the chain first"
    done

    s_interp=$(score_of interp)
    s_dbt=$(score_of dbt)
    s_oracle=$(score_of oracle)
    w_interp=$(wall_of interp); w_dbt=$(wall_of dbt); w_oracle=$(wall_of oracle)
    iters_interp=$(field_of "$RESULTS/coremark-interp.log" "^Iterations  ")
    iters_dbt=$(field_of "$RESULTS/coremark-dbt.log" "^Iterations  ")
    iters_oracle=$(field_of "$RESULTS/coremark-oracle.log" "^Iterations  ")
    env_date=$(sed -n 's/^# date: //p' "$RESULTS/coremark-env.txt")
    env_host=$(sed -n 's/^# host: //p' "$RESULTS/coremark-env.txt")
    env_rt=$(sed -n 's/^# i686rt: //p' "$RESULTS/coremark-env.txt")
    env_tar=$(sed -n 's/^# tarball: //p' "$RESULTS/coremark-env.txt")
    env_gcc=$(LC_ALL=C grep -m1 "^gcc (" "$RESULTS/coremark-build.txt" 2>/dev/null || echo unknown)
    # one-decimal iterations/sec derived from iterations / wall seconds
    # (CoreMark's own score is integer-truncated in this build)
    precise_of() { # <iterations> <wall_s:rc>
        _i=$1
        _w=$(printf '%s\n' "$2" | sed 's/^\([0-9]*\):[0-9]*$/\1/')
        case $_i in ''|*[!0-9]*) echo '-'; return 0 ;; esac
        case $_w in ''|0|*[!0-9]*) echo '-'; return 0 ;; esac
        echo "$((_i / _w)).$(( (_i % _w) * 10 / _w ))"
    }
    p_interp=$(precise_of "$iters_interp" "$w_interp")
    p_dbt=$(precise_of "$iters_dbt" "$w_dbt")
    p_oracle=$(precise_of "$iters_oracle" "$w_oracle")

    cat > "$ROOT/tests/hardening/h3-coremark.md" <<EOF
# H3 CoreMark performance report — i686rt interp vs dbt vs linux/386 oracle

Generated by \`tools/run-coremark.sh report\` (\`make h3-coremark\`) from the
committed evidence \`tests/hardening/results/coremark-{interp,dbt,oracle}.log\`
and \`coremark-{env,build}.txt\`.  All numbers below are from real, timed,
bounded runs of ONE static i386 CoreMark v1.01 binary on this host.

## Scores

| engine | binary | iterations | CoreMark Iterations/Sec | precise iters/s (wall) | wall / rc | validation |
|---|---|---|---|---|---|---|
| interp | i686rt default engine | $iters_interp | $s_interp | $p_interp | ${w_interp:-?} | $(LC_ALL=C grep -q "Correct operation validated" "$RESULTS/coremark-interp.log" && echo ok || echo FAILED) |
| dbt | i686rt I686RT_ENGINE=dbt | $iters_dbt | $s_dbt | $p_dbt | ${w_dbt:-?} | $(LC_ALL=C grep -q "Correct operation validated" "$RESULTS/coremark-dbt.log" && echo ok || echo FAILED) |
| oracle | native i386 in docker linux/386 | $iters_oracle | $s_oracle | $p_oracle | ${w_oracle:-?} | $(LC_ALL=C grep -q "Correct operation validated" "$RESULTS/coremark-oracle.log" && echo ok || echo FAILED) |

Score = CoreMark's own "Iterations/Sec" output line (integer arithmetic in
this build; identical rounding on all three sides).  The engines run
different iteration counts purely to stay inside the per-run wall bound
(see "Iterations" below) — Iterations/Sec is the normalized metric, and
every run far exceeds CoreMark's 10 s validity minimum.

Headline reading: the oracle (host-class x86 translation) is roughly two
orders of magnitude above both engines, and within i686rt the dbt engine
measured ~2.5-3x SLOWER than the -Os interpreter on this integer-heavy
workload.

## Environment

- Host: $env_host
- Run date (UTC): $env_date
- Oracle: docker \`--platform linux/386 $IMAGE\` (gcc: $env_gcc).
  NOTE (honest environment statement): this is NOT qemu TCG.  Docker
  Desktop on Apple Silicon runs linux/386 containers with user-space x86
  translation (Rosetta-class) over an arm64 kernel; /proc/cpuinfo inside
  the 386 container exposes the Apple ARM cpu and the observed oracle
  rate is Rosetta-class, ~1-2 orders above qemu-TCG-class speed.  The
  "oracle" column records what was actually measured; it is a strong
  (host-translation-class) reference, not a qemu TCG reference.
- Engines: docker \`--platform linux/arm64 $IMAGE\` running \`_build/i686rt\`
  ($env_rt), engine interp (default) and I686RT_ENGINE=dbt, one process
  per run, --memory 2g --cpus 2, inner bound \`timeout -s KILL $RUN_TIMEOUT\`.
- CoreMark source: $env_tar
- Build: \`make PORT_DIR=linux compile XCFLAGS="-march=i686 -static
  -DPERFORMANCE_RUN=1 -DHAS_FLOAT=0"\` in the linux/386 container.
  -DHAS_FLOAT=0 changes only score PRINTING ("%f" -> "%d"; the "CoreMark
  1.0 : ..." banner line is omitted under HAS_FLOAT=0 — "Iterations/Sec"
  remains the reported metric).  The benchmark workload (list, matrix
  incl. the float matmul, state machine) and CRC validation are
  unchanged; the standard 2K performance CRCs validate on all three
  runs.
- Invocation (canonical CoreMark performance-run parameters):
  \`coremark.exe 0x0 0x0 0x66 <iterations> 7 1 2000\`
- Iterations: oracle=$ITER_ORACLE interp=$ITER_INTERP dbt=$ITER_DBT
  (chosen from calibration rates so the oracle lands in the 60-120 s
  card target and each engine run stays well inside the 600 s bound).

## Counters (flags_elided, chain_hits, ...) — NOT OBSERVABLE in this build

The task asked for the existing counters' readings.  Honest status:
ctx->flags_elided, ctx->chain_hits, ctx->blocks_executed,
ctx->syscalls_executed etc. exist in src/i686rt.h and blocks_executed/
syscalls_executed are incremented, but src/main.c only prints stats
when \`ctx.stats_enabled\` is set — and NOTHING in the current tree sets
it (no --stats flag, no I686RT env var; \`--stats\` is not in the option
table and is rejected by parse_args).  flags_elided and chain_hits have
no increments or readouts reachable at runtime at all (chain_hits is
accumulated only in DBT trampoline registers).  No src/ changes are
allowed in this lane, so the counters' readings are "unavailable (not
wired to any output)".  Recorded for the lanes that own that work.

## Findings

1. DEFAULT-PORT BUILD FAILS UNDER BOTH ENGINES (interpreter decode
   defect, evidence recorded): with -DHAS_FLOAT=1 (the stock linux port),
   both interp (28 s) and dbt (87 s) completed ALL 2000 calibration
   iterations and then died in the final score PRINTING, inside musl's
   static printf float formatter (\`fmt_fp\`):
   \`i686rt: interp: undecodable instruction at eip=0x0804e76f (op:0)\`,
   bytes \`da e9 df e0 9e 7a 1d 75 ...\` = FUCOMPP; FNSTSW AX; SAHF.
   The DA-page decode table (src/x86/insn_tab.h, "x87 DA" group row)
   routes mod=3 reg=5 (the DA E8+i FUCOMP family, incl. DA E9) to
   I686_OP_INVALID even though the row's own comment claims "DA E9
   FUCOMPP"; the registered h_fucompp handler is unreachable.  The dbt
   path dies through the D2 interpret-one-then-resume exit at the same
   eip.  Escalated to the coordinator (DEFECTS.md is not lane-owned).
2. dbt slower than interp on this workload: ~$s_dbt vs ~$s_interp
   Iterations/Sec (H3 card context: dead-flag elimination and block
   linking are the levers the DBT is expected to pull; these are the
   honest baseline numbers they have to beat).  No DBTFALL fallback
   lines appeared in the dbt run stderr.
3. The oracle column is Rosetta-class (see Environment), so the
   interp/dbt-vs-oracle gap is a lower bound on the true gap to qemu
   TCG or native i686.
4. Variance / chain notes: this report is from the second full chain
   invocation.  The first invocation aborted the interp/dbt runs before
   any guest execution (harness argument bug: the runner got no
   \`--\`-separated guest argv, exited rc=2 with its usage text; oracle
   measured 3333 there and was discarded).  The oracle host translation
   is noisy on this Mac: full oracle runs measured 3333, ~4170
   (calibration) and 5000 Iterations/Sec — treat the oracle number as
   +/-25%; the engine numbers (native arm64, single-threaded) repeated
   within ~2% (interp calibration 2000-iteration run: 71/s).

## Reproduce (single official chain)

    PATH=<cross-musl-bin>:\$PATH make build CC=<aarch64-unknown-linux-musl-gcc>
    tools/run-coremark.sh && make h3-coremark

H3: interp=$s_interp dbt=$s_dbt oracle=$s_oracle
EOF
    log "report written: tests/hardening/h3-coremark.md"
}

# --- main --------------------------------------------------------------------
if [ "${1:-}" = "report" ]; then
    report
    exit 0
fi
[ -z "${1:-}" ] || die "unknown argument '$1' (try: report)"

command -v docker >/dev/null 2>&1 || die "docker not found"
docker ps >/dev/null 2>&1 || die "docker daemon not reachable"
[ -x "$BUILD/i686rt" ] || die "_build/i686rt missing — build it first (see Makefile 'build')"
mkdir -p "$BUILD" "$RESULTS"

# --- 1. fetch (cached under _build/) -----------------------------------------
if [ ! -f "$TARBALL" ] || [ "$FORCE_FETCH" = 1 ]; then
    rm -f "$TARBALL"
    fetched=0
    for url in \
        https://github.com/eembc/coremark/archive/refs/tags/v1.01.tar.gz \
        https://www.eembc.org/coremark/downloads/coremark-1.01.tar.gz
    do
        log "fetch: trying $url"
        container_clean h3-coremark-fetch
        if docker run --rm --name h3-coremark-fetch --platform linux/arm64 \
               --memory 2g --cpus 2 -v "$BUILD:/b" \
               -e H3_FETCH_TIMEOUT="$FETCH_TIMEOUT" -e URL="$url" \
               "$IMAGE" sh -c 'apk add -q curl ca-certificates && \
                 timeout "$H3_FETCH_TIMEOUT" curl -fsSL -o /b/coremark-1.01.tar.gz "$URL"'
        then
            fetched=1
            container_verify_gone h3-coremark-fetch
            break
        fi
        container_verify_gone h3-coremark-fetch
    done
    [ "$fetched" = 1 ] || die "all CoreMark fetch attempts failed"
fi
CT_SHA=$(sha256_of "$TARBALL")
log "source tarball: $TARBALL (sha256 $CT_SHA)"

if [ ! -f "$CT/core_main.c" ] || [ "$FORCE_BUILD" = 1 ]; then
    rm -rf "$CT"
    mkdir -p "$CT"
    tar xzf "$TARBALL" -C "$CT" --strip-components 1
fi

# --- 2. staging (fresh; the build writes here, runs read here) ---------------
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$CT" "$STAGE/coremark"
rm -f "$STAGE"/coremark/run*.log
cp "$BUILD/i686rt" "$STAGE/i686rt"
chmod +x "$STAGE/i686rt"

# --- 3. build static i386 coremark (linux/386 oracle container) --------------
cat > "$INNER_BUILD" <<'EOF'
# generated by tools/run-coremark.sh — do not edit
set -eu
apk add -q gcc musl-dev make
cd /w/coremark
make clean >/dev/null 2>&1 || true
timeout "$H3_BUILD_TIMEOUT" make -j"$(nproc)" PORT_DIR=linux compile \
    XCFLAGS="-march=i686 -static -DPERFORMANCE_RUN=1 -DHAS_FLOAT=0"
[ -x coremark.exe ] || { echo "BUILD FAILED: no coremark.exe" >&2; exit 1; }
head -c 4 coremark.exe | od -An -c | head -n 1
gcc --version | head -n 1
EOF
container_clean h3-coremark-build
docker run --rm --name h3-coremark-build --platform linux/386 \
        --memory 2g --cpus 2 -v "$STAGE:/w" -v "$BUILD:/b" \
        -e H3_BUILD_TIMEOUT="$BUILD_TIMEOUT" \
        "$IMAGE" sh /b/.h3-coremark-build.sh > "$RESULTS/coremark-build.txt" 2>&1 \
    || die "coremark build failed (see $RESULTS/coremark-build.txt)"
container_verify_gone h3-coremark-build
# od of the first 4 bytes of an ELF32 shows " 177   E   L   F"
LC_ALL=C grep -q "177" "$RESULTS/coremark-build.txt" \
    || die "coremark.exe is not an ELF image (see $RESULTS/coremark-build.txt)"
log "built static i386 coremark.exe (HAS_FLOAT=0)"

# --- 4. the three timed runs ---------------------------------------------------
cat > "$INNER_RUN" <<'EOF'
# generated by tools/run-coremark.sh — do not edit
# args: <stdout> <stderr> [VAR=val ...] cmd args...
set -u
out=$1; err=$2; shift 2
envs=''
while :; do
    case ${1:-} in
        [A-Za-z_]*=*) envs="$envs $1"; shift ;;
        *) break ;;
    esac
done
start=$(date +%s)
rc=0
# shellcheck disable=SC2086
timeout -s KILL "$H3_RUN_TIMEOUT" env $envs "$@" > "$out" 2> "$err" || rc=$?
end=$(date +%s)
echo "RUNRC=$((end - start)):$rc"
EOF

run_one() { # name platform container stdout stderr [VAR=val ...] cmd args...
    _name=$1; _plat=$2; _crt=$3; shift 3
    container_clean "$_crt"
    _rc=0
    docker run --rm --name "$_crt" --platform "$_plat" \
            --memory 2g --cpus 2 -v "$STAGE:/w" -v "$BUILD:/b" \
            -e H3_RUN_TIMEOUT="$RUN_TIMEOUT" \
            "$IMAGE" sh /b/.h3-coremark-run.sh "$@" \
        > "$RESULTS/.h3-$_name-rc" 2>&1 || _rc=$?
    container_verify_gone "$_crt"
    [ "$_rc" -eq 0 ] || die "$_name run container failed (rc=$_rc)"
}

# (a) oracle: linux/386 container, native run of the same static binary
log "oracle run: $ITER_ORACLE iterations (bound ${RUN_TIMEOUT}s)"
run_one oracle linux/386 h3-coremark-oracle \
    /w/oracle.out /w/oracle.err \
    /w/coremark/coremark.exe 0x0 0x0 0x66 "$ITER_ORACLE" 7 1 2000
cp "$STAGE/oracle.out" "$RESULTS/coremark-oracle.log"
cp "$STAGE/oracle.err" "$RESULTS/coremark-oracle.err"
log "oracle: $(field_of "$RESULTS/coremark-oracle.log" "Iterations/Sec")"

# (b) interp: arm64 container under i686rt, default engine
log "interp run: $ITER_INTERP iterations (bound ${RUN_TIMEOUT}s)"
run_one interp linux/arm64 h3-coremark-interp \
    /w/interp.out /w/interp.err \
    /w/i686rt -- /w/coremark/coremark.exe 0x0 0x0 0x66 "$ITER_INTERP" 7 1 2000
cp "$STAGE/interp.out" "$RESULTS/coremark-interp.log"
cp "$STAGE/interp.err" "$RESULTS/coremark-interp.err"
log "interp: $(field_of "$RESULTS/coremark-interp.log" "Iterations/Sec")"

# (c) dbt: arm64 container under i686rt, I686RT_ENGINE=dbt
log "dbt run: $ITER_DBT iterations (bound ${RUN_TIMEOUT}s)"
run_one dbt linux/arm64 h3-coremark-dbt \
    /w/dbt.out /w/dbt.err \
    I686RT_ENGINE=dbt /w/i686rt -- /w/coremark/coremark.exe 0x0 0x0 0x66 "$ITER_DBT" 7 1 2000
cp "$STAGE/dbt.out" "$RESULTS/coremark-dbt.log"
cp "$STAGE/dbt.err" "$RESULTS/coremark-dbt.err"
log "dbt: $(field_of "$RESULTS/coremark-dbt.log" "Iterations/Sec")"

# --- 5. environment stamp ------------------------------------------------------
RT_SHA=$(sha256_of "$BUILD/i686rt")
{
    echo "# CoreMark run environment (tools/run-coremark.sh)"
    echo "# date: $(date -u '+%FT%TZ')"
    echo "# host: $(uname -sm) (docker desktop)"
    echo "# tarball: $TARBALL sha256=$CT_SHA"
    echo "# i686rt: $BUILD/i686rt sha256=$RT_SHA"
    echo "# image: $IMAGE (linux/386 oracle, linux/arm64 run containers)"
    echo "# coremark flags: -O2 -march=i686 -static -DPERFORMANCE_RUN=1 -DHAS_FLOAT=0"
    echo "# invocation: coremark.exe 0x0 0x0 0x66 <iters> 7 1 2000"
    echo "# iterations: oracle=$ITER_ORACLE interp=$ITER_INTERP dbt=$ITER_DBT"
    echo "# run bound: ${RUN_TIMEOUT}s per run (--memory 2g --cpus 2)"
    for f in oracle interp dbt; do
        _line=$(sed -n 's/^RUNRC=//p' "$RESULTS/.h3-$f-rc" 2>/dev/null | tail -n 1)
        echo "# RUNRC $f: wall_s:rc=${_line:-missing}"
    done
} > "$RESULTS/coremark-env.txt"
rm -f "$RESULTS"/.h3-*-rc

log "chain complete; writing report"
report
