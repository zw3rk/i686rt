#!/bin/sh
# tests/hardening/mkreport.sh — assemble tests/hardening/h2-report.md from
# the committed runner logs tests/hardening/results/{libctest,ltp}.tap
# (produced by tools/run-libctest.sh and tools/run-ltp.sh).
#
# The numbers are parsed verbatim from the tap logs ("# SUITE"/"# RESULT"
# lines); outcome classes are grouped from the per-row "# class=" comments.
# One-line triage notes are keyed by class in note_for() below — H2 triages
# and reports, it does not fix anything.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RES=$ROOT/tests/hardening/results
REPORT=$ROOT/tests/hardening/h2-report.md
TAB=$(printf '\t')

die() { echo "mkreport.sh: $*" >&2; exit 1; }

[ -f "$RES/libctest.tap" ] || die "missing $RES/libctest.tap (run tools/run-libctest.sh)"
[ -f "$RES/ltp.tap" ]      || die "missing $RES/ltp.tap (run tools/run-ltp.sh)"
grep -q '^# RESULT libctest ' "$RES/libctest.tap" || die "libctest.tap has no RESULT line"
grep -q '^# RESULT ltp ' "$RES/ltp.tap" || die "ltp.tap has no RESULT line"

# --- one-line triage notes keyed by "<log>:<class>" (plus example id) -------
note_for() {
    _side=$1; _cls=$2; _ex=$3
    case "$_side:$_cls" in
        *:timeout)
            case "$_ex" in
                math/*)
                    echo "exceeds the 30 s bound under interp: the drem/fmod/remainder/remquo families either grind enormous ulp vector tables too slowly or spin in an x87 partial-remainder loop — needs I686RT_TRACE sampling before any fix." ;;
                *)
                    echo "exceeds the 30 s bound; the pthread/cond/cancel/robust cluster (and raise-race, pthread_once-deadlock) is the signature of a futex-edge deadlock or livelock under the translator — needs I686RT_TRACE sampling before any fix." ;;
            esac ;;
        *:exec-format)
            echo "guest tried to exec a non-EM_386 image (the container's arm64 /bin/sh via system()/popen()/posix_spawn); by design the translator only loads ELFCLASS32/EM_386." ;;
        *:enosys)
            echo "reached an unimplemented syscall — I686RT_SYSTRACE pins these to _llseek(140), readv(145), tkill(238) and get_robust_list(312) returning -ENOSYS (futex(240) itself works)." ;;
        *:build-fail)
            echo "static build failed in the i386 oracle container (compile/link error); no binary ever existed to run." ;;
        *:global-bound)
            echo "not reached: the run-loop global wall bound expired first." ;;
        *:tconf)
            echo "LTP TCONF exit — the test skipped itself (container lacks a feature); not a translator failure." ;;
        *:design-dynamic)
            echo "binary is dynamically linked and this runner scope is static-only (would need an i386 loader sysroot)." ;;
        *:sig11)
            echo "translator process died with SIGSEGV (unhandled guest fault) — highest-priority triage class." ;;
        *:sig6 | *:sig4)
            echo "guest abort/ILL propagated as a host signal death — guest-visible fault-handling divergence." ;;
        libctest:rc[0-9]*)
            case "$_ex" in
                math/*)
                    echo "musl's math vectors demand exact 80-bit x87 results AND fenv exception flags; the D9 default mode keeps 64-bit doubles with CW rounding and approximate flags — 1-ulp double mismatches, large long-double ('l') mismatches, 'bad fp exception' flag diffs, fenv rounding-mode restore gaps. --x87-80 is the exactness mode (not exercised by this runner)." ;;
                *)
                    echo "test reported failed subchecks (libc-test convention: rc = failure count); semantic divergences dominated by: _llseek(140)/readv(145) ENOSYS breaking stdio fseek/ftello paths; SysV IPC pid fields (msg_lspid/shm_cpid/sempid) carrying host pids instead of the guest pid; robust/PI futex edges (FUTEX_WAIT_REQUEUE_PI, get_robust_list(312) ENOSYS, EDEADLK-vs-deadlock on PI relock); guest setrlimit not enforced on fork/brk; _llseek off_t handling at 0x7fffffff; strptime '%F'; strtod double-rounding (D9 class); dlopen-dependent tests without their DSO." ;;
            esac ;;
        ltp:rc[0-9]*)
            echo "the LTP framework setup trips unimplemented syscalls before most test bodies run — I686RT_SYSTRACE pins ftruncate64(194), sched_getaffinity(242), _llseek(140), msync(144) and statx(383) returning -ENOSYS across the subset (SAFE_* setup, the tmpdir sync check, the CPU-count probe); ioctl ENOTTY / EBADF systrace noise is normal." ;;
        *)
            echo "(open triage — inspect the row in the committed tap log)" ;;
    esac
}

# --- parsers -----------------------------------------------------------------
suites_table() { # <tap>
    awk '
        /^# SUITE / {
            suite=$3; pass=$4; fail=$5; tmo=$6; skip=$7; tot=$8
            sub(/^pass=/, "", pass); sub(/^fail=/, "", fail); sub(/^timeout=/, "", tmo)
            sub(/^skip=/, "", skip); sub(/^total=/, "", tot)
            rate = (tot > 0) ? sprintf("%.1f%%", 100.0 * pass / tot) : "n/a"
            printf "| %s | %s | %s | %s | %s | %s | %s |\n", suite, pass, fail, tmo, skip, tot, rate
        }
    ' "$1"
}

result_field() { # <tap> <field>
    awk -v f="$2" '/^# RESULT [a-z]/ {
        for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == f) print kv[2] }
    }' "$1" | tail -n 1
}

result_line() { # <tap>
    grep '^# RESULT ' "$1" | tail -n 1
}

suite_field() { # <tap> <suite> <field> — field from the "# SUITE <suite>" row
    awk -v s="$2" -v f="$3" '/^# SUITE / && $3 == s {
        for (i = 4; i <= NF; i++) { split($i, kv, "="); if (kv[1] == f) print kv[2] }
    }' "$1" | tail -n 1
}

suite_pt() { # <tap> <suite> — "pass/total (rate%)"
    p=$(suite_field "$1" "$2" pass); t=$(suite_field "$1" "$2" total)
    [ -n "$p" ] && [ -n "$t" ] || die "no # SUITE $2 row in $1"
    r=$(awk -v p="$p" -v t="$t" 'BEGIN { printf "%.1f%%", 100.0 * p / t }')
    printf '%s/%s (%s)' "$p" "$t" "$r"
}

suite_delta() { # <tap-default> <tap-80bit> <suite> — pass-rate delta in pp
    pd=$(suite_field "$1" "$3" pass); td=$(suite_field "$1" "$3" total)
    p8=$(suite_field "$2" "$3" pass); t8=$(suite_field "$2" "$3" total)
    [ -n "$pd" ] && [ -n "$td" ] && [ -n "$p8" ] && [ -n "$t8" ] || die "no # SUITE $3 row for delta"
    awk -v pd="$pd" -v td="$td" -v p8="$p8" -v t8="$t8" \
        'BEGIN { printf "%+.1f pp", 100.0 * (p8 / t8 - pd / td) }'
}

api_compiled() { # <tap> — "compiled/of" from the "# API api-compile" row
    sed -n 's/^# API api-compile compiled=\([0-9]*\) of=\([0-9]*\) .*$/\1\/\2/p' "$1" | tail -n 1
}

tap_source_commit() { # <tap> — libc-test commit recorded in the header
    sed -n 's/^# source: .* @ //p' "$1" | tail -n 1
}

tap_names() { # <tap> <suite> — sorted test names recorded in the tap
    awk -v s="$2" '
        index($0, " - " s "/") > 0 && $0 ~ /^(not )?ok [0-9]+ - / {
            line = $0
            sub(/^.* - /, "", line)
            sub(/[ \t].*$/, "", line)
            sub("^" s "/", "", line)
            print line
        }' "$1" | LC_ALL=C sort
}

pass_names() { # <tap> <suite> — sorted names of passing (non-skip) rows
    awk -v s="$2" '
        index($0, " - " s "/") > 0 && $0 ~ /^ok [0-9]+ - / && $0 !~ /# SKIP/ {
            line = $0
            sub(/^.* - /, "", line)
            sub(/[ \t].*$/, "", line)
            sub("^" s "/", "", line)
            print line
        }' "$1" | LC_ALL=C sort
}

suite_flips() { # <tap-default> <tap-80bit> <suite> — "gained/lost" pass counts
    pd=$(pass_names "$1" "$3"); p8=$(pass_names "$2" "$3")
    g=$(diff_names "$p8" "$pd" | wc -l | tr -d ' ')
    l=$(diff_names "$pd" "$p8" | wc -l | tr -d ' ')
    printf '%s/%s' "$g" "$l"
}

diff_names() { # <names-a> <names-b> — lines of a absent from b
    [ -n "$1" ] || return 0
    printf '%s\n' "$1" | C11_EXCL=$2 awk '
        BEGIN {
            n = split(ENVIRON["C11_EXCL"], arr, "\n")
            for (i = 1; i <= n; i++) if (arr[i] != "") excl[arr[i]] = 1
        }
        !($0 in excl) { print }'
}

suite_drift() { # <tap-default> <tap-80bit> — one "- suite: ..." line per
                # suite whose test-name sets differ, "" when identical
    out=""
    for s in functional regression math; do
        dn=$(tap_names "$1" "$s"); xn=$(tap_names "$2" "$s")
        if [ "$dn" != "$xn" ]; then
            added=$(diff_names "$xn" "$dn")
            removed=$(diff_names "$dn" "$xn")
            line="$s:"
            if [ -n "$added" ]; then line="$line added-upstream: $(printf '%s ' $added)"; fi
            if [ -n "$removed" ]; then line="$line absent-from-80bit: $(printf '%s ' $removed)"; fi
            out="$out
- ${line% }"
        fi
    done
    printf '%s' "$out"
}

# two-mode table (C11: SPEC D9 measurement) — emitted only when the
# optional 80-bit log exists; without it the report is byte-identical
# to the pre-C11 generator output.
two_mode_table() { # <tap-default> <tap-80bit>
    for s in functional regression math; do
        d=$(suite_delta "$1" "$2" "$s")
        fl=$(suite_flips "$1" "$2" "$s")
        if [ "$s" = math ]; then
            # the highlighted row: 80-bit exactness is what the math vectors demand
            printf '| **%s** | %s | %s | **%s** | %s |\n' "$s" "$(suite_pt "$1" "$s")" "$(suite_pt "$2" "$s")" "$d" "$fl"
        else
            printf '| %s | %s | %s | %s | %s |\n' "$s" "$(suite_pt "$1" "$s")" "$(suite_pt "$2" "$s")" "$d" "$fl"
        fi
    done
    printf '| api (compile-time) | %s compiled | %s compiled | n/a (oracle-side) | n/a |\n' \
        "$(api_compiled "$1")" "$(api_compiled "$2")"
}

wall_of() { # <tap>
    sed -n 's/^# WALL seconds=\([0-9]*\)$/\1/p' "$1" | tail -n 1
}

# outcome classes, one line per class:
#   class<TAB>count<TAB>example-id<TAB>first-captured-output-line
classes() { # <tap>
    awk '
        function flush() {
            if (p_id != "") {
                if (p_kind == "fail") {
                    fcnt[p_cls]++
                    if (!(p_cls in fid)) { fid[p_cls] = p_id; fout[p_cls] = p_out }
                } else {
                    scnt[p_cls]++
                    if (!(p_cls in sid)) { sid[p_cls] = p_id; sout[p_cls] = p_out }
                }
            }
            p_id = ""
        }
        BEGIN { p_id = ""; p_out = "-" }
        /^# SUITE / || /^# RESULT / || /^# WALL / || /^1\.\./ || /^ok [0-9]/ || /^not ok [0-9]/ { flush() }
        /^not ok [0-9]+ - / { p_kind = "fail"; p_id = $5; p_cls = "unclassified"; p_out = "-"; next }
        /^ok [0-9]+ - .*# SKIP class=/ {
            p_kind = "skip"
            p_id = $4
            line = $0
            sub(/.*# SKIP class=/, "", line)
            split(line, w, /[ \t]/)
            p_cls = w[1]
            p_out = "-"
            next
        }
        /^# class=/ {
            line = $0
            sub(/^# class=/, "", line)
            split(line, w, /[ \t]/)
            p_cls = w[1]
            next
        }
        /^# out: / { p_out = substr($0, 8); next }
        END {
            flush()
            for (k in fcnt) printf "%s\t%d\tfail\t%s\t%s\n", k, fcnt[k], fid[k], fout[k]
            for (k in scnt) printf "%s\t%d\tskip\t%s\t%s\n", k, scnt[k], sid[k], sout[k]
        }
    ' "$1" | LC_ALL=C sort -t "$TAB" -k2,2rn -k1,1
}

render_classes() { # <tap> <side-label>
    echo "| class | kind | count | example | captured first line | triage note |"
    echo "|---|---|---|---|---|---|"
    classes "$1" | while IFS="$TAB" read -r cls cnt kind exid outline; do
        note=$(note_for "$2" "$cls" "$exid")
        printf '| %s | %s | %d | %s | %s | %s |\n' \
            "$cls" "$kind" "$cnt" "$exid" "$outline" "$note"
    done
}

header_lines() { # <tap>
    grep -E '^# (date|host|i686rt|engine|x87|containers|source|suites):' "$1" | sed 's/^# //'
}

lc_p=$(result_field "$RES/libctest.tap" pass); lc_t=$(result_field "$RES/libctest.tap" total)
ltp_p=$(result_field "$RES/ltp.tap" pass);     ltp_t=$(result_field "$RES/ltp.tap" total)
[ "${lc_t:-0}" -gt 0 ] || die "libctest total is zero"
[ "${ltp_t:-0}" -gt 0 ] || die "ltp total is zero"

rate_of() { # <tap>
    awk -v p="$(result_field "$1" pass)" -v t="$(result_field "$1" total)" \
        'BEGIN { printf "%.1f%%", 100.0 * p / t }'
}

{
    echo "# H2 pass-rate report — musl libc-test + LTP subset under i686rt"
    echo ""
    echo "Generated by \`tests/hardening/mkreport.sh\` (\`make h2-report\`) from the"
    echo "committed runner logs \`tests/hardening/results/{libctest,ltp}.tap\`."
    echo "Pass rate = pass / total over the rows recorded in the log (skip rows"
    echo "count against total; every skip is classified below).  H2 triages and"
    echo "reports — it does not fix anything."
    echo ""
    echo "## Summary"
    echo ""
    echo "| log | pass | fail | timeout | skip | total | pass rate |"
    echo "|---|---|---|---|---|---|---|"
    echo "| libctest | $(result_field "$RES/libctest.tap" pass) | $(result_field "$RES/libctest.tap" fail) | $(result_field "$RES/libctest.tap" timeout) | $(result_field "$RES/libctest.tap" skip) | $(result_field "$RES/libctest.tap" total) | $(rate_of "$RES/libctest.tap") |"
    echo "| ltp | $(result_field "$RES/ltp.tap" pass) | $(result_field "$RES/ltp.tap" fail) | $(result_field "$RES/ltp.tap" timeout) | $(result_field "$RES/ltp.tap" skip) | $(result_field "$RES/ltp.tap" total) | $(rate_of "$RES/ltp.tap") |"
    echo ""
    echo "Raw result lines: \`$(result_line "$RES/libctest.tap")\` / \`$(result_line "$RES/ltp.tap")\`."
    echo ""
    echo "## musl libc-test (static i386, oracle-built) — per suite"
    echo ""
    echo "| suite | pass | fail | timeout | skip | total | pass rate |"
    echo "|---|---|---|---|---|---|---|"
    suites_table "$RES/libctest.tap"
    echo ""
    api_line=$(grep -E '^# API api-compile ' "$RES/libctest.tap" | tail -n 1)
    if [ -n "$api_line" ]; then
        echo "($api_line — the api suite is compile-time-only, see README.md; not part of the runtime totals.)"
        echo ""
    fi
    if [ -f "$RES/libctest-x87_80.tap" ]; then
        grep -q '^# RESULT libctest ' "$RES/libctest-x87_80.tap" \
            || die "libctest-x87_80.tap has no RESULT line"
        echo "## Two-mode measurement: default x87 (64-bit) vs --x87-80 (exact 80-bit)"
        echo ""
        echo "Campaign C11 measurement of SPEC decision D9's exact 80-bit x87 mode"
        echo "(no fix obligation): same runner, same bounds; the only knob is"
        echo "\`H2_X87_80=1\` (\`i686rt --x87-80\`).  Default numbers are cited"
        echo "from the committed log \`results/libctest.tap\`; 80-bit numbers from"
        echo "\`results/libctest-x87_80.tap\`.  Delta = 80-bit pass rate minus"
        echo "default pass rate, in percentage points; flips count per-suite tests"
        echo "passing in exactly one of the two logs (gained/lost by 80-bit)."
        echo ""
        echo "| suite | default pass/total (rate) | --x87-80 pass/total (rate) | delta | flips (80-bit gained/lost) |"
        echo "|---|---|---|---|---|"
        two_mode_table "$RES/libctest.tap" "$RES/libctest-x87_80.tap"
        echo ""
        echo "The **math** delta is the D9 signal: musl's math vectors demand exact"
        echo "80-bit x87 results (and fenv flags); functional/regression do not use"
        echo "x87 transcendentals and are recorded as measured, no threshold."
        echo "The api suite is compile-time-only in the i386 oracle container and"
        echo "is translator- and mode-independent (listed for provenance)."
        echo ""
        drift=$(suite_drift "$RES/libctest.tap" "$RES/libctest-x87_80.tap")
        echo "Source-tree note: default log libc-test @ $(tap_source_commit "$RES/libctest.tap"),"
        echo "80-bit log libc-test @ $(tap_source_commit "$RES/libctest-x87_80.tap")."
        if [ -n "$drift" ]; then
            echo "Test-name drift (rows present in one log only; those suites' deltas"
            echo "mix tree drift with mode — math/regression carry the D9 signal):"
            printf '%s\n' "$drift"
        else
            echo "Test-name sets are identical in both logs."
        fi
        echo ""
        echo "80-bit run header:"
        echo ""
        echo '```'
        header_lines "$RES/libctest-x87_80.tap"
        echo "wall: $(wall_of "$RES/libctest-x87_80.tap") s (run loop, excludes fetch/build)"
        echo '```'
        echo ""
        echo "Raw 80-bit log: \`tests/hardening/results/libctest-x87_80.tap\`."
        echo ""
    fi
    echo "## LTP 20240930 subset (static i386, oracle-built) — per directory"
    echo ""
    echo "| directory | pass | fail | timeout | skip | total | pass rate |"
    echo "|---|---|---|---|---|---|---|"
    suites_table "$RES/ltp.tap"
    echo ""
    echo "## Failure and skip classes"
    echo ""
    echo "### libctest"
    echo ""
    render_classes "$RES/libctest.tap" libctest
    echo ""
    echo "### ltp"
    echo ""
    render_classes "$RES/ltp.tap" ltp
    echo ""
    echo "## Reproduce"
    echo ""
    echo '```sh'
    echo "# build the translator (aarch64 musl cross; see Makefile 'build')"
    echo 'PATH=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH \'
    echo '  make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc'
    echo "# fetch + build (cached under _build/) + run each suite under i686rt"
    echo "tools/run-libctest.sh   # -> tests/hardening/results/libctest.tap"
    echo "tools/run-ltp.sh        # -> tests/hardening/results/ltp.tap"
    echo "make h2-report          # -> tests/hardening/h2-report.md (this file)"
    echo '```'
    echo ""
    echo "## Environment"
    echo ""
    echo "libctest.tap header:"
    echo ""
    echo '```'
    header_lines "$RES/libctest.tap"
    echo "wall: $(wall_of "$RES/libctest.tap") s (run loop, excludes fetch/build)"
    echo '```'
    echo ""
    echo "ltp.tap header:"
    echo ""
    echo '```'
    header_lines "$RES/ltp.tap"
    echo "wall: $(wall_of "$RES/ltp.tap") s (run loop, excludes fetch/build)"
    echo '```'
    echo ""
    echo "Scope, suite selection rationale and classification rules: tests/hardening/README.md."
} > "$REPORT"

printf 'H2: libctest=%s/%s ltp=%s/%s\n' "$lc_p" "$lc_t" "$ltp_p" "$ltp_t" >> "$REPORT"

echo "mkreport.sh: wrote $REPORT"
tail -n 1 "$REPORT"
