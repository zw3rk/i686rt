#!/usr/bin/env bash
# run-e03.sh — E03 rosetta-elf32 probe driver (as run 2026-10-20)
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Reproduces every E03 probe and writes verbatim transcripts to logs/.
# Read-only wrt hyper-linux/hyper-linux-examples; the only guest-side
# mutation is /tmp/hello-i386 in the lima VM plus a reversible
# binfmt_misc qemu-i386 disable/enable cycle (restored in-line).
set -u

HL=/Users/angerman/Projects/zw3rk/hyper-linux/_build/hl
X64_HELLO=/nix/store/fsqxl9xnppms64abzv3syajrmh4lz389-hl-x64-test-binaries-x86_64-unknown-linux-musl-0.1.0/bin/test-hello
X64_BUSYBOX=/nix/store/aflblv48yhibafwyvh2qfl0r1xx41d6v-busybox-static-x86_64-unknown-linux-musl-1.37.0/bin/busybox
HOST_ROSETTA=/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta
LIMACTL=/nix/store/piidmzyl8dvi91i5y6hs8kaclbalk7bf-lima-2.1.4/bin/limactl
VM=hl-rosetta
VM_ROSETTA=/mnt/lima-rosetta/rosetta
HLFLAGS="--fs-mode=legacy --audio-backend null"

LOGS="$(cd "$(dirname "$0")" && pwd)/logs"
mkdir -p "$LOGS"

# log <name> -- runs the rest verbatim, recording the transcript
log() {
  local name="$1"; shift
  {
    printf '$ %s\n' "$*"
    "$@"
    printf 'exit=%d\n' "$?"
  } >"$LOGS/$name.log" 2>&1
}

# ---- 0. environment -------------------------------------------------
{
  date
  echo "--- host ---"
  uname -m
  sw_vers 2>/dev/null | head -2
  file "$HOST_ROSETTA"
  echo "--- hl ---"
  ls -l "$HL"
  file "$X64_HELLO" "$X64_BUSYBOX"
  echo "--- lima VM $VM ---"
  "$LIMACTL" list
  "$LIMACTL" shell "$VM" -- uname -a
  "$LIMACTL" shell "$VM" -- ls -l "$VM_ROSETTA"
  "$LIMACTL" shell "$VM" -- cat /proc/sys/fs/binfmt_misc/rosetta
  echo "--- test vector ---"
  ./gen_hello386
  file hello-i386
} >"$LOGS/00-environment.log" 2>&1

# ---- 1. hl baselines (x86_64 via Rosetta pipeline) ------------------
log 10-hl-baseline-test-hello   "$HL" $HLFLAGS "$X64_HELLO"
log 11-hl-baseline-busybox      "$HL" $HLFLAGS "$X64_BUSYBOX" sh -c \
  'echo baseline-busybox-ok; uname -m; ls -l ./hello-i386; ls -l /Library/Apple/usr/libexec/oah/RosettaLinux/'

# ---- 2. hl probes ----------------------------------------------------
log 20-hl-launch-hello-i386     "$HL" $HLFLAGS ./hello-i386
log 21-hl-guest-exec-hello-i386 "$HL" $HLFLAGS "$X64_BUSYBOX" sh -c \
  './hello-i386; echo exit=$?'
log 22-hl-guest-exec-translator "$HL" $HLFLAGS "$X64_BUSYBOX" sh -c \
  '/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta ./hello-i386; echo exit=$?'
log 23-hl-native-launch-translator "$HL" $HLFLAGS "$HOST_ROSETTA" ./hello-i386

# ---- 3. lima VM: RosettaLinux itself --------------------------------
"$LIMACTL" shell "$VM" -- cp "$(pwd)/hello-i386" /tmp/hello-i386
"$LIMACTL" shell "$VM" -- chmod 755 /tmp/hello-i386

log 30-lima-baseline-rosetta-x86_64 "$LIMACTL" shell "$VM" -- \
  sh -c "$VM_ROSETTA $X64_BUSYBOX echo rosetta-baseline-ok; echo rc=\$?"
log 31-lima-baseline-binfmt-x86_64   "$LIMACTL" shell "$VM" -- \
  sh -c "$X64_BUSYBOX echo direct-binfmt-ok; $X64_BUSYBOX uname -m; echo rc=\$?"

# CORE PROBE: the RosettaLinux translator handed the ELF32 image.
"$LIMACTL" shell "$VM" -- sh -c \
  "$VM_ROSETTA /tmp/hello-i386 >/tmp/e03.out 2>/tmp/e03.err; rc=\$?; \
   echo rc=\$rc; echo --stdout--; od -c /tmp/e03.out; echo --stderr--; od -c /tmp/e03.err; \
   for i in 1 2 3; do $VM_ROSETTA /tmp/hello-i386; echo try\$i rc=\$?; done" \
  >"$LOGS/32-lima-rosetta-hello-i386.log" 2>&1
echo "wrote $LOGS/32-lima-rosetta-hello-i386.log"

# Isolation: rosetta's own stderr (separate session, no shell death
# diagnostics near the file) — proves both stderr lines are rosetta's.
"$LIMACTL" shell "$VM" -- sh -c \
  'rm -f /tmp/e3c.err; /mnt/lima-rosetta/rosetta /tmp/hello-i386 2>/tmp/e3c.err' \
  >/dev/null 2>&1
"$LIMACTL" shell "$VM" -- sh -c 'od -c /tmp/e3c.err; wc -c /tmp/e3c.err' \
  >"$LOGS/34-lima-rosetta-stderr-isolated.log" 2>&1
echo "wrote $LOGS/34-lima-rosetta-stderr-isolated.log"

# Direct kernel exec: with the VM's stock qemu-i386 binfmt handler
# (confounder: ELF32 is silently emulated by qemu), then with that
# handler disabled (reversible; restored in the same command).
"$LIMACTL" shell "$VM" -- sh -c \
  'echo "--- stock handlers: direct exec ---"; /tmp/hello-i386; echo rc=$?; \
   sudo sh -c "echo 0 > /proc/sys/fs/binfmt_misc/qemu-i386"; \
   echo "--- qemu-i386 handler disabled: direct exec ---"; \
   /tmp/hello-i386; echo rc=$?; \
   sudo sh -c "echo 1 > /proc/sys/fs/binfmt_misc/qemu-i386"; \
   grep -m1 enabled /proc/sys/fs/binfmt_misc/qemu-i386 && echo handler-restored' \
  >"$LOGS/33-lima-direct-exec.log" 2>&1
echo "wrote $LOGS/33-lima-direct-exec.log"

echo "done: $(ls "$LOGS" | wc -l | tr -d " ") logs in $LOGS"
