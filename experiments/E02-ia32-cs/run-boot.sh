#!/bin/bash
# run-boot.sh — E02: boot the Alpine 6.12 virt kernel + E02 initramfs in
# qemu-system-x86_64 (TCG) on this Apple Silicon Mac and capture the
# full serial log.
#
# usage: run-boot.sh <log-file> [extra kernel cmdline]
set -euo pipefail

cd "$(dirname "$0")"

QEMU="${QEMU:-/nix/store/3j5v0clldx5f8cq92bj0l15qkh70yybx-qemu-10.2.4/bin/qemu-system-x86_64}"
KERNEL="downloads/vmlinuz-virt"
INITRD="build/initramfs.cpio.gz"
LOG="$1"
APPEND="console=ttyS0 panic=-1"
if [ "$#" -ge 2 ]; then
    APPEND="$APPEND $2"
fi

: > "$LOG"

# Watchdog: kill qemu after 300 s if the guest has not powered off.
(
    sleep 300
    pkill -f "e02-vm-$$.*" 2>/dev/null || true
) &
WD=$?

"$QEMU" -name "e02-vm-$$" \
    -m 512M -smp 1 \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append "$APPEND" \
    -nographic -no-reboot -monitor none \
    >> "$LOG" 2>&1 || true

kill %1 2>/dev/null || true
wait 2>/dev/null || true

echo "run-boot: log written to $LOG ($(wc -c < "$LOG") bytes)"
