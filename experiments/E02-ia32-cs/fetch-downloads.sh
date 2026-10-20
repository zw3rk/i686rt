#!/bin/bash
# fetch-downloads.sh — E02: fetch the Alpine kernel and busybox-static
# into downloads/ (kept out of git; see README.md for URLs + sha256).
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p downloads
cd downloads

BASE=https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64

curl -fsLO "$BASE/netboot-3.22.6/vmlinuz-virt"
curl -fsLO "$BASE/netboot-3.22.6/config-6.12.110-0-virt"
curl -fsLO "$BASE/../main/x86_64/busybox-static-1.37.0-r20.apk" ||
    curl -fsLO https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/busybox-static-1.37.0-r20.apk

mkdir -p busybox
tar -xzf busybox-static-1.37.0-r20.apk -C busybox

shasum -a 256 vmlinuz-virt busybox-static-1.37.0-r20.apk
grep -E '^CONFIG_IA32_EMULATION' config-6.12.110-0-virt
