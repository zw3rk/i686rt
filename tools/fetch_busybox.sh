#!/bin/sh
# tools/fetch_busybox.sh — fetch the Alpine i686 static busybox for RC2 (L2h)
#
# Copyright 2026 Moritz Angerman <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Lists the Alpine v3.22 main/x86 repository directory first to pick the
# current busybox-static-<ver>.apk filename (an apk is a gzipped tar),
# extracts bin/busybox to _build/busybox-i686, verifies it is a static
# ELF32 Intel 80386 executable, and records the URL + sha256 in
# _build/busybox.sha256.  Idempotent: skips the download when the stamp's
# recorded binary sha256 still matches the file on disk.

set -eu

ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86"
OUT="${1:-_build}/busybox-i686"
APK_DIR=$(dirname "$OUT")
STAMP="$APK_DIR/busybox.sha256"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

mkdir -p "$APK_DIR"

# Idempotent: the stamp's "busybox-i686" line pins the binary sha256
# (sha256sum-style "<sha>  <name>" collapses to two awk fields).
if [ -f "$STAMP" ] && [ -f "$OUT" ]; then
    want=$(awk '$2 == "busybox-i686" {print $1}' "$STAMP" | tail -n 1)
    have=$(sha256_of "$OUT")
    if [ -n "$want" ] && [ "$want" = "$have" ]; then
        echo "busybox: $OUT up to date (sha256 $have)"
        exit 0
    fi
fi

# Pick the current apk name from the live directory index.
index=$(curl -fsSL "$ALPINE_BASE/")
apk_name=$(printf '%s\n' "$index" |
    grep -oE 'busybox-static-[0-9][0-9A-Za-z._-]*\.apk' | sort -u | tail -n 1)
if [ -z "$apk_name" ]; then
    echo "fetch_busybox: no busybox-static apk in $ALPINE_BASE" >&2
    exit 1
fi
url="$ALPINE_BASE/$apk_name"
apk="$APK_DIR/$apk_name"

echo "busybox: fetching $url"
curl -fSL --retry 3 -o "$apk" "$url"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# busybox-static ships the binary as bin/busybox.static (the dynamic
# busybox package owns the plain name); accept either spelling.
entry=$(tar -tzf "$apk" | grep -E '(^|/)bin/busybox$' | head -n 1)
if [ -z "$entry" ]; then
    entry=$(tar -tzf "$apk" | grep -E '(^|/)bin/busybox\.static$' | head -n 1)
fi
if [ -z "$entry" ]; then
    echo "fetch_busybox: no bin/busybox inside $apk_name" >&2
    exit 1
fi
tar -xzf "$apk" -C "$tmp" "$entry"
cp "$tmp/$entry" "$OUT"
chmod 0755 "$OUT"

# Verify: static ELF32 LSB executable for Intel 80386.
file "$OUT" | grep -q 'ELF 32-bit LSB' || {
    echo "fetch_busybox: $OUT is not an ELF 32-bit LSB image" >&2; exit 1; }
file "$OUT" | grep -q 'Intel 80386' || {
    echo "fetch_busybox: $OUT is not an Intel 80386 image" >&2; exit 1; }
file "$OUT" | grep -q 'statically linked' || {
    echo "fetch_busybox: $OUT is not statically linked" >&2; exit 1; }

apk_sha=$(sha256_of "$apk")
bin_sha=$(sha256_of "$OUT")
{
    echo "# url: $url"
    echo "$apk_sha  $apk_name"
    echo "$bin_sha  busybox-i686"
} > "$STAMP"

echo "busybox: $OUT ($apk_name, apk sha256 $apk_sha)"
