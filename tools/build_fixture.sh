#!/bin/sh
#
# tools/build_fixture.sh — build a freestanding i386 static ELF fixture
#
# Usage: tools/build_fixture.sh <src.c> <out>
#
# E06-proven path (experiments/E06-nixpkgs-attrs/FINDINGS.md): docker
# --platform linux/386 alpine:3.20 runs a real i386 environment (QEMU
# TCG inside Docker Desktop) whose gcc is natively 32-bit, so no -m32
# is needed.  The output is a genuine static ELF32 EM_386 executable,
# verified with file(1) before this script reports success.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: tools/build_fixture.sh <src.c> <out>" >&2
    exit 2
fi

src=$1
out=$2

case $src in /*) ;; *) src=$PWD/$src ;; esac
case $out in /*) ;; *) out=$PWD/$out ;; esac

if [ ! -f "$src" ]; then
    echo "build_fixture.sh: no such source: $src" >&2
    exit 2
fi

# Both paths must live under the repository root so a single docker
# volume mount covers the source and the output.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case $src in
    "$root"/*) src=${src#"$root"/} ;;
    *) echo "build_fixture.sh: source must live under $root" >&2; exit 2 ;;
esac
case $out in
    "$root"/*) out=${out#"$root"/} ;;
    *) echo "build_fixture.sh: output must live under $root" >&2; exit 2 ;;
esac

mkdir -p "$root/$(dirname -- "$out")"

extra_src=
if [ -f "$root/${src%.c}_cases.c" ]; then
    extra_src="${src%.c}_cases.c"
fi

docker run --rm --platform linux/386 \
    -v "$root":/w \
    alpine:3.20 \
    sh -c "apk add --no-cache gcc musl-dev >/dev/null &&
           cd /w &&
           cc -std=c11 -Wall -Wextra -ffreestanding -static -nostdlib -O2 \
              -march=i686 -mno-mmx -mno-sse -mno-sse2 \
              -fno-pie -fno-stack-protector \
              -o '$out' '$src' $extra_src"

desc=$(file -b "$out")
case $desc in
    *"ELF 32-bit LSB executable, Intel 80386"*)
        echo "build_fixture.sh: $out: $desc"
        ;;
    *)
        echo "build_fixture.sh: $out is not an i386 static ELF: $desc" >&2
        exit 1
        ;;
esac
