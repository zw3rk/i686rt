#!/bin/bash
# mkinit.sh — E02: compile the probes (docker linux/amd64 alpine + gcc),
# generate hello-i386 with the host generator, and assemble the
# initramfs (newc cpio, gzipped) with a /dev/console node.
#
# Inputs (under downloads/, fetched by fetch-downloads.sh):
#   downloads/vmlinuz-virt                      Alpine 6.12 virt kernel
#   downloads/busybox/bin/busybox.static        Alpine busybox-static
# Outputs:
#   build/probe-farjmp build/probe-int80 build/run-exe
#   build/hello-i386 build/initramfs.cpio.gz
#
# Everything runs from the experiment directory; artifacts stay in
# build/ (git-ignored).

set -euo pipefail

cd "$(dirname "$0")"
EXP="$PWD"
DL="$EXP/downloads"
BLD="$EXP/build"

mkdir -p "$BLD"

# --- 1. compile freestanding static non-PIE probes in docker (amd64 TCG) ---
docker run --rm --platform linux/amd64 \
    -v "$EXP":/w -w /w alpine:latest sh -c '
set -eux
apk add --no-cache gcc >/dev/null
CFLAGS="-nostdlib -static -no-pie -O2 -Wall -Wextra"
gcc $CFLAGS -o build/probe-farjmp probe-farjmp.S
gcc $CFLAGS -o build/probe-int80  probe-int80.c
gcc $CFLAGS -o build/run-exe      run-exe.c
# probes must be ET_EXEC at VA < 4 GiB for the 32-bit lret trick
readelf -h build/probe-farjmp | grep -E "Type:|Entry point"
'

# --- 2. generate the i386 ELF on the host with the committed generator ---
cc -std=c11 -O2 -Wall -Wextra -Werror -o "$BLD/gen_hello386" gen_hello386.c
"$BLD/gen_hello386" "$BLD/hello-i386"
file "$BLD/hello-i386"

# --- 3. assemble the initramfs in docker (root: mknod works there).
# The tree is staged inside the container (mknod is not possible on the
# macOS bind mount); only the final cpio.gz is copied back out. ---
docker run --rm --platform linux/amd64 \
    -v "$EXP":/w -w /w alpine:latest sh -c '
set -eux
rm -rf build/initroot
mkdir -p build/initroot/bin build/initroot/dev build/initroot/proc build/initroot/sys
cp downloads/busybox/bin/busybox.static build/initroot/bin/busybox
chmod 755 build/initroot/bin/busybox
for a in sh echo cat dmesg grep uname mount mkdir mknod poweroff sleep; do
    ln -sf busybox "build/initroot/bin/$a"
done
cp init build/initroot/init
chmod 755 build/initroot/init
cp build/probe-farjmp build/probe-int80 build/run-exe build/hello-i386 \
   build/initroot/
chmod 755 build/initroot/probe-farjmp build/initroot/probe-int80 \
          build/initroot/run-exe build/initroot/hello-i386
cp -a build/initroot /tmp/initroot
mknod -m 600 /tmp/initroot/dev/console c 5 1
(cd /tmp/initroot && find . | busybox cpio -o -H newc --quiet | gzip -9) \
    > build/initramfs.cpio.gz
rm -rf /tmp/initroot
ls -la build/initramfs.cpio.gz
'

echo "mkinit: done"
