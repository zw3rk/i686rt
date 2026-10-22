#!/bin/sh
#
# tools/setup-wine32.sh — fetch the Debian i386 Wine32 sysroot for i686rt
# (Phase 7, card L7b; SPEC 4 7.3).
#
# Populates _sysroot/debian-wine32-i386/ with the minimal non-wow64 Wine
# set for a text-mode `wine cmd /c echo ok` under i686rt --sysroot, plus
# the glibc the wine loader needs.  Extraction preserves package paths
# (usr/bin/wine-stable, usr/lib/i386-linux-gnu/wine/...), the same
# dpkg-deb-style layout tools/setup_sysroot.py produces for the plain
# glibc sysroot (_sysroot/debian-i386/).
#
# Package closure (determined from the archive, wine 10.0~repack era,
# non-wow64 i386; versions derived from the pool at run time):
#
#   libc6 + libc6-i686        pool/main/g/glibc/   ld-linux.so.2, libc,
#                                                  libm (the only DT_NEEDED
#                                                  outside the wine tree)
#   libwine (i386)            the wine tree: i386-unix/*.so,
#                             i386-windows/*.dll|*.exe PE builtins
#                             (ntdll, kernel32, cmd.exe, ...),
#                             usr/share/wine/wine.inf (needed by wineboot)
#   wine-common (all)         usr/share/wine/fonts/ (registered by
#                             wineboot when creating the prefix)
#   wine32 (i386)             usr/lib/i386-linux-gnu/wine/wine (the real
#                             ELF32 loader), .../wineserver,
#                             usr/bin/wine32-stable wrapper
#   wine32-preloader (i386)   usr/lib/i386-linux-gnu/wine/wine-preloader
#   wine (all)                usr/bin/*-stable wrappers + apploader
#
# `wine cmd` needs no graphics stack: libwine's large Debian Depends
# (X11/wayland/pulse/gstreamer/avcodec/fontconfig/freetype/...) are the
# everything-enabled build's runtime-dlopened optional subsystems, each
# with graceful fallback; the loader-side DT_NEEDED set of wine/wine,
# wine/wineserver, i386-unix/ntdll.so and i386-unix/win32u.so is exactly
# { libc.so.6, libm.so.6, ntdll.so } (verified with objdump -p).  Those
# packages are therefore NOT fetched.
#
# No maintainers scripts run on plain extraction, so the update-
# alternatives links a real Debian system has are recreated as symlinks
# (usr/bin/wine -> wine-stable, usr/bin/wine32 -> wine32-stable,
# usr/bin/wineboot -> wineboot-stable; libwine postinst, slave links),
# and the usrmerge compat symlink lib -> usr/lib is added when the debs
# did not ship a real lib/ tree (same as setup_sysroot.py).  i686rt's
# --sysroot resolver handles the i386-linux-gnu multiarch paths.
#
# Each .deb is an `ar` archive; the data.tar.* member is streamed through
# `ar p` + `tar` (data.tar.xz / data.tar.gz; zstd debs are rejected with
# a clear message — current Debian wine and glibc debs ship xz).  curl
# transfers are bounded by --max-time; pool listing -> newest-version
# selection is per package with upstream-version coherence across the
# wine set (epoch/debian-revision stripped).  A rerun whose .stamp still
# matches the key files on disk skips all work (idempotent); --force
# re-fetches and re-extracts from scratch.  Downloaded debs are cached
# in _sysroot/pool (shared with setup_sysroot.py) and reused when the
# ar magic still checks out.
#
# Usage:
#     tools/setup-wine32.sh            fetch + extract + stamp
#     tools/setup-wine32.sh --verify   check the tree; prints
#                                      WINE32-SYSROOT-OK iff
#                                      usr/bin/wine (or wine-stable) is
#                                      executable and the wine32 shared
#                                      objects are present
#     tools/setup-wine32.sh --force    re-fetch + re-extract
#
# Requires: curl, ar, tar (xz), sort -V, sha256sum or shasum.  Runs on
# macOS (same host class as setup_sysroot.py) and Linux.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

set -eu

MIRROR=https://deb.debian.org/debian
WINE_POOL=pool/main/w/wine
GLIBC_POOL=pool/main/g/glibc
DASH_POOL=pool/main/d/dash

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$self_dir/.." && pwd)
sysroot=$repo_root/_sysroot/debian-wine32-i386
cache_dir=$repo_root/_sysroot/pool
stamp=$sysroot/.stamp

ua=i686rt-setup-wine32/1.0
curl_list_max=60      # seconds, pool listing
curl_get_max=900      # seconds, single deb download

prog=$(basename -- "$0")

die() {
    printf '%s: error: %s\n' "$prog" "$*" >&2
    exit 1
}

info() {
    printf '%s: %s\n' "$prog" "$*"
}

check_tools() {
    for tool in curl ar tar; do
        command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
    done
    LC_ALL=C sort -V </dev/null >/dev/null 2>&1 \
        || die "sort -V (version sort) not supported by this sort"
    if command -v sha256sum >/dev/null 2>&1; then
        hash_cmd=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        hash_cmd=shasum
    else
        die "required: sha256sum or shasum"
    fi
}

hash_file() {  # <file> -> sha256 hex on stdout
    if [ "$hash_cmd" = sha256sum ]; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

http_get() {  # <url>  (bounded)
    curl -fsS --retry 2 --max-time "$curl_list_max" -A "$ua" "$1"
}

deb_candidates() {  # <listing> <pkg> <arch-suffix: all|i386> -> filenames
    printf '%s\n' "$1" \
        | sed -n 's/.*href="\('"$2"'_[^"]*_'"$3"'\.deb\)".*/\1/p'
}

newest_deb() {  # candidates on stdin -> newest filename (sort -V)
    sort -V | tail -n 1
}

upstream_of() {  # <deb filename> -> upstream version (epoch + revision stripped)
    w_up=${1#*_}            # strip pkgname -> [epoch:]upstream-revision_arch.deb
    w_up=${w_up%_*}         # strip _arch.deb -> [epoch:]upstream-revision
    case $w_up in *:*) w_up=${w_up#*:} ;; esac   # strip epoch
    w_up=${w_up%-*}         # strip debian revision (+binNMU)
}

fetch_deb() {  # <pool-subdir> <filename>; sets fetched_path
    f_url=$1
    f_dest=$cache_dir/$2
    if [ -f "$f_dest" ] && [ "$(head -c 8 "$f_dest" 2>/dev/null)" = '!<arch>' ]; then
        info "cached $2"
        fetched_path=$f_dest
        return 0
    fi
    curl -fsS --retry 2 --max-time "$curl_get_max" -A "$ua" \
        -o "$f_dest.part" "$f_url" \
        || die "download failed: $f_url"
    [ "$(head -c 8 "$f_dest.part")" = '!<arch>' ] \
        || die "not an ar archive: $f_url"
    mv "$f_dest.part" "$f_dest"
    info "downloaded $2 ($(wc -c <"$f_dest" | tr -d ' ') bytes)"
    fetched_path=$f_dest
}

extract_deb() {  # <deb path>
    e_deb=$1
    e_member=$(ar t "$e_deb" | grep -E '^data\.tar\.(xz|gz|zst)$' | head -n 1)
    [ -n "$e_member" ] || die "no data.tar.* member in $e_deb"
    case $e_member in
    *.zst)
        die "$e_deb uses $e_member; zstd extraction is not supported by \
this script (current Debian wine and glibc debs ship data.tar.xz)"
        ;;
    esac
    if ar p "$e_deb" "$e_member" | tar -tf - | grep -qE '(^|/)\.\.(/|$)'; then
        die "unsafe member path in $e_deb (.. component)"
    fi
    case $e_member in
    *.xz) ar p "$e_deb" "$e_member" | tar -xJf - -C "$sysroot" ;;
    *.gz) ar p "$e_deb" "$e_member" | tar -xzf - -C "$sysroot" ;;
    esac
}

stamp_ok() {  # 0 if .stamp exists and every key file still hashes equal
    [ -f "$stamp" ] || return 1
    s_paths=$(sed -n 's/^key //p' "$stamp") || return 1
    [ -n "$s_paths" ] || return 1
    while IFS= read -r s_line; do
        s_rel=${s_line%% *}
        s_hash=${s_line#* }
        if [ ! -f "$sysroot/$s_rel" ] \
            || [ "$(hash_file "$sysroot/$s_rel")" != "$s_hash" ]; then
            return 1
        fi
    done <<EOF
$s_paths
EOF
    return 0
}

write_stamp() {  # args: <pool-subdir>:<deb filename> ...
    : >"$stamp"
    w_total=0
    for w_entry in "$@"; do
        w_pool=${w_entry%%:*}
        w_file=${w_entry#*:}
        w_ver=${w_file%_*}
        w_ver=${w_ver#*_}
        w_path=$cache_dir/$w_file
        w_size=$(wc -c <"$w_path" | tr -d ' ')
        w_total=$((w_total + w_size))
        printf 'package %s %s %s %s %s %s\n' \
            "${w_file%%_*}" "$w_ver" \
            "$(hash_file "$w_path")" "$w_size" \
            "$MIRROR/$w_pool/$w_file" "$w_file" >>"$stamp"
    done
    for w_rel in \
        usr/lib/i386-linux-gnu/wine/wine \
        usr/lib/i386-linux-gnu/wine/wineserver \
        usr/lib/i386-linux-gnu/wine/i386-unix/ntdll.so \
        usr/lib/i386-linux-gnu/wine/i386-windows/ntdll.dll \
        usr/lib/i386-linux-gnu/wine/i386-windows/kernel32.dll \
        usr/lib/i386-linux-gnu/wine/i386-windows/cmd.exe \
        usr/share/wine/wine.inf \
        usr/bin/dash \
        lib/ld-linux.so.2 \
        usr/lib/i386-linux-gnu/libc.so.6
    do
        [ -f "$sysroot/$w_rel" ] || die "key file missing after extraction: $w_rel"
        printf 'key %s %s\n' "$w_rel" "$(hash_file "$sysroot/$w_rel")" >>"$stamp"
    done
    info "stamp written: $stamp (total download $w_total bytes)"
}

do_fetch() {
    check_tools
    if [ -f "$stamp" ] && stamp_ok; then
        info "stamp matches; wine32 sysroot up to date ($stamp)"
        return 0
    fi

    # --- derive the package set from the pool listings -------------------
    w_listing=$(http_get "$MIRROR/$WINE_POOL/") \
        || die "cannot list $MIRROR/$WINE_POOL/"
    g_listing=$(http_get "$MIRROR/$GLIBC_POOL/") \
        || die "cannot list $MIRROR/$GLIBC_POOL/"

    libwine_deb=$(deb_candidates "$w_listing" libwine i386 | newest_deb)
    [ -n "$libwine_deb" ] || die "no libwine_*_i386.deb in $WINE_POOL"
    upstream_of "$libwine_deb"
    up=$w_up
    info "wine set: newest libwine $libwine_deb (upstream $up)"

    w_pkgs=
    for spec in \
        'wine32 i386' \
        'wine32-preloader i386' \
        'wine all' \
        'wine-common all'
    do
        w_pkg=${spec%% *}
        w_arch=${spec#* }
        w_deb=$(deb_candidates "$w_listing" "$w_pkg" "$w_arch" \
            | grep -F "_${up}-" | newest_deb)
        [ -n "$w_deb" ] || die "no $w_pkg matching wine upstream $up in $WINE_POOL"
        w_pkgs="$w_pkgs $w_deb"
        info "  $w_deb"
    done

    libc6_deb=$(deb_candidates "$g_listing" libc6 i386 | newest_deb)
    [ -n "$libc6_deb" ] || die "no libc6_*_i386.deb in $GLIBC_POOL"
    info "glibc: newest $libc6_deb"
    libc6i686_deb=$(deb_candidates "$g_listing" libc6-i686 i386 | newest_deb)
    if [ -n "$libc6i686_deb" ]; then
        info "glibc: newest $libc6i686_deb"
    else
        info "libc6-i686: not shipped for this suite (skipped; modern \
Debian i386 glibc is i686-optimized in libc6 itself)"
    fi

    # dash provides /bin/sh: the wine wrapper scripts (usr/bin/wine ->
    # wine-stable `#!/bin/sh`) are shell scripts, so the sysroot needs a
    # real interpreter for the launch chain (RC7b).
    d_listing=$(http_get "$MIRROR/$DASH_POOL/") \
        || die "cannot list $MIRROR/$DASH_POOL/"
    dash_deb=$(deb_candidates "$d_listing" dash i386 | newest_deb)
    [ -n "$dash_deb" ] || die "no dash_*_i386.deb in $DASH_POOL"
    info "dash: newest $dash_deb"

    # --- download everything before touching the tree --------------------
    w_entries=
    for w_deb in $libc6_deb ${libc6i686_deb:-} $libwine_deb $dash_deb $w_pkgs; do
        case $w_deb in
        libc6-*) w_pool=$GLIBC_POOL ;;
        libc6_*) w_pool=$GLIBC_POOL ;;
        dash_*)  w_pool=$DASH_POOL ;;
        *)       w_pool=$WINE_POOL ;;
        esac
        fetch_deb "$MIRROR/$w_pool/$w_deb" "$w_deb"
        w_entries="$w_entries $w_pool:$w_deb"
    done

    # --- fresh extraction, then fixups + stamp ---------------------------
    rm -rf "$sysroot"
    mkdir -p "$sysroot"
    for w_deb in $libc6_deb ${libc6i686_deb:-} $libwine_deb $dash_deb $w_pkgs; do
        info "extracting $w_deb"
        extract_deb "$cache_dir/$w_deb"
    done

    # usrmerge compat: lib -> usr/lib and bin -> usr/bin like a real
    # Debian system.
    if [ ! -e "$sysroot/lib" ] && [ ! -L "$sysroot/lib" ]; then
        ln -s usr/lib "$sysroot/lib"
        info "created usrmerge compat symlink lib -> usr/lib"
    fi
    if [ ! -e "$sysroot/bin" ] && [ ! -L "$sysroot/bin" ]; then
        ln -s usr/bin "$sysroot/bin"
        info "created usrmerge compat symlink bin -> usr/bin"
    fi

    # /bin/sh -> dash (Debian's base alternatives choice).
    ln -sfn dash "$sysroot/usr/bin/sh"
    info "alternatives replica: usr/bin/sh -> dash"

    # update-alternatives replicas (maintainer scripts do not run on
    # plain extraction; libwine postinst installs these slave links at
    # priority 70 pointing at the -stable wrappers).
    for w_alt in wine:wine-stable wine32:wine32-stable wineboot:wineboot-stable; do
        w_link=${w_alt%%:*}
        w_target=${w_alt#*:}
        ln -sfn "$w_target" "$sysroot/usr/bin/$w_link"
        info "alternatives replica: usr/bin/$w_link -> $w_target"
    done

    # shellcheck disable=SC2086
    write_stamp $w_entries
}

check_one() {  # <description> <path> [executable]
    v_path=$sysroot/$2
    if [ ! -e "$v_path" ] || { [ "$#" -ge 3 ] && [ ! -x "$v_path" ]; }; then
        info "MISSING $1: $2"
        v_fail=$((v_fail + 1))
        return 0
    fi
    info "ok $1: $2"
}

do_verify() {
    v_fail=0
    # loader entry point: usr/bin/wine (or the wine-stable it wraps)
    if [ -x "$sysroot/usr/bin/wine" ]; then
        info "ok loader: usr/bin/wine (executable)"
    elif [ -x "$sysroot/usr/bin/wine-stable" ]; then
        info "ok loader: usr/bin/wine-stable (executable)"
    else
        info "MISSING loader: usr/bin/wine (or wine-stable) not executable"
        v_fail=$((v_fail + 1))
    fi
    # wine32 shared objects + PE builtins
    check_one "wine32 loader" usr/lib/i386-linux-gnu/wine/wine x
    check_one "wine32 wineserver" usr/lib/i386-linux-gnu/wine/wineserver x
    check_one "wine32 unix ntdll" usr/lib/i386-linux-gnu/wine/i386-unix/ntdll.so
    check_one "wine32 PE ntdll" usr/lib/i386-linux-gnu/wine/i386-windows/ntdll.dll
    check_one "wine32 PE kernel32" usr/lib/i386-linux-gnu/wine/i386-windows/kernel32.dll
    check_one "wine32 PE cmd" usr/lib/i386-linux-gnu/wine/i386-windows/cmd.exe
    check_one "wine.inf" usr/share/wine/wine.inf
    check_one "wine fonts" usr/share/wine/fonts/courer.fon
    # glibc the wine loader needs
    check_one "glibc loader" lib/ld-linux.so.2
    check_one "glibc libc" usr/lib/i386-linux-gnu/libc.so.6
    check_one "dash shell" usr/bin/dash exec
    check_one "/bin/sh -> dash" bin/sh
    if [ "$v_fail" -ne 0 ]; then
        die "verify failed: $v_fail check(s) missing (run without --verify to (re-)fetch)"
    fi
    echo "WINE32-SYSROOT-OK"
}

case ${1:-} in
'')    do_fetch ;;
--verify) do_verify ;;
--force)
    rm -f "$stamp"
    do_fetch
    ;;
*)
    die "usage: $prog [--verify|--force]"
    ;;
esac
