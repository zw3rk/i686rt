#!/usr/bin/env python3
"""Fetch a Debian i386 glibc sysroot for i686rt (Phase 4, L4b; SPEC 3.8(3)).

Scrapes the Debian main-mirror glibc pool directory
(https://deb.debian.org/debian/pool/main/g/glibc/) for the newest
``libc6_<ver>_i386.deb`` (the underscore right after ``libc6`` excludes the
``libc6-amd64``/``libc6-i686``/``libc6-x32`` variant packages) and — when the
suite still ships it — ``libc6-i686_<ver>_i386.deb`` (which carries
/lib/i686/cmov/libc.so.6).  The base libc6 deb already provides the essential
artifacts: the dynamic loader ``ld-linux.so.2`` and ``libc.so.6``.

Each .deb is an ``ar`` archive; the ``data.tar.*`` member is extracted with a
minimal in-script ``ar`` reader plus the stdlib ``tarfile`` module:

  * ``data.tar.xz``  -> stdlib ``lzma`` via ``tarfile`` mode ``r:xz`` (primary;
                        current Debian glibc i386 debs ship xz)
  * ``data.tar.gz``  -> stdlib ``gzip`` via ``tarfile`` mode ``r:gz``
  * ``data.tar.zst`` -> stdlib ``compression.zstd`` when running on Python
                        >= 3.14 (PEP 784); otherwise falls back to
                        ``docker run --platform linux/386 alpine`` +
                        ``apk add dpkg && dpkg-deb -x`` as the extraction
                        engine (documented fallback: zstd is not in the
                        stdlib before 3.14)

Files land under ``_sysroot/debian-i386/`` with package paths preserved
(lib/, usr/lib/, ...).  Because Debian i386 is usr-merged, current libc6 debs
place the real files in ``usr/lib/i386-linux-gnu/`` and a relative symlink at
``usr/lib/ld-linux.so.2``; the script adds the usrmerge compat symlink
``lib -> usr/lib`` at the sysroot root (exactly what a Debian system has)
when the deb did not populate a real ``lib/`` tree, so both
``lib/ld-linux.so.2`` and ``lib/i386-linux-gnu/libc.so.6`` resolve.

Validation (no external ``file`` dependency): ``ld-linux.so.2`` and
``libc.so.6`` are opened and their ELF headers parsed — magic ``\\x7fELF``,
EI_CLASS == 1 (ELFCLASS32), EI_DATA == 1 (little-endian) and
e_machine == 3 (EM_386) — before ``_sysroot/debian-i386/.stamp`` is written.

The stamp is JSON (package URLs + sha256s, key-lib file list with sha256s).
A rerun whose stamp still matches the files on disk skips all work
(idempotent); ``--force`` re-fetches and re-extracts from scratch.

Usage:
    python3 tools/setup_sysroot.py [--force]

stdlib only (urllib for downloads; lzma/tarfile for extraction).
"""

# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

import argparse
import functools
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

MIRROR = "https://deb.debian.org/debian"
POOL_PATH = "pool/main/g/glibc/"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSROOT = os.path.join(REPO_ROOT, "_sysroot", "debian-i386")
CACHE_DIR = os.path.join(REPO_ROOT, "_sysroot", "pool")
STAMP = os.path.join(SYSROOT, ".stamp")
UA = "i686rt-setup-sysroot/1.0"

# Logical name -> candidate package paths (first existing wins).
KEY_LIBS = [
    ("ld-linux.so.2",
     ["lib/ld-linux.so.2", "usr/lib/ld-linux.so.2",
      "lib/i386-linux-gnu/ld-linux.so.2", "usr/lib/i386-linux-gnu/ld-linux.so.2"]),
    ("libc.so.6",
     ["lib/i386-linux-gnu/libc.so.6", "usr/lib/i386-linux-gnu/libc.so.6",
      "lib/i686/cmov/libc.so.6", "lib/libc.so.6", "usr/lib/libc.so.6"]),
]


def die(msg):
    sys.stderr.write("setup_sysroot: error: %s\n" % msg)
    sys.exit(1)


def info(msg):
    print("setup_sysroot: %s" % msg)


# --------------------------------------------------------------------------
# Debian version comparison (dpkg verrevcmp port; needed to pick "newest").
# --------------------------------------------------------------------------

def _order(ch):
    """Sort weight of one character; None is the end-of-string sentinel."""
    if ch is None:
        return 0
    if ch.isdigit():
        return 0
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _verrevcmp(a, b):
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        first_diff = 0
        while ((ia < len(a) and not a[ia].isdigit())
               or (ib < len(b) and not b[ib].isdigit())):
            ac = _order(a[ia] if ia < len(a) else None)
            bc = _order(b[ib] if ib < len(b) else None)
            if ac != bc:
                return -1 if ac < bc else 1
            if ia < len(a):
                ia += 1
            if ib < len(b):
                ib += 1
        while ia < len(a) and a[ia] == "0":
            ia += 1
        while ib < len(b) and b[ib] == "0":
            ib += 1
        while (ia < len(a) and ib < len(b)
               and a[ia].isdigit() and b[ib].isdigit()):
            if first_diff == 0:
                first_diff = ord(a[ia]) - ord(b[ib])
            ia += 1
            ib += 1
        if ia < len(a) and a[ia].isdigit():
            return 1
        if ib < len(b) and b[ib].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _split_version(v):
    epoch = 0
    head, sep, rest = v.partition(":")
    if sep and head.isdigit():
        epoch = int(head)
        v = rest
    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    return epoch, upstream, revision


def deb_version_cmp(v1, v2):
    e1, u1, r1 = _split_version(v1)
    e2, u2, r2 = _split_version(v2)
    if e1 != e2:
        return -1 if e1 < e2 else 1
    c = _verrevcmp(u1, u2)
    if c:
        return c
    return _verrevcmp(r1, r2)


# --------------------------------------------------------------------------
# Network + pool scraping.
# --------------------------------------------------------------------------

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def scrape_pool():
    """Return {pkg-name: (version, filename)} for libc6 / libc6-i686 i386."""
    html = http_get(MIRROR + "/" + POOL_PATH).decode("utf-8", "replace")
    found = {}
    for href in re.findall(r'href="([^"]+)"', html):
        m = re.match(r"^libc6-i686_(.+)_i386\.deb$", href)
        if m:
            found["libc6-i686"] = (m.group(1), href)
            continue
        m = re.match(r"^libc6_(.+)_i386\.deb$", href)
        if m:  # "libc6_" with the underscore: excludes libc6-amd64/-i686/-x32
            found["libc6"] = (m.group(1), href)
    return found


def download(filename):
    """Fetch a pool file into CACHE_DIR; reuse when the sha256 matches."""
    url = MIRROR + "/" + POOL_PATH + filename
    dest = os.path.join(CACHE_DIR, filename)
    if os.path.exists(dest):
        info("cached %s" % filename)
        return url, dest
    tmp = dest + ".part"
    with open(tmp, "wb") as f:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            shutil.copyfileobj(r, f, 1 << 16)
    os.replace(tmp, dest)
    info("downloaded %s (%d bytes)" % (filename, os.path.getsize(dest)))
    return url, dest


# --------------------------------------------------------------------------
# .deb extraction: minimal ar reader + stdlib tarfile.
# --------------------------------------------------------------------------

def ar_member(deb_bytes, wanted_prefix):
    """Return the raw bytes of the first ar member named wanted_prefix*."""
    if deb_bytes[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive (bad magic)")
    off = 8
    while off + 60 <= len(deb_bytes):
        hdr = deb_bytes[off:off + 60]
        name = hdr[0:16].decode("ascii", "replace").rstrip(" \n/")
        try:
            size = int(hdr[48:58].decode("ascii").strip() or "0")
        except ValueError:
            raise ValueError("corrupt ar header size field")
        body = deb_bytes[off + 60:off + 60 + size]
        if len(body) != size:
            raise ValueError("truncated ar member %r" % name)
        if name.startswith(wanted_prefix):
            return name, body
        off += 60 + size
        if (60 + size) % 2:  # members are 2-byte aligned
            off += 1
    raise ValueError("no %r member in .deb" % wanted_prefix)


def _tar_open(deb_path, member_name, body):
    """Open the data.tar.* member with tarfile, decompressing as needed."""
    if member_name.endswith(".tar.xz"):
        return tarfile.open(fileobj=io.BytesIO(body), mode="r:xz")
    if member_name.endswith(".tar.gz"):
        return tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")
    if member_name.endswith(".tar.zst"):
        # Python >= 3.14 ships compression.zstd (PEP 784).
        try:
            from compression import zstd  # type: ignore
        except ImportError:
            zstd = None
        if zstd is not None:
            dec = zstd.ZstdDecompressor()
            try:
                reader = dec.decompress_reader(io.BytesIO(body))
                return tarfile.open(fileobj=reader, mode="r:")
            except AttributeError:
                pass  # different PEP 784 shape -> docker fallback below
        return _tar_open_via_docker(deb_path)
    raise ValueError("unsupported data.tar compression: %s" % member_name)


def _tar_open_via_docker(deb_path):
    """zstd fallback: docker linux/386 alpine + dpkg-deb extracts the .deb
    directly into SYSROOT (zstd is not in the stdlib before Python 3.14)."""
    info("%s: data.tar.zst and no stdlib zstd -> docker dpkg-deb fallback"
         % os.path.basename(deb_path))
    cmd = ["docker", "run", "--rm", "--platform", "linux/386",
           "-v", CACHE_DIR + ":/deb:ro", "-v", SYSROOT + ":/out",
           "alpine", "sh", "-c",
           "apk add --no-cache dpkg >/dev/null && "
           "dpkg-deb -x /deb/%s /out" % os.path.basename(deb_path)]
    try:
        subprocess.run(cmd, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        raise ValueError("docker dpkg-deb fallback failed for %s: %s"
                         % (deb_path, e))
    return None  # extraction already done; caller skips tarfile walk


def _safe_dest(rel):
    """Sanitize a package path; returns a filesystem path under SYSROOT."""
    rel = posixpath.normpath(rel.lstrip("./"))
    if rel == ".":  # the archive root entry itself
        return ""
    if not rel or posixpath.isabs(rel):
        return None
    parts = rel.split("/")
    if any(p in ("", "..") for p in parts):
        return None
    dest = os.path.join(SYSROOT, *parts)
    real = os.path.realpath(dest)
    if real != os.path.realpath(SYSROOT) and not real.startswith(
            os.path.realpath(SYSROOT) + os.sep):
        return None
    return dest


def extract_deb(deb_path):
    """Extract one .deb into SYSROOT.  Returns number of files written."""
    with open(deb_path, "rb") as f:
        deb = f.read()
    name, body = ar_member(deb, "data.tar.")
    tf = _tar_open(deb_path, name, body)
    if tf is None:  # docker path extracted already
        return -1
    count = 0
    for m in tf:
        dest = _safe_dest(m.name)
        if dest is None:
            info("skipping unsafe path %r" % m.name)
            continue
        if not dest:  # archive root
            continue
        if m.isdir():
            os.makedirs(dest, exist_ok=True)
        elif m.issym():
            if os.path.lexists(dest):
                os.remove(dest)
            os.symlink(m.linkname, dest)
            count += 1
        elif m.isfile():
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(dest, "wb") as out:
                shutil.copyfileobj(src, out, 1 << 16)
            os.chmod(dest, m.mode & 0o7777)
            count += 1
        elif m.islnk():
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            target = _safe_dest(m.linkname)
            if target and os.path.exists(target):
                if os.path.lexists(dest):
                    os.remove(dest)
                os.link(target, dest)
                count += 1
        else:
            info("skipping special member %r (type %r)" % (m.name, m.type))
    tf.close()
    return count


# --------------------------------------------------------------------------
# Validation + stamp.
# --------------------------------------------------------------------------

def resolve_in_sysroot(rel, max_hops=20):
    """Resolve a (possibly symlinked) sysroot-relative path inside SYSROOT.
    Absolute symlink targets are treated as sysroot-rooted (chroot-style)."""
    cur = rel
    for _ in range(max_hops):
        path = os.path.join(SYSROOT, cur)
        if not os.path.islink(path):
            return cur if os.path.exists(path) else None
        target = os.readlink(path)
        if os.path.isabs(target):
            cur = posixpath.normpath(target.lstrip("/"))
        else:
            cur = posixpath.normpath(
                posixpath.join(posixpath.dirname(cur), target))
    return None


def validate_elf32_i386(path):
    with open(path, "rb") as f:
        h = f.read(20)
    if len(h) < 20:
        raise ValueError("short ELF header (%d bytes)" % len(h))
    if h[:4] != b"\x7fELF":
        raise ValueError("bad ELF magic")
    if h[4] != 1:
        raise ValueError("not ELFCLASS32 (EI_CLASS=%d)" % h[4])
    if h[5] != 1:
        raise ValueError("not little-endian (EI_DATA=%d)" % h[5])
    machine = struct.unpack("<H", h[18:20])[0]
    if machine != 3:
        raise ValueError("not EM_386 (e_machine=%d)" % machine)
    return True


def find_key_libs():
    """Locate the key libraries; returns [(logical, relpath)] or fails."""
    out = []
    for logical, candidates in KEY_LIBS:
        hit = None
        for cand in candidates:
            rel = resolve_in_sysroot(cand)
            if rel is not None:
                hit = (logical, cand, rel)
                break
        if hit is None:
            die("key library %s not found under %s (looked for %s)"
                % (logical, SYSROOT, ", ".join(candidates)))
        logical, cand, rel = hit
        try:
            validate_elf32_i386(os.path.join(SYSROOT, rel))
        except ValueError as e:
            die("%s (%s): %s" % (logical, rel, e))
        info("%s -> %s (ELF32/EM_386 ok)" % (logical, rel))
        out.append({"name": logical, "path": rel,
                    "sha256": sha256_file(os.path.join(SYSROOT, rel))})
    return out


def stamp_matches(keylibs):
    if not os.path.exists(STAMP):
        return False
    try:
        with open(STAMP) as f:
            stamp = json.load(f)
        for entry in stamp.get("keylibs", []):
            path = os.path.join(SYSROOT, entry["path"])
            if not os.path.exists(path) or sha256_file(path) != entry["sha256"]:
                return False
    except (ValueError, KeyError, OSError):
        return False
    return keylibs is None or stamp.get("keylibs") == keylibs


def main():
    ap = argparse.ArgumentParser(
        description="Fetch the Debian i386 glibc sysroot for i686rt.")
    ap.add_argument("--force", action="store_true",
                    help="re-fetch and re-extract even if the stamp matches")
    args = ap.parse_args()

    if not args.force and stamp_matches(None):
        keylibs = find_key_libs()
        info("stamp matches; sysroot up to date (%s)" % STAMP)
        for entry in keylibs:
            info("  %s -> %s" % (entry["name"], entry["path"]))
        print("L4B OK")
        return

    os.makedirs(CACHE_DIR, exist_ok=True)

    pool = scrape_pool()
    if "libc6" not in pool:
        die("no libc6_*_i386.deb found in %s%s" % (MIRROR, POOL_PATH))
    ver, fname = pool["libc6"]
    info("libc6: newest pool version %s (%s)" % (ver, fname))

    wanted = [("libc6", ver, fname)]
    if "libc6-i686" in pool:
        ver686, fname686 = pool["libc6-i686"]
        info("libc6-i686: newest pool version %s (%s)" % (ver686, fname686))
        wanted.append(("libc6-i686", ver686, fname686))
    else:
        info("libc6-i686: not shipped for this suite (modern Debian i386 "
             "glibc is i686-optimized in libc6 itself); skipping")

    # Download first so nothing is destroyed unless we have the payloads.
    fetched = []
    for name, ver, fname in wanted:
        url, dest = download(fname)
        fetched.append((name, ver, url, dest))

    # Fresh extraction into a clean sysroot, then stamp.
    if os.path.exists(SYSROOT):
        shutil.rmtree(SYSROOT)
    os.makedirs(SYSROOT)
    packages = []
    for name, ver, url, dest in fetched:
        count = extract_deb(dest)
        packages.append({"name": name, "version": ver, "url": url,
                         "sha256": sha256_file(dest),
                         "size": os.path.getsize(dest)})
        info("extracted %s_%s (%s)"
             % (name, ver, "dpkg-deb" if count < 0 else "%d entries" % count))

    # Debian usrmerge compat: current debs keep everything under usr/lib;
    # provide lib -> usr/lib like a real system when no real lib/ tree came
    # out of the packages, so /lib/ld-linux.so.2 and /lib/i386-linux-gnu/...
    # both resolve.
    libdir = os.path.join(SYSROOT, "lib")
    if not os.path.lexists(libdir):
        os.symlink("usr/lib", libdir)
        info("created usrmerge compat symlink lib -> usr/lib")

    keylibs = find_key_libs()

    stamp = {
        "tool": "tools/setup_sysroot.py",
        "mirror": MIRROR,
        "pool": POOL_PATH,
        "packages": packages,
        "keylibs": keylibs,
    }
    with open(STAMP, "w") as f:
        json.dump(stamp, f, indent=2, sort_keys=True)
        f.write("\n")
    info("stamp written: %s" % STAMP)
    print("L4B OK")


if __name__ == "__main__":
    main()
