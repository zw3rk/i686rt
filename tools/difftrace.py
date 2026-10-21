#!/usr/bin/env python3
"""tools/difftrace.py -- compare two i686rt I686RT_TRACE streams (L3d).

Reads the two trace files captured by tools/difftest.sh (the same guest
run under I686RT_ENGINE=interp and I686RT_ENGINE=dbt) and compares the
event sequences extracted from them:

  T lines: "T <eip> op=<op> len=<len> b=<bytes> esp=<esp>"  -> (eip, op, len)
  S lines: "S <nr>(<args>) -> <rv>" or "S <nr> -> <rv>"     -> (nr, rv)

The T comparison tuple deliberately keeps (eip, op, len) and excludes
esp: the two engine runs carry different I686RT_ENGINE environment
strings, so the initial guest stack (hence esp) can shift by
environment-size while execution itself is identical; the opcode bytes
are a pure function of eip.  Interleaved diagnostics (the "i686rt: ..."
lines and the engine-fallback warning) do not start with "T " or "S "
and are ignored.  A line that does start a T/S event but parses as
neither the full format nor a single bare token is a parse error.

On divergence the FIRST mismatching event is reported with up to three
lines of preceding context from each side, followed by a summary (event
counts and matched prefix length).

Exit status: 0 traces identical, 1 divergence reported, 2 parse error
(unreadable file or malformed trace line).

Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
SPDX-License-Identifier: Apache-2.0
"""

import argparse
import re
import sys

# Full interpreter format (src/interp/interp.c):
#   "T %08x op=%u len=%u b=%02x.. esp=%08x"
T_FULL = re.compile(
    r"^T ([0-9a-fA-F]{1,8}) op=(\d+) len=(\d+)"
    r"(?: b=([0-9a-fA-F]*) esp=([0-9a-fA-F]{1,8}))?$"
)
# Syscall lines: "S <nr> -> <rv>", "S <nr>(<a1>) -> <rv>",
# "S <nr>(<a1>,<a2>,<a3>) -> <rv>" (args are decimal or hex, unused here).
S_FULL = re.compile(r"^S (-?\d+)(?:\([^)]*\))? -> (-?\d+)$")
# Bare-token fallbacks so hand-written or deliberately corrupted traces
# still compare event-by-event ("T 1" vs "T 9" must diverge, not parse-error).
T_SHORT = re.compile(r"^T (\S+)$")
S_SHORT = re.compile(r"^S (\S+)$")

CONTEXT = 3  # preceding events shown from each side at a divergence


class Event:
    """One trace event: kind T/S, comparison key, source line, raw text."""

    __slots__ = ("kind", "key", "lineno", "raw")

    def __init__(self, kind, key, lineno, raw):
        self.kind = kind
        self.key = key
        self.lineno = lineno
        self.raw = raw


def parse_file(path):
    """Parse one trace file into a list of Event; raises ValueError on a
    malformed T/S line or an unreadable file."""
    events = []
    try:
        stream = open(path, "r", encoding="utf-8", errors="surrogateescape")
    except OSError as exc:
        raise ValueError("cannot open %s: %s" % (path, exc)) from None
    with stream:
        for lineno, line in enumerate(stream, start=1):
            raw = line.rstrip("\r\n")
            if raw.startswith("T "):
                match = T_FULL.match(raw)
                if match is not None:
                    key = (int(match.group(1), 16), int(match.group(2)),
                           int(match.group(3)))
                else:
                    match = T_SHORT.match(raw)
                    if match is None:
                        raise ValueError(
                            "%s:%d: malformed T line: %r" % (path, lineno, raw))
                    key = (match.group(1),)
                events.append(Event("T", key, lineno, raw))
            elif raw.startswith("S "):
                match = S_FULL.match(raw)
                if match is not None:
                    key = (int(match.group(1)), int(match.group(2)))
                else:
                    match = S_SHORT.match(raw)
                    if match is None:
                        raise ValueError(
                            "%s:%d: malformed S line: %r" % (path, lineno, raw))
                    key = (match.group(1),)
                events.append(Event("S", key, lineno, raw))
            # anything else: interleaved diagnostic, ignore
    return events


def counts(events):
    """(T count, S count) for a parsed event list."""
    t = sum(1 for event in events if event.kind == "T")
    return t, len(events) - t


def describe(path, events, index):
    """Human-readable location of event `index` ('end of trace' if past
    the last event)."""
    if index < len(events):
        event = events[index]
        return "%s:%d: %s" % (path, event.lineno, event.raw)
    return "%s: <end of trace>" % path


def print_context(path, events, index):
    """Up to CONTEXT preceding events plus the event at `index` (or the
    end-of-trace marker), indented under a header line."""
    print("  --- %s (last %d events before divergence) ---"
          % (path, min(CONTEXT, index)))
    for i in range(max(0, index - CONTEXT), min(index + 1, len(events))):
        event = events[i]
        print("  %s event %-6d %s:%d: %s"
              % (">" if i == index else " ", i, path, event.lineno, event.raw))
    if index >= len(events):
        print("  > event %-6d %s: <end of trace>" % (index, path))


def compare_native(a_events, b_events, fa, fb):
    """DBT-native mode: one side has no T events (native execution, no
    per-insn trace). Compare the syscall (S) sequences only."""
    a_s = [e for e in a_events if e.kind == 'S']
    b_s = [e for e in b_events if e.kind == 'S']
    n = min(len(a_s), len(b_s))
    for i in range(n):
        if a_s[i].key != b_s[i].key:
            print(f"DIFFTRACE: DIVERGENCE (native syscall compare) at syscall {i}")
            print(f"  a: {a_s[i].raw}   b: {b_s[i].raw}")
            return 1
    if len(a_s) != len(b_s):
        print(f"DIFFTRACE: DIVERGENCE syscall count a={len(a_s)} b={len(b_s)}")
        return 1
    print(f"DIFFTRACE: EQUAL (DBT-native: syscall traces only) "
          f"events: {len(a_s)}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare two i686rt I686RT_TRACE streams and report "
                    "the first divergence (exit 0 equal, 1 divergence, "
                    "2 parse error).")
    parser.add_argument("file_a", help="first trace file (interp side)")
    parser.add_argument("file_b", help="second trace file (dbt side)")
    args = parser.parse_args(argv)

    try:
        events_a = parse_file(args.file_a)
        events_b = parse_file(args.file_b)
    except ValueError as exc:
        print("difftrace: parse error: %s" % exc, file=sys.stderr)
        return 2

    ta, sa = counts(events_a)
    tb, sb = counts(events_b)

    # DBT-native mode: one side ran natively (no per-insn trace); the
    # meaningful differential is the syscall sequence.
    if (ta == 0) != (tb == 0):
        return compare_native(events_a, events_b, args.file_a, args.file_b)

    prefix = 0
    limit = min(len(events_a), len(events_b))
    while prefix < limit and events_a[prefix].key == events_b[prefix].key:
        prefix += 1

    if prefix == len(events_a) == len(events_b):
        print("DIFFTRACE: EQUAL  events: %d (T=%d, S=%d)  a: %s  b: %s"
              % (len(events_a), ta, sa, args.file_a, args.file_b))
        return 0

    print("DIFFTRACE: DIVERGENCE at event %d (matched prefix: %d events)"
          % (prefix, prefix))
    print("  a: %s" % describe(args.file_a, events_a, prefix))
    print("  b: %s" % describe(args.file_b, events_b, prefix))
    print_context(args.file_a, events_a, prefix)
    print_context(args.file_b, events_b, prefix)
    print("DIFFTRACE: summary: a: %d events (T=%d, S=%d)  b: %d events "
          "(T=%d, S=%d)  matched-prefix: %d"
          % (len(events_a), ta, sa, len(events_b), tb, sb, prefix))
    return 1


if __name__ == "__main__":
    sys.exit(main())
