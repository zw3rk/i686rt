# L-C12 — quarantine-stash dispositions (2026-10-23)

Card L-C12, task 1. Lane: `lane/fix-c12`, worktree `../i686rt-c12`,
master base `ba4e54f` ("Post-C2 coordinator fix batch").  Read-only over
the stashes; this document and `fix-c12-port.patch` are the deliverables.
Stash drops remain a coordinator action.

## What the two stashes are

    stash@{0}: On master: quarantine-2: lane leak in dbt/interp/sse/x87_80/insn_tab   (2026-10-22 12:24)
    stash@{1}: On master: quarantine: lane leak comment edits in dbt (L5?)            (2026-10-22 12:11)

Both were created on master at base `c3be9e8` (the DEFECTS.md audit base,
"Phase 3: record audit D3 fix").  `stash@{1}` is a strict subset of
`stash@{0}`: the three shared files carry identical blob pairs
(`97f92a6..08d084f`, `24e625d..f3d1ea8`, `d86e670..14a4a70`), so the
quarantine-2 stash simply re-collected the earlier quarantine plus four
more files.

The content is the DEFECTS.md audit's D4–D12 comment-correction set.
Commit `2541928` ("Apply DEFECTS.md audit D1-D6 comment corrections",
2026-10-22 21:02, after the stashes were taken) applied exactly this
edit set — for `insn_tab.h` it produced the identical post-image blob
`a7fe1ce` that both stashes carry.

Why parts of it are missing from master again: `1b94c8c` ("Merge
lane/5-l5c", parents `2541928` + `05a3120`) resolved `insn_tab.h` by
taking the lane side wholesale (blob `582ab46`, cut before the audit
fix), silently reverting the D9–D12 comment corrections while the
untouched-by-L5c files (emit.h, emit_alu.c, emit_atomic.c, sse.h,
x87_80.h) kept the audit text.  Current master `insn_tab.h` is blob
`4d6a32c` — old comments for D9–D12, everything else unchanged.

## Disposition table

Classes: (a) superseded — same or better text already on master;
(b) still-valid — correction absent on master, matches a DEFECTS.md
D-entry, and verified factually correct against current master code;
(c) obsolete.

| Stash | File | Hunk summary | Class | Evidence |
|---|---|---|---|---|
| @{0},@{1} | src/dbt/emit.h | `i686_emit_ea` doc: 32-bit offset in w21, UXTW wrap, no xG, clobbers w21/w22 (D4) | (a) superseded | Master emit.h:79-82 verbatim; landed in `2541928` |
| @{0},@{1} | src/dbt/emit_alu.c | LDAR comment: `i686_emit_begin` leaves `e->tso` false, arm not emitted (D5) | (a) superseded | Master emit_alu.c:134-136 verbatim; landed in `2541928` |
| @{0},@{1} | src/dbt/emit_atomic.c | Header: AL variants acquire+release, `e->tso` not read (D6) | (a) superseded | Master emit_atomic.c:80-81 verbatim; landed in `2541928` |
| @{0} | src/interp/sse.h | MXCSR RC is bits 13-14, not 14-15 (D7) | (a) superseded | Master sse.h:9 verbatim; landed in `2541928` |
| @{0} | src/interp/x87_80.h | Copyright `moritz@zw3rk.com` (was `zw3erk.com`) (D8) | (a) superseded | Master x87_80.h:4 verbatim; landed in `2541928`; no `zw3erk` left in src/ |
| @{0} | src/x86/insn_tab.h | Preamble bullet: 0x98 stays `I686_OP_CWDE`, 66 sets `pfx_opsize`, no id rewrite (D12) | (b) still-valid | Master lines 31-34 still claim a CWDE->CBW decoder swap; `x86_decode` never assigns `I686_OP_CBW` (only the enum decl, insn_tab.h:167); `h_cwde` handles the 66 width via `pfx_opsize` (h_muldiv.c:292-293, 335). Matches D12 |
| @{0} | src/x86/insn_tab.h | INVALID-list tail: 69/6B are `IMUL_GvEvIz`/`IMUL_GvEvIb` rows, not INVALID (D9) | (b) still-valid | Master line 52 still claims "69/6B ... has no v1 contract id" while rows 0x69/0x6B (lines 350, 352) are the IMUL ids. Matches D9 |
| @{0} | src/x86/insn_tab.h | Enum note: JCC/SETcc cond in modrm_reg, CMOVcc parks it in imm (D11) | (b) still-valid | Master line 174 still says all three use modrm_reg; `x86_decode` parks CMOVcc cond in `imm` (decode.c:572, 584-585), JCC/SETcc in modrm_reg. Matches D11 |
| @{0} | src/x86/insn_tab.h | 0x98 row comment: "66 sets pfx_opsize; id stays CWDE" (D12) | (b) still-valid | Master line 397 still says "decoder swaps the id". Matches D12, same evidence as above |
| @{0} | src/x86/insn_tab.h | 0xD4/0xD5 row comments: AAM/AAD (were DAA/AAA) (D10) | (b) still-valid | Master lines 457-458 still say DAA/AAA; DAA is 0x27 (line 284), AAA is 0x37 (line 300); 0xD4=AAM, 0xD5=AAD. Matches D10 |
| @{0} | src/x86/insn_tab.h | 0F 40-4F CMOVcc rows (16): cond "carried in imm" (were "in modrm_reg") (D11) | (b) still-valid | Master 0F table still says modrm_reg on all 16 rows; decoder stores cond in `imm` (decode.c:584-585). SETcc row's modrm_reg wording is correct and untouched, as D11 prescribes. Matches D11 |

stash@{1} only adds no rows: its three hunks are the emit.h, emit_alu.c,
emit_atomic.c rows above, byte-identical (same blob pairs).

No hunk classified (c) obsolete: every edit is either already on master
or still factually correct against the current decoder.

## Counts

- stash@{0}: 11 hunks — 5 superseded, 6 still-valid, 0 obsolete.
- stash@{1}: 3 hunks — 3 superseded, 0 still-valid, 0 obsolete.
- Total 14 hunk rows, 12 distinct edits (stash@{1} repeats 3).

## Port patch

`docs/lanes/fix-c12-port.patch` carries the six still-valid insn_tab.h
corrections (D9–D12), regenerated against current master blob `4d6a32c`
(the stash's original hunks were cut against `07fe415` and no longer
apply: the preamble and INVALID list were rewritten by RC7b T1/T4b).
The replacement text is byte-identical to what `2541928` ratified; only
the D9 hunk's context lines follow the current line wrapping.

Verified read-only: `git apply --check docs/lanes/fix-c12-port.patch`
is clean on the `ba4e54f` worktree.  The patch is NOT applied — src/
edits go through the coordinator.

## Coordinator actions implied (not performed here)

1. Apply or cherry-pick the port patch (restores D9–D12 comments).
2. After review, drop both stashes: their entire content is then either
   on master (D4–D8 via `2541928`, D9–D12 via the port) or superseded.
   Until the port lands, the stashes are the only remaining copy of the
   D9–D12 corrections outside `2541928`'s object database.
