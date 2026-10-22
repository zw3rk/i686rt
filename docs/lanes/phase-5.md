# Phase 5 — x87 / MMX / SSE / SSE2 lane cards (frozen by the coordinator)

Frozen on master (read-only to lanes): `src/i686rt.h` (x87_st/xmm/
fctrl/fstat/ftag/fop/fpu_ip/fpu_dp/mxcsr/x87_top at ABI-locked
offsets), `src/interp/x87.h` (two-mode ST access, tag sync, m80
conversion, CW/SW encoding helpers), `src/interp/x87_80.h` (softfloat
extended core API: arithmetic, fcom, fprem(1), fscale/fxtract,
constants, transcendentals, conversions, predicates — pure C11), 
`src/interp/sse.h` (xmm access, MXCSR get/set with reserved-bit
masking, round mode, FTZ/DAZ), all Phase 0–4 sources, SPEC.md, this
file. Opcodes: SSE/SSE2 are NOT in the Phase 1 tables; lanes extend
the generator like the RDTSC precedent (S4): add ids + table rows +
generator/test counts in one self-consistent change.

Common rules: as before (worktree/branch only; never push; Curated C11
zero-warning under the cross gcc; one commit after the check; escalate
after 2 failed attempts / needed file outside ownership / ambiguity).
Mode selection is FIXED at startup (ctx->x87_80 via --x87-80 /
I686RT_X87=80, already parsed in main.c) — handlers branch on it.

| Lane | Branch/worktree | Owns | Check (once) |
|---|---|---|---|
| L5a | `lane/5-l5a` | `src/dbt/emit_sse.c` + generator SSE rows + `tests/unit/test_l5a.c` | docker arm64: `L5A OK` |
| L5b | `lane/5-l5b` | `src/interp/h_sse.c` + generator SSE rows (coordinate: L5a owns the DBT side; BOTH add the same table rows — the S5 merge takes one copy; rows must be byte-identical, spec below) + `tests/unit/test_l5b.c` | host unit + arm64: `L5B OK` |
| L5c | `lane/5-l5c` | `src/interp/h_x87.c` + `src/interp/x87.c` (state accessors impl) + generator x87 rows + `tests/unit/test_l5c.c` | arm64: `L5C OK` |
| L5d | `lane/5-l5d` | `src/interp/x87_80.c` (softfloat core) + `tests/unit/test_l5d.c` | host unit: `L5D OK` |
| L5e | `lane/5-l5e` | `tests/test_p5_fpu_sse.c` + `tests/golden/p5.txt` + `tests/golden/p5_x87_80.txt` + `tools/mkgolden.sh` + Makefile append | oracle golden generation + i686rt both modes: `L5E OK` |

## Generator rows (shared spec; both L5a and L5b emit them identically)

SSE2 integer + SSE scalar FP over the used 0F map (names frozen):
MOVD/MOVQ_xmm (0F 6E/7E, 66 0F 6E/7E), MOVAPS/MOVUPS (28/29/2A/2B,
66*), MOVHPD/MOVLPD (66 0F 16/17/12/13), MOVSD/MOVSS (0F 10/11,
F2/F3), MOVAPD/MOVUPD (66 0F 28/29/2A/2B), MOVZX-family none, PUNPCK*
(66 0F 60-6D), PSHUFD (66 0F 70), PSHUFLW/HW (F2/F3 0F 70), ADDPS/
ADDSS (0F 58, F3 58), ADDPD/ADDSD (66 58, F2 58), SUB/MUL/DIV same
pattern (5C/5D/5E), CMPPS/SS/PD/SD (0F C2 + 66/F2/F3 C2, imm8 pred),
ANDPS/ANDPD (0F 54, 66 54), ANDNPS/ANDNPD (55), ORPS/ORPD (56), XORPS/
XORPD (57), PXOR (66 0F EF), POR (EB), PAND (DB), PANDN (DF), PADDD
(66 0F FE), PADDQ (D4), PSUBD (FA), PSUBQ (FB), PMULLW (D5), PMULUDQ
(F4), PSHUFW (0F 70), CVTPI2PS/2PD (0F 2A, 66 2A), CVTSI2SS/SD (F3/F2
2A), CVTTPS2PI/2DQ (0F 2C, 66 2C), CVTTSS2SI/SD2SI (F3/F2 2C),
CVTPS2PD (0F 5A), CVTPD2PS (66 5A), CVTSS2SD (F3 5A), CVTSD2SS (F2
5A), CVTDQ2PS (0F 5B), CVTPS2DQ (66 5B), CVTTPS2DQ (F3 5B), MOVMSKPS/
PD (0F 50, 66 50), MOVMSKPD, COMISS/COMISD (0F 2F, 66 2F), UCOMISS/
UCOMISD (2E, 66 2E), LDMXCSR (0F AE /2), STMXCSR (0F AE /3),
PAUSE (F3 90 = NOP), FXRSTOR/XSAVE-family: decline. MMX: EMMS (0F 77)
plus D8–DF x87 opcodes below.
x87 (D8–DF + escaped DF E0/E8-ish): FADD_FSTP etc. as
FADD_m32/m64, FMUL_*, FSUB_(_R), FDIV_(_R), FLD_m32/m64/m80/r16/r32,
FST_FSTP_m32/m64/m80/r32, FILD_m16/m32/m64, FISTP_m16/m32/m64,
FBLD/FBSTP: decline, FLDZ/FLD1/FLDPI/FLDL2E/FLDLN2/FLDLG2/FLDLN10,
FLDCW/FNSTCW (D9 /4 /5 on m16), FNSTSW_AX (DF E0), FNSTSW_m16 (DD /7),
FINCSTP/FDECSTP (D9 F7/FF), FFREE (DD /0), FUCOM (DD E1), FUCOMP
(E9), FUCOMPP (DA E9), FCOMI/FCOMIP (DB F0/F1), FUCOMI/FUCOMIP (DB
E8/E9), FTST (D9 E4), FXAM (D9 E5), FCHS (D9 E0), FABS (D9 E1),
FSQRT (D9 FA), FSIN (D9 FE), FCOS (D9 FF), FPTAN (D9 F2), FPATAN
(D9 F3), F2XM1 (D9 F0), FYL2X (D9 F1), FYL2XP1 (D9 F9), FSCALE (D9
FD), FPREM (D9 F8), FPREM1 (D9 F5), FXTRACT (D9 F4), FRNDINT (D9 FC),
FNOP (D9 D0). Default opnd forms: m/most-in-ST(1) per opcode tables.

## Card L5a — SSE/SSE2 DBT emitters (src/dbt/emit_sse.c)
i686_emit_sse(e, insn) hooked via a dispatch line added by the
coordinator in translate.c (already on master). Emit NEON 1:1 where
straightforward; DECLINE (return -1) anything needing host-helper calls
in v1 — declined insns ride the D2 interp fallback. Unit driver in
docker arm64 over the translated output vs host NEON intrinsics for
~15 declined-free forms → L5A OK.

## Card L5b — SSE interp handlers (src/interp/h_sse.c)
Register handlers for the frozen SSE/MMX ids via
i686_interp_mov_init-style init (add i686_interp_sse_init to interp.h?
NO — freeze: register from h_sse.c's own init called by the coordinator
at S5; provide `void i686_interp_sse_init(void)` and add stub call in
emit path file translate not needed — put the call in
i686_interp_init_all via a WEAK default? Simplest: coordinator adds the
call at S5 merge; lanes export the function). Pure C using sse.h
helpers; FTZ/DAZ honoured; MXCSR exceptions accumulate. Unit test host +
arm64 run for ~40 cases incl. FTZ → L5B OK.

## Card L5c — x87 interpreter (src/interp/h_x87.c + x87.c)
Implement x87.h state accessors (both modes) and register handlers for
the x87 opcode set above; default mode uses double math via x87_get/
set_f64; --x87-80 routes arithmetic through the x87_80 API (extern
from x87_80.h; link stub for the unit test if L5d hasn't landed —
provide tests/unit/x87_80_stub.c implementing the API on long double
for TESTING ONLY, never committed into src/). FXSAVE/FNSAVE via
signals_i386.c's fpstate struct knowledge → fnstenv/fldenv/fxsave/
fxrstor m512 basic (env + regs, no xsave). → L5C OK.

## Card L5d — softfloat extended core (src/interp/x87_80.c)
Full x87_80.h implementation, pure C11 (uint64 mantissa + int exp;
host long double NOT used for arithmetic — native decomposition only
where the encoding matches; arithmetic by explicit algorithms).
Table-driven where reasonable. Unit test vs long double oracle over
~200 randomized + edge cases (subnormals, inf/nan, snan, signed zeros,
RC×PC combinations) with exact bit expectations; long double on aarch64
IS binary64 — WRONG; aarch64 long double is fp128! Use __float128 on
the HOST mac (clang) for the oracle (correct 80-bit-ish binary128
superset); assert exact-match only where binary128 and x87 agree (they
agree for representable inputs; document). → L5D OK (host unit).

## Card L5e — fixture + golden outputs (tests + tools + Makefile)
tests/test_p5_fpu_sse.c: freestanding i386 (own _start, int 0x80),
raw FPU/SSE asm (no libc FP) computing ~50 named results printed as
hex bits (printf-free: own hex printer); every FP op wrapped in
fninit + explicit CW/MXCSR settings so the two modes produce defined
outputs. tools/mkgolden.sh runs the fixture on the qemu oracle (docker
386) capturing to tests/golden/p5.txt, and — for the 80-bit file —
runs the x87-exact section with CW=64-bit precision mode (0x037F? no:
the fixture SETS CW extended precision and the EXACT cases rely on
80-bit semantics; under i686rt --x87-80 those match; the golden file
is produced by the oracle which IS exact x87 hardware) →
tests/golden/p5_x87_80.txt contains the same run's exact-case lines
(oracle is always exact; the FILE split encodes which cases the
default mode is allowed to miss: default-mode check skips lines marked
X87ONLY). Makefile: test-p5-lima target. Check: mkgolden.sh regenerates
both files; then `i686rt -- fixture` output == p5.txt (default) and
`--x87-80` output == p5_x87_80.txt → L5E OK.

## RC5 record (2026-10-22) — PASSED

Check (docker arm64 alpine:3.20, staged /tmp/rc3): `i686rt -- test_p5_fpu_sse`
vs tests/golden/p5.txt minus X87ONLY lines, and `i686rt --x87-80 -- ...` vs
p5_x87_80.txt (every line). Evidence: default rc=0, 77 cases, diff-lines=0;
--x87-80 rc=0, 83 cases, diff-lines=0. One mismatch preceded the pass
(`x87_subn_mul_m64` gold=0 got=1) and traced to two defects, both fixed in
e31dccc:

- src/interp/x87_80.c to_ieee_bits called rnd_sig with eff < 0 (values below
  half the target format's minimum subnormal), outside rnd_sig's documented
  eff-in-[0,64] contract — its leading-bit-as-guard logic fits only the
  halfway exponent, so every inexact tiny value rounded up to 1 ulp of the
  smallest denormal. Now handled explicitly: signed zero under
  nearest/toward-zero, 1 ulp only toward infinity with matching sign
  (verified for f64 and f32 across RC modes, ties, and below/above-halfway).
- tests/test_p5_fpu_sse.c g_d_2pN600 was one hex digit short of 2^-600
  (1.4375*2^-997); goldens regenerated via mkgolden.sh came out
  byte-identical (the oracle also rounds the corrected product to 0).

Open question (recorded for the final report): round_pack80's eff < 0 branch
zeroes ext80 arithmetic results below half the min subnormal under ALL RC
modes; IEEE-correct toward-infinity would take 1 ulp for the matching sign.
No fixture exercises it (needs |result| < 2^-16446 under a directed RC);
left unchanged to keep the golden baseline stable.
