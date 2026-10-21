/* Coordinator-owned v1 stubs: the lane modules replace these bodies.
 * translate.c links against them from day one so the DBT engine path
 * compiles and runs (every op falls back to interpret-one, D2).
 *
 * Phase 3 (L3a): i686_emit_begin/finish/exit/ea now live in
 * src/dbt/emit_exit.c and i686_emit_alu in src/dbt/emit_alu.c; this file
 * keeps placeholder declinations only for the modules whose lanes have
 * not landed yet (mov L3b, branch/string L3c). */
#include "dbt/emit.h"

int i686_emit_mov(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
int i686_emit_branch(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
int i686_emit_string(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
