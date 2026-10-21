/* Coordinator v1 stub: LOCK ops decline (D2 single-threaded fallback).
 * L4c replaces this file's body. */
#include "dbt/emit.h"

int i686_emit_atomic(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
