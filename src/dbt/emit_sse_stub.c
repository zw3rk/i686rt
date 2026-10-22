/* Coordinator v1 stub: SSE declines to the D2 interpreter (L5a owns
 * the real emitters). */
#include "dbt/emit.h"

int i686_emit_sse(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
