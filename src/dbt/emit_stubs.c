/* Coordinator-owned v1 stubs: the lane modules replace these bodies.
 * translate.c links against them from day one so the DBT engine path
 * compiles and runs (every op falls back to interpret-one, D2). */
#include "dbt/emit.h"

int i686_emit_alu(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e; (void)insn; return -1;
}
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
void i686_emit_begin(i686_emit_ctx_t *e, i686_ctx_t *ctx, uint8_t *code,
                     size_t cap, uint32_t guest_eip)
{
    memset(e, 0, sizeof(*e));
    a64_buf_init(&e->buf, (uint32_t *)(void *)code, cap / 4U);
    e->ctx = ctx;
    e->guest_eip = guest_eip;
    e->block_open = true;
}
uint8_t *i686_emit_finish(i686_emit_ctx_t *e, size_t *out_len)
{
    *out_len = e->buf.count * 4U;
    e->block_open = false;
    return (uint8_t *)(void *)e->buf.words;
}
void i686_emit_exit(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                    uint32_t dest)
{
    (void)e; (void)reason; (void)arg; (void)dest;
    e->block_open = false;
}
void i686_emit_ea(i686_emit_ctx_t *e, const x86_insn_t *insn, int add_seg)
{
    (void)e; (void)insn; (void)add_seg;
}
