/*
 * tests/unit/test_l5d_cases.c — Unit test cases for test_l5d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l5d_internal.h"

/* ---------------- golden table ----------------------------------------- */

enum {
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_SQRT, OP_FPREM, OP_FPREM1,
    OP_FSCALE, OP_FSIN, OP_FCOS, OP_FPTAN, OP_FPATAN, OP_F2XM1,
    OP_FYL2X, OP_FYL2XP1, OP_TOI32, OP_TOI64
};

typedef struct {
    const char *op;
    unsigned rc, pc;
    const char *a, *b, *out;
    unsigned flags;
    int qq, complete; /* FPREM/FPREM1 only; -1 otherwise */
} grow_t;

/* Generated offline (exact integer/Fraction math; Decimal series for the
 * transcendentals).  See tests write-up in the file header. */
static const grow_t GOLD[] = {
    {"ADD",0,64,"3FFF8000000000000000","3FBE8000000000000000","3FFF8000000000000000",32,-1,-1},
    {"ADD",0,64,"3FFF8000000000000000","3FBF8000000000000000","3FFF8000000000000000",32,-1,-1},
    {"ADD",0,64,"3FFF8000000000000001","3FBF8000000000000000","3FFF8000000000000002",32,-1,-1},
    {"MUL",0,64,"3FFF8000000000000001","3FFF8000000000000001","3FFF8000000000000002",32,-1,-1},
    {"MUL",0,64,"1FF78000000000000000","3FFF8000000000000001","1FF78000000000000001",0,-1,-1},
    {"SUB",0,64,"00018000000000000000","00000000000000000001","00007FFFFFFFFFFFFFFF",2,-1,-1},
    {"DIV",0,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAB",32,-1,-1},
    {"DIV",1,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAA",32,-1,-1},
    {"DIV",2,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAB",32,-1,-1},
    {"DIV",3,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAA",32,-1,-1},
    {"ADD",0,24,"3FFF8000080000000000","3FE18000000000000000","3FFF8000080000000000",32,-1,-1},
    {"ADD",0,53,"3FFF8000000000004000","3FC48000000000000000","3FFF8000000000004000",32,-1,-1},
    {"MUL",0,24,"00007FFFFF8000000000","3FFF8000000000000000","00007FFFFF8000000000",2,-1,-1},
    {"MUL",0,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFF8000000000000000",40,-1,-1},
    {"MUL",3,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFEFFFFFFFFFFFFFFFF",40,-1,-1},
    {"MUL",1,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFEFFFFFFFFFFFFFFFF",40,-1,-1},
    {"SQRT",0,64,"40008000000000000000","00000000000000000000","3FFFB504F333F9DE6484",32,-1,-1},
    {"SQRT",0,64,"40018000000000000000","00000000000000000000","40008000000000000000",0,-1,-1},
    {"SQRT",0,64,"40029000000000000000","00000000000000000000","4000C000000000000000",0,-1,-1},
    {"SQRT",0,64,"3FFEFFFFFFFFFFFFFFFE","00000000000000000000","3FFEFFFFFFFFFFFFFFFF",32,-1,-1},
    {"DIV",0,64,"00018000000000000000","40458000000000000000","00000000000000000000",48,-1,-1},
    {"ADD",0,64,"00004000000000000000","00004000000000000000","00018000000000000000",2,-1,-1},
    {"SUB",0,64,"00018000000000000000","00000000000000000002","00007FFFFFFFFFFFFFFE",2,-1,-1},
    {"FPREM",0,64,"4001B800000000000000","3FFF8000000000000000","3FFEC000000000000000",0,5,1},
    {"FPREM1",0,64,"4001B800000000000000","3FFF8000000000000000","BFFD8000000000000000",0,6,1},
    {"FPREM",0,64,"4001F000000000000000","40008000000000000000","3FFFC000000000000000",0,3,1},
    {"FPREM1",0,64,"4001F000000000000000","40008000000000000000","BFFE8000000000000000",0,4,1},
    {"FPREM",0,64,"3FFFA000000000000000","3FFF8000000000000000","3FFD8000000000000000",0,1,1},
    {"FPREM1",0,64,"3FFFA000000000000000","3FFF8000000000000000","3FFD8000000000000000",0,1,1},
    {"FPREM",0,64,"401D8000000080000000","3FFEC000000000000000","3FFE8000000000000000",0,5,1},
    {"FPREM1",0,64,"401D8000000080000000","3FFEC000000000000000","BFFD8000000000000000",0,6,1},
    {"FPREM",0,64,"4000E000000000000000","4000C000000000000000","3FFE8000000000000000",0,1,1},
    {"FPREM1",0,64,"4000E000000000000000","4000C000000000000000","3FFE8000000000000000",0,1,1},
    {"FPREM",0,64,"40638000000000000000","3FFFC000000000000000","40258000000000000000",0,2,0},
    {"FPREM1",0,64,"40638000000000000000","3FFFC000000000000000","40258000000000000000",0,2,0},
    {"FPREM",0,64,"4000C000000000000000","40638000000000000000","4000C000000000000000",0,0,1},
    {"FPREM1",0,64,"4000C000000000000000","40638000000000000000","4000C000000000000000",0,0,1},
    {"FSCALE",0,64,"3FFF8000000000000000","3FFFF333333333333333","40008000000000000000",0,-1,-1},
    {"FSCALE",0,64,"4000C000000000000000","C000A000000000000000","3FFEC000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFE8000000000000000","4005C800000000000000","40628000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFEC000000000000000","BFFF8000000000000000","3FFDC000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFEC000000000000000","3FFE8000000000000000","3FFEC000000000000000",0,-1,-1},
    {"FSIN",0,64,"3FFF8000000000000000","00000000000000000000","3FFED76AA47848677021",32,-1,-1},
    {"FSIN",0,64,"3FFE8000000000000000","00000000000000000000","3FFDF57743A2582F7F44",32,-1,-1},
    {"FCOS",0,64,"3FFF8000000000000000","00000000000000000000","3FFE8A51407DA8345C92",32,-1,-1},
    {"FCOS",0,64,"3FFE8000000000000000","00000000000000000000","3FFEE0A94032DBEA7CEE",32,-1,-1},
    {"FPTAN",0,64,"3FFF8000000000000000","00000000000000000000","3FFFC75922E5F71D2DC5",32,-1,-1},
    {"FPTAN",0,64,"3FFE8000000000000000","00000000000000000000","3FFE8BDA7ADF9A3A5219",32,-1,-1},
    {"FPATAN",0,64,"3FFF8000000000000000","3FFF8000000000000000","3FFEC90FDAA22168C235",32,-1,-1},
    {"FPATAN",0,64,"3FFDAAAAAAAAAAAAAAAB","3FFF8000000000000000","3FFF9FE0BB5BD42AFFEC",32,-1,-1},
    {"F2XM1",0,64,"3FFE8000000000000000","00000000000000000000","3FFDD413CCCFE7799211",32,-1,-1},
    {"F2XM1",0,64,"BFFE8000000000000000","00000000000000000000","BFFD95F619980C4336F7",32,-1,-1},
    {"F2XM1",0,64,"3FFF8000000000000000","00000000000000000000","3FFF8000000000000000",0,-1,-1},
    {"F2XM1",0,64,"BFFF8000000000000000","00000000000000000000","BFFE8000000000000000",0,-1,-1},
    {"FSIN",0,64,"40278000000000000000","00000000000000000000","BFFDCFB89138B6AEC68E",32,-1,-1},
    {"FSIN",0,64,"40138000040000000000","00000000000000000000","3FFEBE15D8EBE0492119",32,-1,-1},
    {"FSIN",0,64,"4004C900000000000000","00000000000000000000","BFF8FDA789F15A413AA5",32,-1,-1},
    {"FSIN",0,64,"4005C900000000000000","00000000000000000000","BFF9FD9FC19A387F8615",32,-1,-1},
    {"FYL2X",0,64,"4000C000000000000000","40008000000000000000","4000CAE00D1CFDEB43D0",32,-1,-1},
    {"FYL2X",0,64,"40008000000000000000","3FFE8000000000000000","3FFE8000000000000000",0,-1,-1},
    {"FYL2X",0,64,"40018000000000000000","3FFE8000000000000000","3FFF8000000000000000",0,-1,-1},
    {"FYL2XP1",0,64,"3FFE8000000000000000","4000C000000000000000","3FFFE0A02756F9C1CB6F",32,-1,-1},
    {"FYL2XP1",0,64,"BFFE8000000000000000","40008000000000000000","C0008000000000000000",0,-1,-1},
    {"TOI32",0,64,"4000A000000000000000","00000000000000000000","00000002",32,-1,-1},
    {"TOI32",2,64,"4000A000000000000000","00000000000000000000","00000003",32,-1,-1},
    {"TOI32",1,64,"4000A000000000000000","00000000000000000000","00000002",32,-1,-1},
    {"TOI32",1,64,"C000A000000000000000","00000000000000000000","FFFFFFFD",32,-1,-1},
    {"TOI32",0,64,"4000E000000000000000","00000000000000000000","00000004",32,-1,-1},
    {"TOI32",3,64,"3FFE8000000000000000","00000000000000000000","00000000",32,-1,-1},
    {"TOI32",0,64,"4001A000000000000000","00000000000000000000","00000005",0,-1,-1},
    {"TOI32",0,64,"401E8000000000000000","00000000000000000000","80000000",1,-1,-1},
    {"TOI32",0,64,"4062C9F2C9CD04674EDF","00000000000000000000","80000000",1,-1,-1},
    {"TOI64",0,64,"403D8000000000000000","00000000000000000000","4000000000000000",0,-1,-1},
    {"TOI64",0,64,"403E8000000000000001","00000000000000000000","8000000000000000",1,-1,-1},
    {"TOI64",3,64,"3FFFC000000000000000","00000000000000000000","0000000000000001",32,-1,-1},

    /* Directed-rounding deep-tiny (C4): values below/around 2^-16446 */
    {"MUL",0,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFE8000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFE8000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFEC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFEC000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFEC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFEC000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFEC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFEC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFEC000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFEC000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFFC000000000000000","00000000000000000002",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFFC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFFC000000000000000","00000000000000000002",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFFC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFFC000000000000000","80000000000000000002",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFFC000000000000000","80000000000000000002",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFFC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFFC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFD8000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFD8000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",0,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",1,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",2,64,"00000000000000000001","4001A000000000000000","00000000000000000001",50,-1,-1},
    {"DIV",3,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",0,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",1,64,"80000000000000000001","4001A000000000000000","80000000000000000001",50,-1,-1},
    {"DIV",2,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",3,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"DIV",0,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",1,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",2,64,"00000000000000000001","40638000000000000000","00000000000000000001",50,-1,-1},
    {"DIV",3,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",0,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",1,64,"80000000000000000001","40638000000000000000","80000000000000000001",50,-1,-1},
    {"DIV",2,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",3,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
};

int op_id(const char *s)
{
    if (!strcmp(s, "ADD")) return OP_ADD;
    if (!strcmp(s, "SUB")) return OP_SUB;
    if (!strcmp(s, "MUL")) return OP_MUL;
    if (!strcmp(s, "DIV")) return OP_DIV;
    if (!strcmp(s, "SQRT")) return OP_SQRT;
    if (!strcmp(s, "FPREM")) return OP_FPREM;
    if (!strcmp(s, "FPREM1")) return OP_FPREM1;
    if (!strcmp(s, "FSCALE")) return OP_FSCALE;
    if (!strcmp(s, "FSIN")) return OP_FSIN;
    if (!strcmp(s, "FCOS")) return OP_FCOS;
    if (!strcmp(s, "FPTAN")) return OP_FPTAN;
    if (!strcmp(s, "FPATAN")) return OP_FPATAN;
    if (!strcmp(s, "F2XM1")) return OP_F2XM1;
    if (!strcmp(s, "FYL2X")) return OP_FYL2X;
    if (!strcmp(s, "FYL2XP1")) return OP_FYL2XP1;
    if (!strcmp(s, "TOI32")) return OP_TOI32;
    return OP_TOI64;
}

int eq_hex(const uint8_t o[10], const char *want)
{
    uint8_t w[10];
    from_hex(w, want);
    return eq80(o, w);
}

uint32_t strtoul_hex32(const char *h)
{
    uint32_t v = 0;
    while (*h) {
        char c = *h++;
        v = (v << 4) | (uint32_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return v;
}

uint64_t strtoul_hex64(const char *h)
{
    uint64_t v = 0;
    while (*h) {
        char c = *h++;
        v = (v << 4) | (uint64_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return v;
}

int ulp1_hex(const uint8_t o[10], const char *want)
{
    uint8_t w[10];
    from_hex(w, want);
    return ulp1(o, w);
}

void run_goldens(void)
{
    size_t i;
    for (i = 0; i < sizeof GOLD / sizeof GOLD[0]; i++) {
        const grow_t *g = &GOLD[i];
        uint8_t a[10], b[10], o[10] = {0};
        uint32_t qq = 0xFFFFFFFFu;
        bool comp = true, sf = false;
        int32_t i32 = 0;
        int64_t i64 = 0;
        unsigned fl = 0;
        char eo[32];

        from_hex(a, g->a);
        from_hex(b, g->b);
        x87_80_set_prec(g->pc);
        x87_80_set_round(g->rc);
        switch (op_id(g->op)) {
        case OP_ADD: fl = x87_80_add(o, a, b); break;
        case OP_SUB: fl = x87_80_sub(o, a, b); break;
        case OP_MUL: fl = x87_80_mul(o, a, b); break;
        case OP_DIV: fl = x87_80_div(o, a, b); break;
        case OP_SQRT: fl = x87_80_sqrt(o, a); break;
        case OP_FPREM: fl = x87_80_fprem(o, a, b, &qq, &comp); break;
        case OP_FPREM1: fl = x87_80_fprem1(o, a, b, &qq, &comp); break;
        case OP_FSCALE: fl = x87_80_fscale(o, a, b); break;
        case OP_FSIN: fl = x87_80_fsin(o, a, &sf); break;
        case OP_FCOS: fl = x87_80_fcos(o, a, &sf); break;
        case OP_FPTAN: {
            uint8_t one[10];
            fl = x87_80_fptan(o, one, a, &sf);
            CHECK(eq_hex(one, "3FFF8000000000000000"),
                  "fptan(%s) one-push: got non-1.0", g->a);
            break;
        }
        case OP_FPATAN: fl = x87_80_fpatan(o, a, b); break;
        case OP_F2XM1: fl = x87_80_f2xm1(o, a); break;
        case OP_FYL2X: fl = x87_80_fyl2x(o, a, b); break;
        case OP_FYL2XP1: fl = x87_80_fyl2xp1(o, a, b); break;
        case OP_TOI32: fl = x87_80_to_i32(a, &i32, g->rc); break;
        default: fl = x87_80_to_i64(a, &i64); break;
        }
        hx80(o, eo, sizeof eo);

        if (op_id(g->op) == OP_TOI32) {
            CHECK((uint32_t)i32 == (uint32_t)strtoul_hex32(g->out) &&
                      fl == g->flags,
                  "golden %s(%s) rc=%u: got %" PRIX32 "/%u want %s/%u",
                  g->op, g->a, g->rc, (uint32_t)i32, fl, g->out, g->flags);
        } else if (op_id(g->op) == OP_TOI64) {
            CHECK((uint64_t)i64 == strtoul_hex64(g->out) && fl == g->flags,
                  "golden %s(%s): got %016" PRIX64 "/%u want %s/%u",
                  g->op, g->a, (uint64_t)i64, fl, g->out, g->flags);
        } else {
            /* transcendentals to <= 1 ulp; everything else bit-exact */
            int series = op_id(g->op) == OP_FSIN || op_id(g->op) == OP_FCOS ||
                         op_id(g->op) == OP_FPTAN || op_id(g->op) == OP_FPATAN;
            int ok = series ? ulp1_hex(o, g->out) : eq_hex(o, g->out);
            CHECK(ok && fl == g->flags,
                  "golden %s(%s,%s) rc=%u pc=%u: got %s/%u want %s/%u",
                  g->op, g->a, g->b, g->rc, g->pc, eo, fl, g->out, g->flags);
        }
        if ((op_id(g->op) == OP_FPREM || op_id(g->op) == OP_FPREM1) &&
            g->qq >= 0) {
            CHECK(qq == (uint32_t)g->qq && comp == (g->complete == 1),
                  "golden %s(%s,%s): qq=%u complete=%d want %d/%d",
                  g->op, g->a, g->b, qq, comp ? 1 : 0, g->qq, g->complete);
        }
    }
    x87_80_set_round(0u);
    x87_80_set_prec(64u);
}

/* ---------------- specials --------------------------------------------- */

void run_specials(void)
{
    uint8_t a[10], b[10], o[10], o2[10];
    unsigned fl, c3, c2, c0;
    uint32_t qq;
    bool comp, sf;
    int32_t i32;
    int64_t i64;
    double d;
    float f;

    x87_80_set_round(0u);
    x87_80_set_prec(64u);

    /* constants: canonical FLDPI/FLDL2E/FLDLN2 patterns (+ln10) */
    x87_80_pi(o);
    CHECK(eq_hex(o, "4000C90FDAA22168C235"), "pi pattern");
    x87_80_log2e(o);
    CHECK(eq_hex(o, "3FFFB8AA3B295C17F0BC"), "log2e pattern");
    x87_80_ln2(o);
    CHECK(eq_hex(o, "3FFEB17217F7D1CF79AC"), "ln2 pattern");
    x87_80_ln10(o);
    CHECK(eq_hex(o, "4000935D8DDDAAA8AC17"), "ln10 pattern");
    x87_80_zero(o);
    CHECK(eq_hex(o, "00000000000000000000") && !x87_80_sign(o), "zero");
    x87_80_one(o);
    CHECK(eq_hex(o, "3FFF8000000000000000"), "one");
    x87_80_inf(o, true);
    CHECK(eq_hex(o, "FFFF8000000000000000") && x87_80_is_inf(o), "-inf");
    x87_80_nan(o, false, false);
    CHECK(eq_hex(o, "7FFFC000000000000000") && x87_80_is_nan(o) && !x87_80_is_snan(o), "qnan");
    x87_80_nan(o, true, true);
    CHECK(eq_hex(o, "FFFF8000000000000001") && x87_80_is_snan(o), "snan");

    /* set_round/set_prec */
    CHECK(x87_80_set_round(2u) == 0u, "set_round prev");
    CHECK(x87_80_set_round(9u) == 2u, "set_round invalid keeps");
    CHECK(x87_80_set_round(0u) == 2u, "set_round back");
    CHECK(x87_80_set_prec(24u) == 64u && x87_80_set_prec(64u) == 24u,
          "set_prec");

    /* NaN propagation: first NaN wins, snan quiets + IE */
    from_hex(a, "3FFF8000000000000000"); /* 1.0 */
    from_hex(b, "7FFF8000000000000001"); /* snan payload 1 */
    fl = x87_80_add(o, b, a);
    CHECK(eq_hex(o, "7FFFC000000000000001") && fl == X_IE, "snan quieting");
    from_hex(b, "7FFFC000000000000123"); /* qnan */
    fl = x87_80_add(o, b, a);
    CHECK(eq_hex(o, "7FFFC000000000000123") && fl == 0, "qnan first operand");
    from_hex(b, "FFFF8000000000000001"); /* negative snan as b */
    fl = x87_80_mul(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000001") && fl == X_IE,
          "snan as b operand quiets");

    /* invalid arithmetic -> real indefinite */
    from_hex(a, "7FFF8000000000000000");
    from_hex(b, "FFFF8000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf + -inf");
    fl = x87_80_sub(o, a, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf - inf");
    from_hex(b, "00000000000000000000");
    fl = x87_80_mul(o, b, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "0 * inf");
    fl = x87_80_div(o, b, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "0/0");
    fl = x87_80_div(o, a, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf/inf");

    /* divide by zero */
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_div(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == X_ZE, "1/0");
    from_hex(a, "BFFF8000000000000000");
    fl = x87_80_div(o, a, b);
    CHECK(eq_hex(o, "FFFF8000000000000000") && fl == X_ZE, "-1/0");
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_div(o, b, a); /* 0 / 1 = 0 exact */
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "0/1");

    /* sqrt specials */
    from_hex(a, "BFFF8000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "sqrt(-1)");
    from_hex(a, "80000000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "sqrt(-0)");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "sqrt(inf)");

    /* signed zeros */
    from_hex(a, "00000000000000000000");
    from_hex(b, "80000000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "+0 + -0 = +0 (NE)");
    fl = x87_80_add(o, b, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "-0 + -0 = -0");
    x87_80_set_round(1u);
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "+0 + -0 = -0 (RD)");
    x87_80_set_round(0u);

    /* DE on denormal and pseudo-denormal operands */
    from_hex(a, "00008000000000000001"); /* pseudo-denormal (J=1, field 0) */
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(fl == (X_DE | X_PE), "pseudo-denormal operand DE: fl=%u", fl);
    CHECK(eq_hex(o, "3FFF8000000000000000"), "pseudo-den + 1 rounds to 1");
    from_hex(a, "00000000000000000001"); /* subnormal */
    fl = x87_80_mul(o, a, b);
    CHECK(fl == X_DE, "subnormal mul flags: %u", fl);
    CHECK(eq_hex(o, "00000000000000000001"), "subnormal * 1 exact");

    /* fcom codes */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "40008000000000000000");
    x87_80_fcom(a, b, false, &c3, &c2, &c0);
    CHECK(c3 == 0 && c2 == 0 && c0 == 1, "fcom 1<2");
    x87_80_fcom(b, a, false, &c3, &c2, &c0);
    CHECK(c3 == 0 && c2 == 0 && c0 == 0, "fcom 2>1");
    x87_80_fcom(a, a, false, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 0 && c0 == 0, "fcom 1==1");
    from_hex(a, "80000000000000000000");
    from_hex(b, "00000000000000000000");
    x87_80_fcom(a, b, false, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 0 && c0 == 0, "fcom -0 == +0");
    from_hex(b, "7FFFC000000000000000");
    x87_80_fcom(a, b, true, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 1 && c0 == 1, "fcom unordered");

    /* fprem specials */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "00000000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fprem mod 0");
    from_hex(a, "7FFF8000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fprem inf dividend");
    from_hex(a, "40008000000000000000");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "40008000000000000000") && fl == 0 && comp, "fprem inf modulus");
    from_hex(a, "80000000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0 && qq == 0 && comp,
          "fprem 0 dividend");

    /* fscale table cells (SDM Table 3-34) */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "fscale(1,+inf)");
    from_hex(b, "FFFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "fscale(1,-inf)");
    from_hex(a, "00000000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == 0, "fscale(0,-inf) indef no IE");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == 0, "fscale(inf,-inf)");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "fscale(inf,+inf)");

    /* fxtract */
    from_hex(a, "00000000000000000000");
    fl = x87_80_fxtract(o, o2, a);
    CHECK(eq_hex(o, "00000000000000000000") && eq_hex(o2, "FFFF8000000000000000") &&
              fl == X_ZE, "fxtract(0): ZE, sig 0, exp -inf");
    from_hex(a, "4002A000000000000000"); /* 10.0 */
    fl = x87_80_fxtract(o, o2, a);
    CHECK(eq_hex(o, "3FFFA000000000000000"), "fxtract sig 1.25");
    CHECK(eq_hex(o2, "4000C000000000000000"), "fxtract exp 3");

    /* fsin/fcos/fptan domain and specials (card protocol) */
    from_hex(a, "403E8000000000000000"); /* 2^63 */
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "403E8000000000000000") && fl == X_IE && !sf,
          "fsin(2^63) domain: out=a IE");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fsin(inf)");
    fl = x87_80_fcos(o, a, &sf);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fcos(inf)");
    from_hex(a, "80000000000000000000");
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "fsin(-0)");

    /* f2xm1 specials */
    from_hex(a, "80000000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "f2xm1(-0)");
    from_hex(a, "FFFF8000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "BFFF8000000000000000") && fl == 0, "f2xm1(-inf) = -1");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "f2xm1(+inf)");

    /* fyl2x specials */
    from_hex(a, "BFFF8000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fyl2x(-1,1)");
    from_hex(a, "00000000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFF8000000000000000") && fl == X_ZE, "fyl2x(0,1) = -inf ZE");
    from_hex(b, "80000000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fyl2x(0,0)");

    /* fpatan zero cases (SDM Table 3-30); a = ST(0) = x, b = ST(1) = y */
    from_hex(a, "00000000000000000000"); /* x=+0 */
    from_hex(b, "80000000000000000000"); /* y=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "fpatan(+0,-0)=-0");
    from_hex(a, "80000000000000000000"); /* x=-0, y=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(ulp1_hex(o, "C000C90FDAA22168C235") && (fl & X_PE), "fpatan(-0,-0)=-pi");
    from_hex(b, "00000000000000000000"); /* y=+0, x=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(ulp1_hex(o, "4000C90FDAA22168C235") && (fl & X_PE), "fpatan(-0,+0)=+pi");

    /* conversions */
    fl = x87_80_from_i32(o, -5);
    CHECK(eq_hex(o, "C001A000000000000000") && fl == 0, "from_i32(-5)");
    fl = x87_80_from_i64(o, INT64_MIN);
    CHECK(eq_hex(o, "C03E8000000000000000") && fl == 0, "from_i64(min)");
    d = 0.1;
    fl = x87_80_from_f64(o, d);
    CHECK(eq_hex(o, "3FFBCCCCCCCCCCCCD000") && fl == 0, "from_f64(0.1)");
    fl = x87_80_to_f64(o, &d);
    CHECK(d == 0.1 && fl == 0, "to_f64(0.1 ext) roundtrip");
    from_hex(a, "3FFF8000000000000020"); /* 1 + 2^-58 */
    fl = x87_80_to_f64(a, &d);
    CHECK(d == 1.0 && fl == X_PE, "to_f64(1+2^-58) = 1.0 PE");
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_to_i32(a, &i32, 0xFFu);
    CHECK(i32 == 1 && fl == 0, "to_i32 rc passthrough");
    from_hex(a, "7FFFC000000000000000");
    fl = x87_80_to_i32(a, &i32, 4u);
    CHECK(i32 == (-2147483647 - 1) && fl == X_IE, "to_i32(qnan) indefinite");
    from_hex(a, "C03E8000000000000000"); /* -2^63 exactly */
    fl = x87_80_to_i64(a, &i64);
    CHECK(i64 == INT64_MIN && fl == 0, "to_i64(-2^63)");
    from_hex(a, "403E8000000000000001"); /* 2^63+2 */
    fl = x87_80_to_i64(a, &i64);
    CHECK((uint64_t)i64 == 0x8000000000000000ULL && fl == X_IE,
          "to_i64(2^63+2) indefinite");
    f = 0.5f;
    fl = x87_80_from_f32(o, f);
    CHECK(eq_hex(o, "3FFE8000000000000000") && fl == 0, "from_f32(0.5)");
    fl = x87_80_to_f32(o, &f);
    CHECK(f == 0.5f && fl == 0, "to_f32 roundtrip");

    /* predicates */
    from_hex(a, "FFFF8000000000000001");
    CHECK(x87_80_sign(a) && x87_80_is_nan(a) && x87_80_is_snan(a),
          "predicates on -snan");
}

/* ---------------- randomized arithmetic vs the oracle ------------------- */

static uint64_t rng_state = 0x5DEECE66D12345ULL;

uint64_t nextr(void)
{
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng_state;
}

void gen_operand(uint8_t v[10], dec_t *d)
{
    uint64_t m = nextr() ^ (nextr() << 21);
    unsigned r = (unsigned)(nextr() & 0xFu);
    unsigned field;
    bool sign = (nextr() & 1u) != 0;

    switch (r) {
    case 0: field = 0; break;                       /* denormal zone */
    case 1: field = 1; break;
    case 2: field = 0x3FFF; break;
    case 3: field = 0x3FFE; break;
    case 4: field = 0x4000; break;
    case 5: field = 16383; break;                   /* near overflow */
    case 6: field = 16382; break;
    case 7: field = 16384 - 4; break;
    case 8: field = 0x3FFF + 200; break;
    case 9: field = 0x3FFF - 200; break;
    default: field = (unsigned)(nextr() % 0x7FFEu) + 1u; break;
    }
    if (field == 0) {
        /* subnormal / pseudo-denormal / (rarely) zero */
        if ((nextr() & 7u) == 0) m = 0;
        else if (nextr() & 1u) m |= 0x8000000000000000ULL; /* pseudo-den. */
        else m &= 0x7FFFFFFFFFFFFFFFULL;
        if (m == 0) m = 1;
    } else {
        m |= 0x8000000000000000ULL;
    }
    mk80(v, (field | (sign ? 0x8000u : 0u)), m);
    dec(v, d);
}

void run_random(void)
{
    int i;
    static const unsigned rcs[4] = {0, 1, 2, 3};
    static const unsigned pcs[3] = {64, 53, 24};
    int n_add = 0, n_sub = 0, n_mul = 0, n_div = 0, n_sqrt = 0;

    for (i = 0; i < 600; i++) {
        uint8_t a[10], b[10], o[10], e[10];
        dec_t da, db;
        unsigned rc = rcs[i & 3u], pc = pcs[(i / 4u) % 3u];
        unsigned fl, ef;
        int kind = i % 5;
        char ba[32], bb[32], bo[32], be[32];

        x87_80_set_round(rc);
        x87_80_set_prec(pc);
        gen_operand(a, &da);
        gen_operand(b, &db);
        if (db.cls != 1) continue;
        if (kind != 4 && da.cls != 1) continue;

        switch (kind) {
        case 0:
            fl = x87_80_add(o, a, b);
            ef = orc_addsub(e, &da, &db, false, rc, pc);
            n_add++;
            break;
        case 1:
            fl = x87_80_sub(o, a, b);
            ef = orc_addsub(e, &da, &db, true, rc, pc);
            n_sub++;
            break;
        case 2:
            fl = x87_80_mul(o, a, b);
            ef = orc_mul(e, &da, &db, rc, pc);
            n_mul++;
            break;
        case 3:
            fl = x87_80_div(o, a, b);
            ef = orc_div(e, &da, &db, rc, pc);
            n_div++;
            break;
        default:
            if (da.sign) continue; /* sqrt covered by specials for negatives */
            fl = x87_80_sqrt(o, a);
            ef = orc_sqrt(e, &da, rc, pc);
            n_sqrt++;
            break;
        }
        /* DE from either operand's field-0 encoding */
        if (da.den_enc || db.den_enc) ef |= X_DE;
        hx80(a, ba, sizeof ba);
        hx80(b, bb, sizeof bb);
        hx80(o, bo, sizeof bo);
        hx80(e, be, sizeof be);
        CHECK(eq80(o, e) && fl == ef,
              "random %s rc=%u pc=%u\n  a=%s\n  b=%s\n  got %s fl=%u\n  want %s fl=%u",
              kind == 0 ? "add" : kind == 1 ? "sub" : kind == 2 ? "mul"
                        : kind == 3 ? "div" : "sqrt",
              rc, pc, ba, bb, bo, fl, be, ef);
        if (g_fail > 20) return;
    }
    printf("random cases: add=%d sub=%d mul=%d div=%d sqrt=%d\n",
           n_add, n_sub, n_mul, n_div, n_sqrt);
    CHECK(n_add >= 50 && n_div >= 50, "random case counts");
}

