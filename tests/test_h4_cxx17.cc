/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * H4 C++17 guest (Phase 7, RC-H): try/catch stack unwinding across
 * call frames, catch ordering with rethrow, dynamic_cast RTTI (hit +
 * miss), std::thread create/join with value collection, and
 * thread_local isolation plus per-thread destructor runs. Prints one
 * `PASS cxx17/<name>` line per case and exits 0 on success; any
 * mismatch prints `FAIL ...` and exits 1. Output is fully
 * deterministic (no pointers, no timings).
 */

#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>

static int h4_failures;

#define H4_OK(n) \
    do { \
        std::printf("PASS cxx17/%s\n", n); \
    } while (0)
#define H4_FAIL(n) \
    do { \
        std::printf("FAIL cxx17/%s\n", n); \
        ++h4_failures; \
    } while (0)
#define H4_CHECK(n, cond) \
    do { \
        if (cond) \
            H4_OK(n); \
        else \
            H4_FAIL(n); \
    } while (0)

struct H4Err : std::runtime_error {
    explicit H4Err(const char *m) : std::runtime_error(m)
    {
    }
};

static int h4_depth2(void)
{
    throw H4Err("h4-boom");
}

static int h4_depth1(void)
{
    return h4_depth2() + 1;
}

static void t_exceptions(void)
{
    bool order_ok = false;
    try {
        (void)h4_depth1();
        H4_FAIL("exceptions-unwind");
    } catch (const H4Err &e) {
        H4_CHECK("exceptions-unwind", std::string(e.what()) == "h4-boom");
    } catch (...) {
        H4_FAIL("exceptions-unwind");
    }
    try {
        try {
            throw H4Err("inner");
        } catch (const std::runtime_error &) {
            throw;
        }
    } catch (const H4Err &) {
        order_ok = true;
    } catch (...) {
        order_ok = false;
    }
    H4_CHECK("exceptions-rethrow", order_ok);
}

struct H4Base {
    virtual ~H4Base()
    {
    }
};

struct H4Derived : H4Base {
    int magic = 0x4817;
};

struct H4Other : H4Base {
};

static void t_rtti(void)
{
    H4Derived d;
    H4Other o;
    H4Base *b = &d;
    H4Base *bo = &o;
    H4Derived *back = dynamic_cast<H4Derived *>(b);
    H4_CHECK("rtti-typeid", std::string(typeid(*b).name()).size() > 0);
    H4_CHECK("rtti-cast-ok", back != nullptr && back->magic == 0x4817);
    H4_CHECK("rtti-cast-null", dynamic_cast<H4Derived *>(bo) == nullptr);
    H4_CHECK("rtti-cross-null", dynamic_cast<H4Other *>(b) == nullptr);
}

static void h4_worker(int v, int *out)
{
    *out = v * 2 + 1;
}

static int h4_dtor_count = 0;

struct H4Guard {
    ~H4Guard()
    {
        ++h4_dtor_count;
    }
};

static thread_local H4Guard h4_guard;
static thread_local int h4_tls = 0;

static void h4_tls_worker(int v, int *seen)
{
    h4_tls = v;
    /* Touch the guard so every thread constructs one. */
    (void)h4_guard;
    *seen = h4_tls;
}

static void t_threads(void)
{
    int s0 = 0;
    int s1 = 0;
    int t0 = 0;
    int t1 = 0;
    int base0 = 0;
    std::thread w0(h4_worker, 20, &s0);
    std::thread w1(h4_worker, 21, &s1);
    w0.join();
    w1.join();
    H4_CHECK("threads-join", s0 == 41 && s1 == 43);
    h4_tls = 7;
    base0 = h4_dtor_count;
    {
        std::thread u0(h4_tls_worker, 100, &t0);
        std::thread u1(h4_tls_worker, 200, &t1);
        u0.join();
        u1.join();
    }
    H4_CHECK("threads-tls-isolation", h4_tls == 7 && t0 == 100 && t1 == 200);
    /* Both workers constructed and destroyed exactly one guard each;
     * the main thread's guard is still alive here. */
    H4_CHECK("threads-tls-dtor", h4_dtor_count == base0 + 2);
}

int main(void)
{
    t_exceptions();
    t_rtti();
    t_threads();
    if (h4_failures == 0)
        std::printf("H4: ALL PASS\n");
    else
        std::printf("H4: %d FAILURES\n", h4_failures);
    return h4_failures == 0 ? 0 : 1;
}
