/*
 * tests/unit/dbt_driver.c — host-side template for DBT lane checks.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lanes copy this to tests/unit/test_l3<X>.c and extend: each case
 * writes x86 bytes into the fake window at CASE_EIP, runs them through
 * i686_dbt_translate + i686_jit_run_block (engine stub) and compares
 * the final GPR/flags state against the reference computed by invoking
 * the interpreter on a cloned ctx. Expected final line: L3<X> OK.
 *
 * NOTE: this file is a TEMPLATE; it compiles only on the aarch64 target
 * (the DBT emits and runs A64). Lane checks run it in the arm64 docker
 * VM via the main build's test binary — see docs/lanes/phase-3.md.
 */
