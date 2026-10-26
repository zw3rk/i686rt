# Self-documenting Makefile for i686rt — 32-bit x86 -> AArch64 user-mode translator
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help all build test check test-p0-lima clean

BUILD_DIR := _build

# CC defaults to the shell's clang; inside the cross shell
#   nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv
# that is the aarch64-unknown-linux-musl cross clang.  An explicit
# CC from the environment or command line always wins.
ifeq ($(origin CC),default)
  CC := clang
endif
# src/main.c calls setenv(3), which musl hides under strict -std=c11 unless a
# POSIX feature-test macro is visible; expose exactly that (keeps -pedantic
# and every prescribed warning intact).
CFLAGS  ?= -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror=vla -pedantic -Os -fPIE -Iinclude -Isrc -Isrc/rt32
LDFLAGS ?= -static-pie
HOST_CC ?= cc
# Host-toolchain builds (build-darwin, test-u3) widen strict POSIX to the
# full host API set (MAP_ANONYMOUS, kqueue, MAP_JIT...). Never used for
# cross targets.
ifeq ($(shell uname),Darwin)
HOST_DEFS := -D_DARWIN_C_SOURCE
else
HOST_DEFS :=
endif

# src/main.c plus every vendored rt32 core file present; src/rt32/ arrives
# with lane L0a, so pre-merge this globs to nothing and main.c builds alone.
# Wave U3 (lane u3-i686): src/vm/ (two-regime vm32 + Provider A) and
# src/dbt/aot/ (relative site-table serializer) join the build.
# Exactly one host backend group joins the build (all define the same
# backend symbols). Selected from the compiler target triple so
# cross-builds get the Linux group even when the build host is Darwin.
U3_PROBE_CC := $(or $(CC),cc)
ifeq ($(findstring darwin,$(shell $(U3_PROBE_CC) -dumpmachine 2>/dev/null)),darwin)
U3_BACKEND_SRCS := src/os/backend_darwin.c src/os/backend_darwin_io.c \
        src/os/backend_darwin_net.c
else
U3_BACKEND_SRCS := src/os/backend_linux.c src/os/backend_linux_sys.c
endif
U3_OS_SRCS := $(filter-out src/os/backend_linux.c src/os/backend_linux_sys.c src/os/backend_darwin.c src/os/backend_darwin_io.c src/os/backend_darwin_net.c,$(wildcard src/os/*.c)) $(U3_BACKEND_SRCS)
SRCS := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/x86/*.c) \
        $(wildcard src/interp/*.c) $(U3_OS_SRCS) \
        $(wildcard src/vm/*.c) \
        $(wildcard src/dbt/*.c) $(wildcard src/dbt/aot/*.c) src/trampoline.S
HDRS := src/i686rt.h include/a32host.h $(wildcard src/rt32/*.h) \
         $(wildcard src/x86/*.h) $(wildcard src/interp/*.h) $(wildcard src/os/*.h) \
         $(wildcard src/vm/*.h) $(wildcard src/dbt/*.h) $(wildcard src/dbt/aot/*.h)

OBJ_DIR    := $(BUILD_DIR)/obj
OBJS       := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
I686RT_BIN := $(BUILD_DIR)/i686rt

help: ## Show available build and verification targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

SRCS_X64 := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/x86/*.c) \
        $(wildcard src/interp/*.c) $(U3_OS_SRCS) \
        $(wildcard src/vm/*.c) $(wildcard src/dbt/aot/*.c)
SRCS_X64 := $(filter-out src/rt32/rt32_a64_emit.c,$(SRCS_X64))
OBJS_X64  := $(patsubst src/%.c,$(OBJ_DIR)-x64/%.o,$(SRCS_X64))
I686RT_X64 := $(BUILD_DIR)/i686rt-x86_64

build-x86_64: $(I686RT_X64) ## Interpreter-only x86_64-host build (D3 tier 2, H4)
$(I686RT_X64): $(OBJS_X64)
	$(CC) $(CFLAGS) -DI686RT_NO_DBT $(OBJS_X64) $(LDFLAGS) -o $@
$(OBJ_DIR)-x64/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DI686RT_NO_DBT -c $< -o $@

all: build ## Build everything (currently just the i686rt binary)

build: $(I686RT_BIN) ## Build static-PIE aarch64-linux i686rt binary

$(I686RT_BIN): $(OBJS)
	@printf "\033[32m▸ Linking\033[0m $@\n"
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@
	@ln -sf i686rt $(BUILD_DIR)/i686rt-binfmt-p

$(OBJ_DIR)/%.o: src/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

test: ## Run the test suite (none yet; fixtures arrive in Phase 1)
	@echo "phase 0: no tests yet"

check: check-line-limits test-u3 ## Run line limits + host unit tests (RC-U3)

test-p0-lima: ## Phase 0 Lima placeholder; the real RC0 check is nix build .#i686rt
	@echo "phase 0: no test yet (RC0 = nix build)"

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)

## ------------------------------------------------------------------ ##
##  Phase 1 — i386 fixtures and checks (docker linux/386 oracle, E06)  ##
## ------------------------------------------------------------------ ##

fixtures: tools/build_fixture.sh tests/hello.c tests/test_p1_isa.c ## Build i386 static ELF fixtures into _build (docker, linux/386)
	@mkdir -p $(BUILD_DIR)
	tools/build_fixture.sh tests/hello.c $(BUILD_DIR)/hello
	tools/build_fixture.sh tests/test_p1_isa.c $(BUILD_DIR)/test_p1_isa

test-p1-fixture: fixtures ## Run test_p1_isa under the native i386 docker oracle (must print PASS)
	docker run --rm --platform linux/386 -v "$(CURDIR)/$(BUILD_DIR)":/w alpine:3.20 /w/test_p1_isa

test-p1-lima: ## RC1 on lima (aarch64): run the fixture under i686rt (coordinator executes at S1)
	@echo "RC1 runs on the lima aarch64 host (coordinator executes this at S1):"
	@echo "  ./result/bin/i686rt -- _build/test_p1_isa    # must print PASS"

.PHONY: fixtures test-p1-fixture test-p1-lima

## ------------------------------------------------------------------ ##
##  Phase 2 — L2h: i686 busybox fixture + RC2 targets                   ##
## ------------------------------------------------------------------ ##

busybox: ## Fetch the Alpine i686 static busybox into _build (tools/fetch_busybox.sh)
	@mkdir -p $(BUILD_DIR)
	tools/fetch_busybox.sh

test-p2-lima: busybox ## RC2 (coordinator, aarch64 docker VM): busybox sh under i686rt interp (must print ok)
	I686RT_ENGINE=interp ./$(BUILD_DIR)/i686rt -- ./$(BUILD_DIR)/busybox-i686 sh -c 'ls / && echo ok'

test-p2-busybox-oracle: busybox ## Oracle self-check: run the fetched i686 busybox under docker linux/386 (must print ok)
	docker run --rm --platform linux/386 -v "$(CURDIR)/$(BUILD_DIR)":/w alpine:3.20 /w/busybox-i686 sh -c 'echo ok'

.PHONY: busybox test-p2-lima test-p2-busybox-oracle

## ------------------------------------------------------------------ ##
##  Phase 3 — L3d: differential trace harness (interp vs dbt)          ##
## ------------------------------------------------------------------ ##

difftest: build fixtures ## Differential-trace test_p1_isa under interp vs dbt (tools/difftest.sh; DIFFTEST: EQUAL)
	tools/difftest.sh $(BUILD_DIR)/test_p1_isa

test-p3-lima: fixtures busybox ## RC3 differential: test_p1_isa + busybox echo smoke, interp vs dbt (single PASS)
	@set -e; \
	mkdir -p $(BUILD_DIR)/bb; \
	for a in sh ls echo cat; do ln -sf ../busybox-i686 $(BUILD_DIR)/bb/$$a; done; \
	tools/difftest.sh $(BUILD_DIR)/test_p1_isa >$(BUILD_DIR)/difftest-p1.log || { \
	  cat $(BUILD_DIR)/difftest-p1.log; echo "FAIL: test_p1_isa difftest not EQUAL"; exit 1; }; \
	out=$$(PATH="$(CURDIR)/$(BUILD_DIR)/bb:$$PATH" \
	  tools/difftest.sh $(BUILD_DIR)/busybox-i686 sh -c 'echo ok'); \
	case "$$out" in *DIFFTEST: EQUAL*) ;; *) \
	  printf '%s\n' "$$out"; echo "FAIL: busybox difftest not EQUAL"; exit 1;; esac; \
	case "$$out" in *ok*) ;; *) \
	  printf '%s\n' "$$out"; echo "FAIL: busybox output missing ok"; exit 1;; esac; \
	echo PASS

.PHONY: difftest test-p3-lima

## ------------------------------------------------------------------ ##
##  Phase 5 — L5e: x87/SSE fixture + oracle golden vectors (RC5)       ##
##  RC5/test-p5-lima is executed by the coordinator inside the arm64  ##
##  docker VM with an aarch64 _build/i686rt on the PATH-rooted cwd.   ##
## ------------------------------------------------------------------ ##

fixture-p5: ## Build the x87/SSE i386 fixture into _build (docker linux/386, -msse -msse2)
	@mkdir -p $(BUILD_DIR)
	tools/mkgolden.sh --fixture-only

golden-p5: ## Regenerate tests/golden/p5.txt and p5_x87_80.txt from the docker linux/386 QEMU oracle
	tools/mkgolden.sh

test-p5-lima: ## RC5: fixture under ./_build/i686rt vs goldens, default + --x87-80 (single PASS)
	@test -x "$(BUILD_DIR)/test_p5_fpu_sse" || $(MAKE) --no-print-directory fixture-p5
	@set -e; \
	d=$(BUILD_DIR)/p5check; mkdir -p $$d; \
	grep -v '^CASE X87ONLY ' tests/golden/p5.txt | grep -e '^CASE ' -e '^DONE' > $$d/gold_default.txt; \
	grep -e '^CASE ' -e '^DONE' tests/golden/p5_x87_80.txt > $$d/gold_x87_80.txt; \
	./$(BUILD_DIR)/i686rt -- $(BUILD_DIR)/test_p5_fpu_sse > $$d/act_default.raw; \
	grep -v '^CASE X87ONLY ' $$d/act_default.raw > $$d/act_default.txt; \
	./$(BUILD_DIR)/i686rt --x87-80 -- $(BUILD_DIR)/test_p5_fpu_sse > $$d/act_x87_80.txt; \
	if cmp -s $$d/gold_default.txt $$d/act_default.txt && \
	   cmp -s $$d/gold_x87_80.txt $$d/act_x87_80.txt; then \
	  echo PASS; \
	else \
	  echo "FAIL: RC5 i686rt output vs golden"; \
	  diff $$d/gold_default.txt $$d/act_default.txt | sed -n 1,40p || true; \
	  diff $$d/gold_x87_80.txt $$d/act_x87_80.txt | sed -n 1,40p || true; \
	  exit 1; \
	fi

.PHONY: fixture-p5 golden-p5 test-p5-lima

## ------------------------------------------------------------------ ##
##  Phase 6 — L6b: hl smoke targets (RC6; coordinator executes at S6   ##
##  with the L6a-built hl; every smoke is bounded by timeout 120)      ##
## ------------------------------------------------------------------ ##

# Inputs for the RC6 smokes.  I686RT_BIN is already assigned in the
# build section above, so the ?= here defers to it (same path, kept
# relative to the repo root); an explicit I686RT_BIN= on the command
# line wins either way.
HL_BIN       ?= ../hyper-linux/_build/hl
I686RT_BIN   ?= $(abspath $(BUILD_DIR)/i686rt)
BUSYBOX_I686 ?= $(BUILD_DIR)/busybox-i686

test-p1-hl: ## RC1 on hl: run the fixture under hl+i686rt (coordinator executes at S6)
	@echo "RC1 runs under hl (coordinator executes this at S6):"
	@echo "  $(HL_BIN) --i686rt $(I686RT_BIN) $(BUILD_DIR)/test_p1_isa    # must print PASS"

test-p2-hl: busybox ## RC2 through hl: busybox sh -c 'echo ok' smoke (coordinator executes at S6)
	tools/hl-smoke.sh "$(HL_BIN)" "$(I686RT_BIN)" "$(BUSYBOX_I686)"

test-p3-hl: busybox ## RC3 through hl: busybox sh -c 'echo ok' smoke (coordinator executes at S6)
	tools/hl-smoke.sh "$(HL_BIN)" "$(I686RT_BIN)" "$(BUSYBOX_I686)"

test-p4-hl: ## RC4 on hl: dynamic glibc test_p4 under hl+i686rt (coordinator executes at S6)
	@echo "RC4 runs under hl (coordinator executes this at S6; needs the RC4 sysroot):"
	@echo "  $(HL_BIN) --i686rt $(I686RT_BIN) --sysroot <sysroot> -- $(BUILD_DIR)/test_p4_glibc    # must print PASS"

test-p5-hl: busybox ## RC5 through hl: busybox sh -c 'echo ok' smoke (coordinator executes at S6)
	tools/hl-smoke.sh "$(HL_BIN)" "$(I686RT_BIN)" "$(BUSYBOX_I686)"

.PHONY: test-p1-hl test-p2-hl test-p3-hl test-p4-hl test-p5-hl

## ------------------------------------------------------------------ ##
##  Phase H — H2: musl libc-test + LTP subset runners (hardening)      ##
## ------------------------------------------------------------------ ##

h2-report: ## Assemble tests/hardening/h2-report.md from the committed runner logs (run tools/run-libctest.sh and tools/run-ltp.sh first)
	tests/hardening/mkreport.sh

.PHONY: h2-report

## ------------------------------------------------------------------ ##
##  Wave U3 — lane u3-i686: two-regime vm32, dual backends, AOT sites   ##
## ------------------------------------------------------------------ ##

# Curated-C11 file size discipline for this lane's exclusive ownership
# (Wave U3 card L-U3-I686 as delegated: src/vm/, dual backends,
# src/dbt/aot/, the LOCK-atomics lines in h_alu.c/h_shift.c, the site
# records in emit_mov.c, the i686rt.h tail, and the lane test). Files
# outside this list (vendored src/rt32 donor, src/os/sys_* syscall
# tables) belong to sibling lanes and are not gated here.
U3_OWNED := src/vm/vm32.c src/vm/vm32.h src/vm/vm_file.c src/vm/vm_file.h \
        src/os/backend.h src/os/backend_linux.c src/os/backend_linux_sys.c \
        src/os/backend_darwin.c src/os/backend_darwin_io.c \
        src/os/backend_darwin_net.c \
        src/dbt/aot/aot.h src/dbt/aot/aot.c \
        src/interp/h_alu.c src/interp/h_shift.c src/dbt/emit_mov.c \
        src/i686rt.h tests/unit/test_u3_sites.c
check-line-limits: ## Enforce the <= 900-line rule on lane-owned files
	@fail=0; \
	for f in $(U3_OWNED); do \
	  n=$$(wc -l < "$$f"); \
	  if [ "$$n" -gt 900 ]; then echo "OVER LIMIT: $$f ($$n lines)"; fail=1; fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "FAIL: files over 900 lines"; exit 1; fi; \
	echo "check-line-limits: all lane-owned files <= 900 lines"

# Darwin-portable Wave U3 TU set. The full _build/i686rt-darwin-arm64
# translator binary additionally needs the syscall marshal lane
# (src/os/sys_*.c uses Linux-only headers); until that lane lands,
# build-darwin compiles every lane TU warning-clean under the host
# toolchain and links + runs the portable host check below.
U3_DARWIN_SRCS := src/vm/vm32.c src/vm/vm_file.c \
        src/os/backend_linux.c src/os/backend_linux_sys.c \
        src/os/backend_darwin.c src/os/backend_darwin_io.c \
        src/os/backend_darwin_net.c \
        src/dbt/aot/aot.c \
        src/interp/h_alu.c src/interp/h_shift.c src/dbt/emit_mov.c \
        src/rt32/rt32_vm.c src/x86/decode.c
U3_DARWIN_OBJS := $(patsubst src/%.c,$(OBJ_DIR)-darwin/%.o,$(U3_DARWIN_SRCS))

$(OBJ_DIR)-darwin/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(HOST_CC) $(CFLAGS) $(HOST_DEFS) -c $< -o $@

build-darwin: $(U3_DARWIN_OBJS) test-u3 ## Compile the Wave U3 TU set for macOS arm64 + run the host check

# Portable host check: layout pins, AOT round-trip, Provider A promotion,
# regime selection, and the dual-backend smoke set. Uses the host
# toolchain (never the cross CC).
U3_TEST_SRCS := tests/unit/test_u3_sites.c src/dbt/aot/aot.c \
        src/vm/vm32.c src/vm/vm_file.c src/rt32/rt32_vm.c \
        src/os/backend_linux.c src/os/backend_linux_sys.c \
        src/os/backend_darwin.c src/os/backend_darwin_io.c \
        src/os/backend_darwin_net.c

test-u3: ## Build and run the Wave U3 host check (must print U3-I686 OK)
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(CFLAGS) $(HOST_DEFS) -DI686RT_NO_DBT $(U3_TEST_SRCS) -o $(BUILD_DIR)/test_u3_sites -pthread
	./$(BUILD_DIR)/test_u3_sites

.PHONY: check-line-limits build-darwin test-u3

## ------------------------------------------------------------------ ##
##  Phase H — H3: CoreMark performance (interp vs dbt vs oracle)        ##
## ------------------------------------------------------------------ ##

h3-coremark: ## Assemble tests/hardening/h3-coremark.md from the committed CoreMark logs (run tools/run-coremark.sh first)
	tools/run-coremark.sh report

.PHONY: h3-coremark
