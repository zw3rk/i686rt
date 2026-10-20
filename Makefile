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
CFLAGS  ?= -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror=vla -pedantic -Os -fPIE -Iinclude -Isrc
LDFLAGS ?= -static-pie

# src/main.c plus every vendored rt32 core file present; src/rt32/ arrives
# with lane L0a, so pre-merge this globs to nothing and main.c builds alone.
SRCS := src/main.c $(wildcard src/rt32/*.c) $(wildcard src/x86/*.c) \
        $(wildcard src/interp/*.c) $(wildcard src/os/*.c)
HDRS := src/i686rt.h include/a32host.h $(wildcard src/rt32/*.h) \
         $(wildcard src/x86/*.h) $(wildcard src/interp/*.h) $(wildcard src/os/*.h)

OBJ_DIR    := $(BUILD_DIR)/obj
OBJS       := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SRCS))
I686RT_BIN := $(BUILD_DIR)/i686rt

help: ## Show available build and verification targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

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

check: test ## Alias for test

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
