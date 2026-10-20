{
  description = "i686rt — 32-bit x86 (i686) to AArch64 Linux user-mode binary translator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      darwinSystem = "aarch64-darwin";
      darwinPkgs   = nixpkgs.legacyPackages.${darwinSystem};
      linuxSystem  = "x86_64-linux";
      linuxPkgs    = nixpkgs.legacyPackages.${linuxSystem};
      aarch64LinuxPkgs = nixpkgs.legacyPackages.aarch64-linux;

      # Cross-compilers for aarch64-unknown-linux-musl (i686rt itself)
      darwinA64Musl = darwinPkgs.pkgsCross.aarch64-multiplatform-musl;
      linuxA64Musl  = linuxPkgs.pkgsCross.aarch64-multiplatform-musl;

      # Build form that passed the L0b acceptance check on this host
      # (aarch64-darwin + nix-linux-builder external builders): plain
      #   nix build .#i686rt
      # schedules fine — the darwin->aarch64-linux-musl cross toolchain
      # (aarch64-unknown-linux-musl-gcc-wrapper) is substituted from
      # cache.nixos.org and only the i686rt derivation builds locally.
      # No --system aarch64-linux fallback was needed.

      mkI686rt = crossPkgs: crossPkgs.stdenv.mkDerivation {
        pname = "i686rt";
        version = "0.1.0";
        src = ./.;

        dontStrip = true;
        enableParallelBuilding = true;

        buildPhase = ''
          runHook preBuild
          CC="${crossPkgs.stdenv.cc.targetPrefix}gcc"
          command -v "$CC" >/dev/null 2>&1 || CC="${crossPkgs.stdenv.cc.targetPrefix}cc"
          if [ -f Makefile ]; then
            make build CC="$CC"
          else
            # No Makefile yet (lane L0c): direct compile of the frozen
            # sources.  src/rt32/ lands with lane L0a; glob so this stays
            # correct after the Phase 0 merge (pre-merge: main.c alone).
            # _POSIX_C_SOURCE: main.c (frozen) calls setenv(3), which strict
            # -std=c11 hides; gcc >= 14 makes the implicit declaration an
            # error.  Smallest feature macro that declares it under musl.
            CFLAGS="-std=c11 -Wall -Wextra -Werror=vla -pedantic -Os -fPIE -D_POSIX_C_SOURCE=200809L -Iinclude -Isrc"
            LDFLAGS="-static-pie -Wl,-z,max-page-size=4096"
            SRCS="src/main.c"
            for f in src/rt32/*.c; do
              [ -e "$f" ] && SRCS="$SRCS $f"
            done
            mkdir -p _build
            # shellcheck disable=SC2086
            $CC $CFLAGS -o _build/i686rt $SRCS $LDFLAGS
          fi
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/include
          cp _build/i686rt $out/bin/i686rt
          # argv0 alias for binfmt_misc registration (mirrors a32rt).
          ln -sf i686rt $out/bin/i686rt-binfmt-p
          cp include/a32host.h $out/include/a32host.h
          runHook postInstall
        '';

        meta = with crossPkgs.lib; {
          description = "Standalone static-PIE i686 (32-bit x86) -> AArch64 Linux user-mode translator";
          mainProgram = "i686rt";
          platforms = [ "aarch64-linux" ];
          license = licenses.asl20;
        };
      };

      # mkI686rtTests — eval-only placeholder, intentionally a plain
      # attrset (nothing to build yet).  Phase 1 (experiments/E06) lands
      # the real guest fixture suite: i686 test binaries must be
      # cross-built with pkgsCross.musl32 (musl libc) — NEVER
      # pkgsi686Linux (glibc-based).
      mkI686rtTests = {
        status = "placeholder — fixtures arrive in Phase 1 via pkgsCross.musl32 (E06); never pkgsi686Linux";
      };

    in {
      packages.${darwinSystem} = {
        i686rt  = mkI686rt darwinA64Musl;
        default = self.packages.${darwinSystem}.i686rt;
      };

      checks.${darwinSystem} = {
        i686rt = self.packages.${darwinSystem}.i686rt;
      };

      packages.${linuxSystem} = {
        i686rt  = mkI686rt linuxA64Musl;
        default = self.packages.${linuxSystem}.i686rt;
      };

      checks.${linuxSystem} = {
        i686rt = self.packages.${linuxSystem}.i686rt;
      };

      packages.aarch64-linux = {
        i686rt  = mkI686rt aarch64LinuxPkgs.pkgsMusl;
        default = self.packages.aarch64-linux.i686rt;
      };

      checks.aarch64-linux = {
        i686rt = self.packages.aarch64-linux.i686rt;
      };

      # Exposed for `nix eval .#i686rtTests` only (eval-only, see above).
      i686rtTests = mkI686rtTests;

      # ── Hydra Jobs (ci.zw3rk.com) ───────────────────────────────────
      hydraJobs = {
        ${linuxSystem} = {
          i686rt = self.packages.${linuxSystem}.i686rt;
        };
        aarch64-linux = {
          i686rt = self.packages.aarch64-linux.i686rt;
        };
        ${darwinSystem} = {
          i686rt = self.packages.${darwinSystem}.i686rt;
        };
      };

      devShells.${darwinSystem}.default = darwinPkgs.mkShell {
        name = "i686rt-dev";
        buildInputs = [
          darwinPkgs.gnumake
          darwinPkgs.lima
          darwinA64Musl.stdenv.cc
        ];
        LIMACTL = "${darwinPkgs.lima}/bin/limactl";
      };
    };
}
