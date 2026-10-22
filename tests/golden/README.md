# Golden outputs

`p5.txt` and `p5_x87_80.txt` are captured by `tools/mkgolden.sh` from the
docker `--platform linux/386 alpine:3.20` QEMU TCG oracle (the E06-proven
environment) running `_build/test_p5_fpu_sse` — the fixture built with
`-march=i686 -msse -msse2 -mno-mmx`.  Both files carry the full oracle
run (the oracle is exact 80-bit x87 hardware, so the same bytes are the
exact-mode expectation): the default-mode RC5 check compares `p5.txt`
minus the lines marked `CASE X87ONLY`, and the `--x87-80` check compares
`p5_x87_80.txt` in full.  Regenerate with `make golden-p5`; never
hand-edit.
