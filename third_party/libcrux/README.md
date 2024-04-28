# Libcrux Cryptography

The files in this directory are generated using hax and eurydice from the libcrux
library. They are written natively in Rust and exported to C with hax and eurydice.
All files are included under the Apache2.0 license. (See LICENSE file.)

Necessary hand-written glue-code is in

- `eurydice_glue.h`
- `intrinsics/libcrux_mlkem_avx2.h`

The high level APIs in `api` are hand-written as well.

The Libcrux SHA3 code that is used in the ML-KEM implementation is provided as well.
Note that this code is not verified.
But it provides APIs that are specific to ML-KEM.

All the code relies on the Karamel glue code, provided in `./karamel`.

See `code_gen.txt` for the git revisions for each tool, used to generate the code
in this directory.

* Karamel: https://github.com/FStarLang/karamel
* Charon: https://github.com/AeneasVerif/charon/
* Eurydice: https://github.com/AeneasVerif/eurydice
* F*: https://github.com/fstarLang/fstar

When the F* revision is empty, a released version is used.
By default: [v2024.01.13](https://github.com/FStarLang/FStar/releases/tag/v2024.01.13)
