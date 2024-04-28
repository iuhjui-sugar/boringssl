# Libcrux Cryptography

The files in this directory are generated using hax and eurydice from the libcrux
library. They are written natively in Rust and exported to C with hax and eurydice.
All files are included under the Apache2.0 license. (See LICENSE file.)

Necessary hand-written glue-code is in

- `include/internal/eurydice_glue.h`
- `include/internal/libcrux_hacl_glue.h`
- `src/libcrux_hacl_glue.c`

The high level APIs are hand-written as well in

- `include/Libcrux_Kem_Kyber_Kyber768.h`
- `src/Libcrux_Kem_Kyber_Kyber768.c`

The HACL SHA3 code that is used in the ML-KEM implementation is provided as well.

All the code relies on the Karamel glue code from https://github.com/FStarLang/karamel,
which is provided in `./karamel`.

The HACL code comes from https://github.com/hacl-star/hacl-star 81f0e3bb461fc7d0102211dc9fa5be03951cd654

A standalone cmake file is provided for convenience to build only this code.

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -G"Ninja" ..
ninja
```
