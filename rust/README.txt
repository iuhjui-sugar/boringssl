boringssl-sys
============

A low-level binding crate for Rust that moves in lockstop with boringssl. Boringssl explicitly does not have a
stable ABI, `boringssl-sys` is the solution for preventing subtle-memory corruption bugs due to version skew.

### How it works
`boringssl-sys` uses `bindgen` as part of the cmake build process to generate Rust compatibility shims for each
supported target platform. It is important to generate it for each platform because `bindgen` uses llvm information
for alignment which varies depending on architecture. 
