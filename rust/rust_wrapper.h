// This file is used as a compatibility shim for the error functions in boringssl.
// They are defined as a C macros and thus not visible to bindgen. This file is used
// so that we can invoke the C preprocessor, create some symbols, and link the resulting
// static library into the Rust file. The result of this process is that any changes to the error
// code logic will move in lockstep.

#include <stdint.h>
#include <openssl/err.h>

int ERR_GET_LIB_RUST(uint32_t packed_error);

int ERR_GET_REASON_RUST(uint32_t packed_error);

int ERR_GET_FUNC_RUST(uint32_t packed_error);
