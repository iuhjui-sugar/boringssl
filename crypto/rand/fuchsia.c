/* Copyright 2016 The Fuchsia Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <openssl/rand.h>

#if defined(OPENSSL_FUCHSIA) && !defined(BORINGSSL_UNSAFE_FUZZER_MODE)

#include <limits.h>
#include <stdlib.h>

#include <magenta/syscalls.h>

#include "internal.h"

void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  while (requested > 0) {
    size_t output_bytes_this_pass = MX_CPRNG_DRAW_MAX_LEN;
    if (requested < (size_t) output_bytes_this_pass) {
      output_bytes_this_pass = requested;
    }
    size_t bytes_drawn;
    mx_status_t status = mx_cprng_draw(out, output_bytes_this_pass, &bytes_drawn);
    if (status != NO_ERROR) {
      abort();
    }
    requested -= bytes_drawn;
    out += bytes_drawn;
  }
  return;
}

#endif /* OPENSSL_FUCHSIA && !BORINGSSL_UNSAFE_FUZZER_MODE */
