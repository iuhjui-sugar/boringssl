/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* Post-quantum key agreement, based upon the reference implementation
 * https://github.com/tpoeppelmann/newhope. Note: this implementation does not
 * interoperate with the reference implementation!
 *
 * The authors' permission to use their reference implementation is gratefully
 * acknowledged. */

#ifndef OPENSSL_HEADER_NEWHOPE_H
#define OPENSSL_HEADER_NEWHOPE_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* NEWHOPE_POLY_new returns a new NEWHOPE_POLY object, or NULL on error. */
OPENSSL_EXPORT NEWHOPE_POLY* NEWHOPE_POLY_new(void);

/* NEWHOPE_POLY_free frees |sk|. */
OPENSSL_EXPORT void NEWHOPE_POLY_free(NEWHOPE_POLY* sk);

/* NEWHOPE_SERVERMSG_init initializes |msg| and |sk| for a new key
 * exchange. |msg| must have room for |NEWHOPE_SERVERMSG_LENGTH|. Neither output
 * may be cached. */
OPENSSL_EXPORT void NEWHOPE_keygen(uint8_t* msg, NEWHOPE_POLY* sk);

/* NEWHOPE_server_compute_key completes a key exchange given a client message
 * |msg| and the previously generated server secret |sk|. The result of the key
 * exchange is written to |key|, which must have space for
 * |SHA256_DIGEST_LENGTH| bytes. */
OPENSSL_EXPORT void NEWHOPE_server_compute_key(const NEWHOPE_POLY* sk,
                                               const uint8_t* client_msg,
                                               uint8_t* key);

/* NEWHOPE_client_compute_key completes a key exchange given a server message
 * |in_msg|. The result of the key exchange is written to |key|, which must have
 * space for |SHA256_DIGEST_LENGTH| bytes. The message to be send to the client
 * is written to |msg|, which must have room for |NEWHOPE_CLIENTMSG_LENGTH|
 * bytes. */
OPENSSL_EXPORT void NEWHOPE_client_compute_key(const uint8_t* server_msg,
                                               uint8_t* msg, uint8_t* key);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#define NEWHOPE_SERVERMSG_LENGTH (((1024 * 14) / 8) + 32)
#define NEWHOPE_CLIENTMSG_LENGTH (((1024 * 14) / 8) + 1024 / 4)

#endif /* OPENSSL_HEADER_NEWHOPE_H */
