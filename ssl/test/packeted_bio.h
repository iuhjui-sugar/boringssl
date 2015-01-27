/* Copyright (c) 2014, Google Inc.
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

#ifndef HEADER_PACKETED_BIO
#define HEADER_PACKETED_BIO

#include <openssl/bio.h>
#include <openssl/ssl.h>


// packeted_bio_create creates a filter BIO for testing protocols which expect
// datagram BIOs. It implements a reliable blocking datagram socket and reads
// and writes packets. It also accepts simulated read timeouts. If a read
// timeout is simulated in |BIO_read|, |*out_timeout| set to the timeout and the
// read will fail. |*out_timeout| must be zero on entry to |BIO_read|; it is an
// error to not apply the timeout before the next |BIO_read|.
//
// Note: The read timeout simulation is intended to be used with the async BIO
// wrapper. It doesn't simulate BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, used in DTLS's
// blocking mode.
BIO *packeted_bio_create(OPENSSL_timeval *out_timeout);


#endif  // HEADER_PACKETED_BIO
