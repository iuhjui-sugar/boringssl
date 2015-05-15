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

#include <openssl/bytestring.h>

#include <string.h>

#include "internal.h"


/* kMaxDepth is a just a sanity limit. The code should be such that the length
 * of the input being processes always decreases. None the less, a very large
 * input could otherwise cause the stack to overflow. */
static const unsigned kMaxDepth = 2048;

/* cbs_find_ber walks an ASN.1 structure in |orig_in| and sets |*ber_found|
 * depending on whether an indefinite length element was found. The value of
 * |in| is not changed. It returns one on success (i.e. |*ber_found| was set)
 * and zero on error. */
static int cbs_find_ber(CBS *orig_in, char *ber_found, unsigned depth) {
  CBS in;

  if (depth > kMaxDepth) {
    return 0;
  }

  CBS_init(&in, CBS_data(orig_in), CBS_len(orig_in));
  *ber_found = 0;

  while (CBS_len(&in) > 0) {
    CBS contents;
    unsigned tag;
    size_t header_len;

    if (!CBS_get_any_asn1_element(&in, &contents, &tag, &header_len)) {
      return 0;
    }
    if (CBS_len(&contents) == header_len &&
        header_len > 0 &&
        CBS_data(&contents)[header_len-1] == 0x80) {
      *ber_found = 1;
      return 1;
    }
    if (tag & CBS_ASN1_CONSTRUCTED) {
      if (!CBS_skip(&contents, header_len) ||
          !cbs_find_ber(&contents, ber_found, depth + 1)) {
        return 0;
      }
    }
  }

  return 1;
}

/* is_primitive_type returns true if |tag| likely a primitive type. Normally
 * one can just test the "constructed" bit in the tag but, in BER, even
 * primitive tags can have the constructed bit if they have indefinite
 * length. */
static char is_primitive_type(unsigned tag) {
  return (tag & 0xc0) == 0 &&
         (tag & 0x1f) != (CBS_ASN1_SEQUENCE & 0x1f) &&
         (tag & 0x1f) != (CBS_ASN1_SET & 0x1f);
}

/* is_eoc returns true if |header_len| and |contents|, as returned by
 * |CBS_get_any_asn1_element|, indicate an "end of contents" (EOC) value. */
static char is_eoc(size_t header_len, CBS *contents) {
  return header_len == 2 && CBS_len(contents) == 2 &&
         memcmp(CBS_data(contents), "\x00\x00", 2) == 0;
}

/* cbs_convert_ber reads BER data from |in| and writes DER data to |out|. If
 * |squash_header| is set then the top-level of elements from |in| will not
 * have their headers written. This is used when concatenating the fragments of
 * an indefinite length, primitive value. If |looking_for_eoc| is set then any
 * EOC elements found will cause the function to return after consuming it.
 * It returns one on success and zero on error. */
static int cbs_convert_ber(CBS *in, CBB *out, char squash_header,
                           char looking_for_eoc, unsigned depth) {
  if (depth > kMaxDepth) {
    return 0;
  }

  while (CBS_len(in) > 0) {
    CBS contents;
    unsigned tag;
    size_t header_len;
    CBB *out_contents, out_contents_storage;

    if (!CBS_get_any_asn1_element(in, &contents, &tag, &header_len)) {
      return 0;
    }
    out_contents = out;

    if (CBS_len(&contents) == header_len) {
      if (is_eoc(header_len, &contents)) {
        return looking_for_eoc;
      }

      if (header_len > 0 && CBS_data(&contents)[header_len - 1] == 0x80) {
        /* This is an indefinite length element. If it's a SEQUENCE or SET then
         * we just need to write the out the contents as normal, but with a
         * concrete length prefix.
         *
         * If it's a something else then the contents will be a series of BER
         * elements of the same type which need to be concatenated. */
        const char context_specific = (tag & 0xc0) == 0x80;
        char squash_child_headers = is_primitive_type(tag);

        /* This is a hack, but it sufficies to handle NSS's output. If we find
         * an indefinite length, context-specific tag with a definite, primtive
         * tag inside it, then we assume that the context-specific tag is
         * implicit and the tags within are fragments of a primitive type that
         * need to be concatenated. */
        if (context_specific && (tag & CBS_ASN1_CONSTRUCTED)) {
          CBS in_copy, inner_contents;
          unsigned inner_tag;
          size_t inner_header_len;

          CBS_init(&in_copy, CBS_data(in), CBS_len(in));
          if (!CBS_get_any_asn1_element(&in_copy, &inner_contents, &inner_tag,
                                        &inner_header_len)) {
            return 0;
          }
          if (CBS_len(&inner_contents) > inner_header_len &&
              is_primitive_type(inner_tag)) {
            squash_child_headers = 1;
          }
        }

        if (!squash_header) {
          unsigned out_tag = tag;
          if (squash_child_headers) {
            out_tag &= ~CBS_ASN1_CONSTRUCTED;
          }
          if (!CBB_add_asn1(out, &out_contents_storage, out_tag)) {
            return 0;
          }
          out_contents = &out_contents_storage;
        }

        if (!cbs_convert_ber(in, out_contents,
                             squash_child_headers,
                             1 /* looking for eoc */, depth + 1)) {
          return 0;
        }
        if (out_contents != out && !CBB_flush(out)) {
          return 0;
        }
        continue;
      }
    }

    if (!squash_header) {
      if (!CBB_add_asn1(out, &out_contents_storage, tag)) {
        return 0;
      }
      out_contents = &out_contents_storage;
    }

    if (!CBS_skip(&contents, header_len)) {
      return 0;
    }

    if (tag & CBS_ASN1_CONSTRUCTED) {
      if (!cbs_convert_ber(&contents, out_contents, 0 /* don't squash header */,
                           0 /* not looking for eoc */, depth + 1)) {
        return 0;
      }
    } else {
      if (!CBB_add_bytes(out_contents, CBS_data(&contents),
                         CBS_len(&contents))) {
        return 0;
      }
    }

    if (out_contents != out && !CBB_flush(out)) {
      return 0;
    }
  }

  return looking_for_eoc == 0;
}

int CBS_asn1_ber_to_der(CBS *in, uint8_t **out, size_t *out_len) {
  CBB cbb;

  /* First, do a quick walk to find any indefinite-length elements. Most of the
   * time we hope that there aren't any and thus we can quickly return. */
  char conversion_needed;
  if (!cbs_find_ber(in, &conversion_needed, 0)) {
    return 0;
  }

  if (!conversion_needed) {
    *out = NULL;
    *out_len = 0;
    return 1;
  }

  if (!CBB_init(&cbb, CBS_len(in))) {
    return 0;
  }
  if (!cbs_convert_ber(in, &cbb, 0, 0, 0)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  return CBB_finish(&cbb, out, out_len);
}
