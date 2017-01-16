
#include <openssl/poly1305.h>

#if defined(OPENSSL_X86_64) && !defined(OPENSSL_NO_ASM)

#include <string.h>

#include "../internal.h"
#include "internal.h"

struct poly1305_state_st {
  uint8_t opaque[8*8];
  uint8_t buf[16];
  unsigned int buf_used;
};


extern void poly1305_init_x64(struct poly1305_state_st* state,
                              const uint8_t key[32]);
extern void poly1305_update_x64(struct poly1305_state_st* state,
                                const uint8_t *in, size_t in_len);
extern void poly1305_finish_x64(struct poly1305_state_st* state,
                                uint8_t mac[16]);


void CRYPTO_poly1305_init_x86(poly1305_state *state, const uint8_t key[32]) {
  struct poly1305_state_st *st= (struct poly1305_state_st *)state;
  st->buf_used = 0;
  return poly1305_init_x64(st, key);
}


void CRYPTO_poly1305_update_x86(poly1305_state *state, const uint8_t *in,
                                size_t in_len) {

  struct poly1305_state_st *st = (struct poly1305_state_st *)(state);
  size_t todo;
    /* Attempt to fill as many bytes as possible before calling the update
       function */
  if (in_len < 16 || st->buf_used) {
    todo = 16 - st->buf_used;
    todo = in_len < todo ? in_len : todo;
    OPENSSL_memcpy(st->buf + st->buf_used, in, todo);
    st->buf_used += todo;
    in += todo;
    in_len -= todo;

    if (st->buf_used == 16) {
      poly1305_update_x64(st, st->buf, 16);
      st->buf_used = 0;
    }
  }

  if (in_len >= 16) {
    poly1305_update_x64(st, in, in_len & (-16));
    in += in_len & (-16);
    in_len &= (15);
  }

  if (in_len) {
    OPENSSL_memcpy(st->buf, in, in_len);
    st->buf_used = in_len;
  }
}

void CRYPTO_poly1305_finish_x86(poly1305_state *state, uint8_t mac[16]) {
  struct poly1305_state_st *st = (struct poly1305_state_st *)state;

  if (st->buf_used) {
    if (st->buf_used % 16) {
      OPENSSL_memset(st->buf + st->buf_used, 0, 16 - (st->buf_used % 16));
    }
    poly1305_update_x64(st, st->buf, st->buf_used);
  }

  poly1305_finish_x64(st, mac);
	/* zero out the state */
  OPENSSL_memset(st, 0, sizeof(*st));
}
#endif
