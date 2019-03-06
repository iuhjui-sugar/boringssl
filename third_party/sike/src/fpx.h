#ifndef FPX_H_
#define FPX_H_

#include "utils.h"

// Modular addition, c = a+b mod p503.
void fpadd(const felm_t a, const felm_t b, felm_t c);
// Modular subtraction, c = a-b mod p503.
void fpsub(const felm_t a, const felm_t b, felm_t c);
// Modular division by two, c = a/2 mod p503.
void fpdiv2(const felm_t a, felm_t c);
// Modular correction to reduce field element a in [0, 2*p503-1] to [0, p503-1].
void fpcorrection(felm_t a);
// Multiprecision multiply, c = a*b, where lng(a) = lng(b) = nwords.
void mp_mul(const felm_t a, const felm_t b, dfelm_t c);
// 503-bit Montgomery reduction, c = a mod p
void rdc_mont(const dfelm_t a, felm_t c);
// Modular negation, a = -a mod p503.
void fpneg(felm_t a);
// Copy of a field element, c = a
void fpcopy(const felm_t a, felm_t c);
// Copy a field element, c = a.
void fpzero(felm_t a);
// If option = 0xFF...FF x=y; y=x, otherwise swap doesn't happen. Constant time.
void cswap_asm(point_proj_t x, point_proj_t y, const crypto_word_t option);
// GF(p503^2) multiplication using Montgomery arithmetic, c = a*b in GF(p503^2)
void fp2mul_mont(const f2elm_t a, const f2elm_t b, f2elm_t c);
// GF(p503^2) inversion using Montgomery arithmetic, a = (a0-i*a1)/(a0^2+a1^2)
void fp2inv_mont(f2elm_t a);
// GF(p^2) squaring using Montgomery arithmetic, c = a^2 in GF(p^2).
void fp2sqr_mont(const f2elm_t a, f2elm_t c);
// Modular correction, a = a in GF(p^2).
void fp2correction(f2elm_t a);
// Conversion from Montgomery representation to standard representation,
// c = ma*R^(-1) mod p = a mod p, where ma in [0, p-1].
void from_mont(const felm_t ma, felm_t c);
// Field multiplication using Montgomery arithmetic, c = a*b*R^-1 mod p503, where R=2^768
void fpmul_mont(const felm_t ma, const felm_t mb, felm_t mc);

// GF(p^2) addition, c = a+b in GF(p^2).
#define fp2add(a, b, c)             \
do {                                \
    fpadd(a->c0, b->c0, c->c0);     \
    fpadd(a->c1, b->c1, c->c1);     \
} while(0)

// GF(p^2) subtraction, c = a-b in GF(p^2).
#define fp2sub(a,b,c)               \
do {                                \
    fpsub(a->c0, b->c0, c->c0);     \
    fpsub(a->c1, b->c1, c->c1);     \
} while(0)

// Copy a GF(p^2) element, c = a.
#define fp2copy(a, c)               \
do {                                \
    fpcopy(a->c0, c->c0);           \
    fpcopy(a->c1, c->c1);           \
} while(0)

// GF(p^2) negation, a = -a in GF(p^2).
#define fp2neg(a)                   \
do {                                \
    fpneg(a->c0);                   \
    fpneg(a->c1);                   \
} while(0)

// GF(p^2) division by two, c = a/2  in GF(p^2).
#define fp2div2(a, c)               \
do {                                \
    fpdiv2(a->c0, c->c0);           \
    fpdiv2(a->c1, c->c1);           \
} while(0)

// Modular correction, a = a in GF(p^2).
#define fp2correction(a)            \
do {                                \
    fpcorrection(a->c0);            \
    fpcorrection(a->c1);            \
} while(0)

// Conversion of a GF(p^2) element to Montgomery representation,
// mc_i = a_i*R^2*R^(-1) = a_i*R in GF(p^2).
#define to_fp2mont(a, mc)           \
do {                                \
    fpmul_mont(a->c0, (crypto_word_t*)&p503.mont_R2, mc->c0);   \
    fpmul_mont(a->c1, (crypto_word_t*)&p503.mont_R2, mc->c1);   \
} while(0)

// Conversion of a GF(p^2) element from Montgomery representation to standard representation,
// c_i = ma_i*R^(-1) = a_i in GF(p^2).
#define from_fp2mont(ma, c)         \
do {                                \
    from_mont(ma->c0, c->c0);       \
    from_mont(ma->c1, c->c1);       \
} while(0)

#endif // FPX_H_
