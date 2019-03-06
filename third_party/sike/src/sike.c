/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/

#include <stdint.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/base.h>
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <openssl/hmac.h>

#include "utils.h"
#include "isogeny.h"
#include "fpx.h"

extern const struct params_t p503;

// Domain separation parameters for HMAC
static const uint8_t G[2] = {0,0};
static const uint8_t H[2] = {1,0};
static const uint8_t F[2] = {2,0};

// SIDHp503_JINV_BYTESZ is a number of bytes used for encoding j-invariant.
#define SIDHp503_JINV_BYTESZ    126U
// SIDHp503_PRV_A_BITSZ is a number of bits of SIDH private key (2-isogeny)
#define SIDHp503_PRV_A_BITSZ    250U
// SIDHp503_PRV_A_BITSZ is a number of bits of SIDH private key (3-isogeny)
#define SIDHp503_PRV_B_BITSZ    253U
// MAX_INT_POINTS_ALICE is a number of points used in 2-isogeny tree computation
#define MAX_INT_POINTS_ALICE    7U
// MAX_INT_POINTS_ALICE is a number of points used in 3-isogeny tree computation
#define MAX_INT_POINTS_BOB      8U

// Produces HMAC-SHA256 of data |S| mac'ed with the key |key|. Result is stored in |out|
// which must have size of at least |outsz| bytes. The output of a HMAC may be truncated.
// SIKE implementation requires HMAC to output of 128, 192 and 256 bytes.
static inline void hmac_sum(uint8_t *out, size_t outsz, const uint8_t S[2],
    const uint8_t *key, size_t key_sz) {
    assert(outsz <= 32);
    assert(outsz >= 16);
    assert(outsz*8 > 80);

    uint8_t out_tmp[32];
    unsigned osz = 32;
    HMAC(EVP_sha256(), key, key_sz, S, 2, out_tmp, &osz);
    OPENSSL_memcpy(out, out_tmp, outsz);
}

// Swap points.
// If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
#if !defined(OPENSSL_X86_64) || defined(OPENSSL_NO_ASM)
static void cswap(point_proj_t P, point_proj_t Q, const crypto_word_t option)
{
    crypto_word_t temp;
    for (size_t i = 0; i < NWORDS_FIELD; i++) {
        temp = option & (P->X->c0[i] ^ Q->X->c0[i]);
        P->X->c0[i] = temp ^ P->X->c0[i];
        Q->X->c0[i] = temp ^ Q->X->c0[i];
        temp = option & (P->Z->c0[i] ^ Q->Z->c0[i]);
        P->Z->c0[i] = temp ^ P->Z->c0[i];
        Q->Z->c0[i] = temp ^ Q->Z->c0[i];
        temp = option & (P->X->c1[i] ^ Q->X->c1[i]);
        P->X->c1[i] = temp ^ P->X->c1[i];
        Q->X->c1[i] = temp ^ Q->X->c1[i];
        temp = option & (P->Z->c1[i] ^ Q->Z->c1[i]);
        P->Z->c1[i] = temp ^ P->Z->c1[i];
        Q->Z->c1[i] = temp ^ Q->Z->c1[i];
    }
}
#endif

// Swap points.
// If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
static inline void fp2cswap(point_proj_t P, point_proj_t Q, const crypto_word_t option)
{
#if defined(OPENSSL_X86_64) && !defined(OPENSSL_NO_ASM)
    cswap_asm(P, Q, option);
#else
    cswap(P, Q, option);
#endif
}

static void LADDER3PT(
    const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ, const crypto_word_t* m,
    int is_A, point_proj_t R, const f2elm_t A) {
    point_proj_t R0 = POINT_PROJ_INIT, R2 = POINT_PROJ_INIT;
    f2elm_t A24 = F2ELM_INIT;
    crypto_word_t mask;
    int bit, swap, prevbit = 0;

    const size_t nbits = is_A?SIDHp503_PRV_A_BITSZ:SIDHp503_PRV_B_BITSZ;

    // Initializing constant
    fpcopy((crypto_word_t*)&p503.mont_one, A24[0].c0);
    fp2add(A24, A24, A24);
    fp2add(A, A24, A24);
    fp2div2(A24, A24);
    fp2div2(A24, A24); // A24 = (A+2)/4

    // Initializing points
    fp2copy(xQ, R0->X);
    fpcopy((crypto_word_t*)&p503.mont_one, R0->Z[0].c0);
    fp2copy(xPQ, R2->X);
    fpcopy((crypto_word_t*)&p503.mont_one, R2->Z[0].c0);
    fp2copy(xP, R->X);
    fpcopy((crypto_word_t*)&p503.mont_one, R->Z[0].c0);
    OPENSSL_memset(R->Z->c1, 0, sizeof(R->Z->c1));

    // Main loop
    for (size_t i = 0; i < nbits; i++) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (crypto_word_t)swap;

        fp2cswap(R, R2, mask);
        xDBLADD(R0, R2, R->X, A24);
        fp2mul_mont(R2->X, R->Z, R2->X);
    }
}

// Initialization of basis points
static void init_basis(crypto_word_t *gen, f2elm_t XP, f2elm_t XQ, f2elm_t XR) {
    fpcopy(gen,                  XP->c0);
    fpcopy(gen +   NWORDS_FIELD, XP->c1);
    fpcopy(gen + 2*NWORDS_FIELD, XQ->c0);
    OPENSSL_memset(XQ->c1, 0, sizeof(XQ->c1));
    fpcopy(gen + 3*NWORDS_FIELD, XR->c0);
    fpcopy(gen + 4*NWORDS_FIELD, XR->c1);
}

// Conversion of GF(p^2) element from Montgomery to standard representation.
static void fp2_encode(const f2elm_t x, uint8_t *enc) {
    f2elm_t t;
    from_fp2mont(x, t);

    // convert to bytes in little endian form
    for (size_t i=0; i<FIELD_BYTESZ; i++) {
        enc[i+           0] = (t[0].c0[i/LSZ] >> (LSZ*(i%LSZ))) & 0xFF;
        enc[i+FIELD_BYTESZ] = (t[0].c1[i/LSZ] >> (LSZ*(i%LSZ))) & 0xFF;
    }
}

// Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation.
// Elements over GF(p503) are encoded in 63 octets in little endian format
// (i.e., the least significant octet is located in the lowest memory address).
static void fp2_decode(const uint8_t *enc, f2elm_t t) {
    OPENSSL_memset(t[0].c0, 0, sizeof(t[0].c0));
    OPENSSL_memset(t[0].c1, 0, sizeof(t[0].c1));
    // convert bytes in little endian form to f2elm_t
    for (size_t i = 0; i < FIELD_BYTESZ; i++) {
        t[0].c0[i/LSZ] |= ((crypto_word_t)enc[i+           0]) << (LSZ*(i%LSZ));
        t[0].c1[i/LSZ] |= ((crypto_word_t)enc[i+FIELD_BYTESZ]) << (LSZ*(i%LSZ));
    }
    to_fp2mont(t, t);
}

// Alice's ephemeral public key generation
// Input:  a private key prA in the range [0, 2^250 - 1], stored in 32 bytes.
// Output: the public key pkA consisting of 3 GF(p503^2) elements encoded in 378 bytes.
static int gen_iso_A(const uint8_t* skA, uint8_t* pkA)
{
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    point_proj_t phiP = POINT_PROJ_INIT;
    point_proj_t phiQ = POINT_PROJ_INIT;
    point_proj_t phiR = POINT_PROJ_INIT;
    f2elm_t XPA, XQA, XRA, coeff[3];
    f2elm_t A24plus = F2ELM_INIT;
    f2elm_t C24 = F2ELM_INIT;
    f2elm_t A = F2ELM_INIT;
    unsigned int m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0, ii = 0;

    // Initialize basis points
    init_basis((crypto_word_t*)p503.A_gen, XPA, XQA, XRA);
    init_basis((crypto_word_t*)p503.B_gen, phiP->X, phiQ->X, phiR->X);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiP->Z)->c0);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiQ->Z)->c0);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiR->Z)->c0);

    // Initialize constants
    fpcopy((crypto_word_t*)&p503.mont_one, A24plus->c0);
    fp2add(A24plus, A24plus, C24);

    // Retrieve kernel point
    LADDER3PT(XPA, XQA, XRA, (crypto_word_t*)skA, 1, R, A);

    // Traverse tree
    index = 0;
    for (size_t row = 1; row < A_max; row++) {
        while (index < A_max-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = p503.A_strat[ii++];
            xDBLe(R, R, A24plus, C24, (2*m));
            index += m;
        }
        get_4_isog(R, A24plus, C24, coeff);

        for (size_t i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }
        eval_4_isog(phiP, coeff);
        eval_4_isog(phiQ, coeff);
        eval_4_isog(phiR, coeff);

        fp2copy(pts[npts-1]->X, R->X);
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A24plus, C24, coeff);
    eval_4_isog(phiP, coeff);
    eval_4_isog(phiQ, coeff);
    eval_4_isog(phiR, coeff);

    inv_3_way(phiP->Z, phiQ->Z, phiR->Z);
    fp2mul_mont(phiP->X, phiP->Z, phiP->X);
    fp2mul_mont(phiQ->X, phiQ->Z, phiQ->X);
    fp2mul_mont(phiR->X, phiR->Z, phiR->X);

    // Format public key
    fp2_encode(phiP->X, pkA);
    fp2_encode(phiQ->X, pkA + SIDHp503_JINV_BYTESZ);
    fp2_encode(phiR->X, pkA + 2*SIDHp503_JINV_BYTESZ);
    return 0;
}

// Bob's ephemeral key-pair generation
// It produces a private key skB and computes the public key pkB.
// The private key is an integer in the range [0, 2^Floor(Log(2,3^159)) - 1], stored in 32 bytes.
// The public key consists of 3 GF(p503^2) elements encoded in 378 bytes.
static int gen_iso_B(const uint8_t* skB, uint8_t* pkB)
{
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    point_proj_t phiP = POINT_PROJ_INIT;
    point_proj_t phiQ = POINT_PROJ_INIT;
    point_proj_t phiR = POINT_PROJ_INIT;
    f2elm_t XPB, XQB, XRB, coeff[3];
    f2elm_t A24plus = F2ELM_INIT;
    f2elm_t A24minus = F2ELM_INIT;
    f2elm_t A = F2ELM_INIT;
    unsigned int m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;

    // Initialize basis points
    init_basis((crypto_word_t*)p503.B_gen, XPB, XQB, XRB);
    init_basis((crypto_word_t*)p503.A_gen, phiP->X, phiQ->X, phiR->X);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiP->Z)->c0);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiQ->Z)->c0);
    fpcopy((crypto_word_t*)&p503.mont_one, (phiR->Z)->c0);

    // Initialize constants
    fpcopy((crypto_word_t*)&p503.mont_one, A24plus->c0);
    fp2add(A24plus, A24plus, A24plus);
    fp2copy(A24plus, A24minus);
    fp2neg(A24minus);

    // Retrieve kernel point
    LADDER3PT(XPB, XQB, XRB, (crypto_word_t*)skB, 0, R, A);

    // Traverse tree
    index = 0;
    for (size_t row = 1; row < B_max; row++) {
        while (index < B_max-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = p503.B_strat[ii++];
            xTPLe(R, R, A24minus, A24plus, m);
            index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (size_t i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        }
        eval_3_isog(phiP, coeff);
        eval_3_isog(phiQ, coeff);
        eval_3_isog(phiR, coeff);

        fp2copy(pts[npts-1]->X, R->X);
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A24minus, A24plus, coeff);
    eval_3_isog(phiP, coeff);
    eval_3_isog(phiQ, coeff);
    eval_3_isog(phiR, coeff);

    inv_3_way(phiP->Z, phiQ->Z, phiR->Z);
    fp2mul_mont(phiP->X, phiP->Z, phiP->X);
    fp2mul_mont(phiQ->X, phiQ->Z, phiQ->X);
    fp2mul_mont(phiR->X, phiR->Z, phiR->X);

    // Format public key
    fp2_encode(phiP->X, pkB);
    fp2_encode(phiQ->X, pkB + SIDHp503_JINV_BYTESZ);
    fp2_encode(phiR->X, pkB + 2*SIDHp503_JINV_BYTESZ);
    return 0;
}

// Alice's ephemeral shared secret computation
// It produces a shared secret key ssA using her secret key skA and Bob's public key pkB
// Inputs: Alice's skA is an integer in the range [0, 2^250 - 1], stored in 32 bytes.
//         Bob's pkB consists of 3 GF(p503^2) elements encoded in 378 bytes.
// Output: a shared secret ssA that consists of one element in GF(p503^2) encoded in 126 bytes.
static int ex_iso_A(const uint8_t* skA, const uint8_t* pkB, uint8_t* ssA)
{
    point_proj_t R, pts[MAX_INT_POINTS_ALICE];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = F2ELM_INIT;
    f2elm_t C24 = F2ELM_INIT;
    f2elm_t A = F2ELM_INIT;
    unsigned int m, index = 0, pts_index[MAX_INT_POINTS_ALICE], npts = 0, ii = 0;

    // Initialize images of Bob's basis
    fp2_decode(pkB, PKB[0]);
    fp2_decode(pkB + SIDHp503_JINV_BYTESZ, PKB[1]);
    fp2_decode(pkB + 2*SIDHp503_JINV_BYTESZ, PKB[2]);

    // Initialize constants
    get_A(PKB[0], PKB[1], PKB[2], A); // TODO: Can return projective A?
    fpadd((crypto_word_t*)&p503.mont_one, (crypto_word_t*)&p503.mont_one, C24->c0);
    fp2add(A, C24, A24plus);
    fpadd(C24->c0, C24->c0, C24->c0);

    // Retrieve kernel point
    LADDER3PT(PKB[0], PKB[1], PKB[2], (crypto_word_t*)skA, 1, R, A);

    // Traverse tree
    index = 0;
    for (size_t row = 1; row < A_max; row++) {
        while (index < A_max-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = p503.A_strat[ii++];
            xDBLe(R, R, A24plus, C24, (2*m));
            index += m;
        }
        get_4_isog(R, A24plus, C24, coeff);

        for (size_t i = 0; i < npts; i++) {
            eval_4_isog(pts[i], coeff);
        }

        fp2copy(pts[npts-1]->X, R->X);
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_4_isog(R, A24plus, C24, coeff);
    fp2div2(C24, C24);
    fp2sub(A24plus, C24, A24plus);
    fp2div2(C24, C24);
    j_inv(A24plus, C24, jinv);
    fp2_encode(jinv, ssA);
    return 0;
}

// Bob's ephemeral shared secret computation
// It produces a shared secret key ssB using his secret key skB and Alice's public key pkA
// Inputs: Bob's skB is an integer in the range [0, 2^Floor(Log(2,3^159)) - 1], stored in 32 bytes.
//         Alice's pkA consists of 3 GF(p503^2) elements encoded in 378 bytes.
// Output: a shared secret ssB that consists of one element in GF(p503^2) encoded in 126 bytes.
static int ex_iso_B(const uint8_t* skB, const uint8_t* pkA, uint8_t* ssB)
{
    point_proj_t R, pts[MAX_INT_POINTS_BOB];
    f2elm_t coeff[3], PKB[3], jinv;
    f2elm_t A24plus = F2ELM_INIT;
    f2elm_t A24minus = F2ELM_INIT;
    f2elm_t A = F2ELM_INIT;
    unsigned int m, index = 0, pts_index[MAX_INT_POINTS_BOB], npts = 0, ii = 0;

    // Initialize images of Alice's basis
    fp2_decode(pkA, PKB[0]);
    fp2_decode(pkA + SIDHp503_JINV_BYTESZ, PKB[1]);
    fp2_decode(pkA + 2*SIDHp503_JINV_BYTESZ, PKB[2]);

    // Initialize constants
    get_A(PKB[0], PKB[1], PKB[2], A);
    fpadd((crypto_word_t*)&p503.mont_one, (crypto_word_t*)&p503.mont_one, A24minus->c0);
    fp2add(A, A24minus, A24plus);
    fp2sub(A, A24minus, A24minus);

    // Retrieve kernel point
    LADDER3PT(PKB[0], PKB[1], PKB[2], (crypto_word_t*)skB, 0, R, A);

    // Traverse tree
    index = 0;
    for (size_t row = 1; row < B_max; row++) {
        while (index < B_max-row) {
            fp2copy(R->X, pts[npts]->X);
            fp2copy(R->Z, pts[npts]->Z);
            pts_index[npts++] = index;
            m = p503.B_strat[ii++];
            xTPLe(R, R, A24minus, A24plus, m);
            index += m;
        }
        get_3_isog(R, A24minus, A24plus, coeff);

        for (size_t i = 0; i < npts; i++) {
            eval_3_isog(pts[i], coeff);
        }

        fp2copy(pts[npts-1]->X, R->X);
        fp2copy(pts[npts-1]->Z, R->Z);
        index = pts_index[npts-1];
        npts -= 1;
    }

    get_3_isog(R, A24minus, A24plus, coeff);
    fp2add(A24plus, A24minus, A);
    fp2add(A, A, A);
    fp2sub(A24plus, A24minus, A24plus);
    j_inv(A, A24plus, jinv);
    fp2_encode(jinv, ssB);
    return 0;
}

int SIKE_keypair(uint8_t sk[SIKEp503_PRV_BYTESZ], uint8_t pk[SIKEp503_PUB_BYTESZ]) {
    int ret = -1;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        goto end;
    }

    // Calculate private key for Alice. Needs to be in range [0, 2^0xFA - 1] and < 250 bits
    BIGNUM *bn_sidh_prv = BN_CTX_get(ctx);
    if (!bn_sidh_prv) {
        goto end;
    }

    if (!BN_rand(bn_sidh_prv, SIDHp503_PRV_B_BITSZ, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) {
        goto end;
    }

    // Convert to little endian
    if (!BN_bn2le_padded(sk, BITS_TO_BYTES(SIDHp503_PRV_B_BITSZ), bn_sidh_prv)) {
        goto end;
    }

    // Never fails
    gen_iso_B(sk, pk);

    // All good
    ret = 0;

end:
    BN_CTX_free(ctx);
    return ret;
}

void SIKE_encaps(
    uint8_t ss[SIKEp503_SS_BYTESZ],
    uint8_t ct[SIKEp503_CT_BYTESZ],
    const uint8_t pkB[SIKEp503_PUB_BYTESZ])
{
    uint8_t skA[BITS_TO_BYTES(SIDHp503_PRV_A_BITSZ)] = {0};
    uint8_t j[SIDHp503_JINV_BYTESZ] = {0};
    uint8_t h[SIKEp503_MSG_BYTESZ] = {0};
    uint8_t temp[SIKEp503_MSG_BYTESZ + SIKEp503_CT_BYTESZ] = {0};

    // Generate skA
    // skA = cSHAKE({0,1}^n || pkB), G) mod SIDHp503_PRV_A_BITSZ
    (void)RAND_bytes(temp, SIKEp503_MSG_BYTESZ);
    OPENSSL_memcpy(&temp[SIKEp503_MSG_BYTESZ], pkB, SIKEp503_PUB_BYTESZ);
    hmac_sum(skA, sizeof(skA), G, temp, SIKEp503_MSG_BYTESZ + SIKEp503_PUB_BYTESZ);
    skA[sizeof(skA) - 1] &= (1 << (SIDHp503_PRV_A_BITSZ%8)) - 1;

    // Generate pkA, first part of ciphertext
    gen_iso_A(skA, ct);

    // Generate c1: h = cSHAKE(j-invariant(skA, pkB), F); c1 = h ^ m
    ex_iso_A(skA, pkB, j);
    hmac_sum(h, sizeof(h), F, j, sizeof(j));

    // c1 = h ^ m
    uint8_t *c1 = &ct[SIKEp503_PUB_BYTESZ];
    for (size_t i = 0; i < sizeof(h); i++) {
        c1[i] = temp[i] ^ h[i];
    }

    // Generate shared secret ss = cSHAKE(m||ct, F)
    OPENSSL_memcpy(&temp[SIKEp503_MSG_BYTESZ], ct, SIKEp503_CT_BYTESZ);
    hmac_sum(ss, SIKEp503_SS_BYTESZ, H, temp, SIKEp503_MSG_BYTESZ+SIKEp503_CT_BYTESZ);
}

void SIKE_decaps(
    uint8_t ss[SIKEp503_SS_BYTESZ],
    const uint8_t ct[SIKEp503_CT_BYTESZ],
    const uint8_t pkB[SIKEp503_PUB_BYTESZ],
    const uint8_t skB[SIKEp503_PRV_BYTESZ])
{
    uint8_t j[SIDHp503_JINV_BYTESZ] = {0};
    uint8_t h[SIKEp503_MSG_BYTESZ] = {0};
    uint8_t c0[SIKEp503_PUB_BYTESZ] = {0};
    uint8_t skA[BITS_TO_BYTES(SIDHp503_PRV_A_BITSZ)] = {0};
    uint8_t temp[SIKEp503_CT_BYTESZ + SIKEp503_MSG_BYTESZ] = {0};
    uint8_t shared_nok[SIKEp503_CT_BYTESZ + SIKEp503_MSG_BYTESZ] = {0};

    (void)RAND_bytes(shared_nok, SIKEp503_MSG_BYTESZ);

    // Recover m
    // Let ct = c0 || c1 - both have fixed sizes
    // m = F(j-invariant(c0, skB)) ^ c1
    ex_iso_B(skB, ct, j);
    hmac_sum(h, sizeof(h), F, j, sizeof(j));

    const uint8_t *c1 = &ct[sizeof(c0)];
    for (size_t i = 0; i < sizeof(h); i++) {
        temp[i] = c1[i] ^ h[i];
    }

    // Recover skA = G(m||pkB) mod
    OPENSSL_memcpy(&temp[SIKEp503_MSG_BYTESZ], pkB, SIKEp503_PUB_BYTESZ);
    hmac_sum(skA, sizeof(skA), G, temp, SIKEp503_MSG_BYTESZ + SIKEp503_PUB_BYTESZ);
    skA[sizeof(skA) - 1] &= (1 << (SIDHp503_PRV_A_BITSZ%8)) - 1;

    // Recover c0 = public key A
    gen_iso_A(skA, c0);
    crypto_word_t ok = constant_time_is_zero_w(CRYPTO_memcmp(c0, ct, SIKEp503_PUB_BYTESZ));
    for (size_t i=0; i<SIKEp503_MSG_BYTESZ; i++) {
        temp[i] = constant_time_select_8(ok, temp[i], shared_nok[i]);
    }

    OPENSSL_memcpy(&temp[SIKEp503_MSG_BYTESZ], ct, SIKEp503_CT_BYTESZ);
    hmac_sum(ss, SIKEp503_SS_BYTESZ, H, temp, sizeof(temp));
}
