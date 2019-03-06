/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: API header file for SIKE
*********************************************************************************************/

#ifndef SIKE_H_
#define SIKE_H_

#include <stdint.h>
#include <openssl/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SIKEp503
 *
 * SIKE is a isogeny based post-quantum key encapsulation mechanism. Description of the
 * algorithm is provided in [SIKE]. This implementation uses 503-bit field size. The code
 * is based on "Additional_Implementations" from PQC NIST submission package which can
 * be found here:
 * https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/SIKE.zip
 *
 * [SIKE] https://sike.org/files/SIDH-spec.pdf
 */

// SIKEp503_PUB_BYTESZ is the number of bytes in a public key.
#define SIKEp503_PUB_BYTESZ 378
// SIKEp503_PRV_BYTESZ is the number of bytes in a private key.
#define SIKEp503_PRV_BYTESZ 32
// SIKEp503_SS_BYTESZ is the number of bytes in a shared key.
#define SIKEp503_SS_BYTESZ  16
// SIKEp503_MSG_BYTESZ is the number of bytes in a random bit string concatenated
// with the public key (see 1.4 of SIKE).
#define SIKEp503_MSG_BYTESZ 24
// SIKEp503_SS_BYTESZ is the number of bytes in a ciphertext.
#define SIKEp503_CT_BYTESZ  (SIKEp503_PUB_BYTESZ + SIKEp503_MSG_BYTESZ)

// SIKE_keypair outputs a public and secret key. Internally it uses BN_rand() as
// a entropy source. In case of success function returns 0, otherwise negative
// value.s
OPENSSL_EXPORT int SIKE_keypair(
    uint8_t sk[SIKEp503_PRV_BYTESZ],
    uint8_t pk[SIKEp503_PUB_BYTESZ]);

// SIKE_encaps is a encapsulation function of a SIKE key encapsulation mechnism used to
// fix random session key. It writes ephemeral session key to the |ss| and ciphertext
// to |ct|.
OPENSSL_EXPORT void SIKE_encaps(
    uint8_t ss[SIKEp503_SS_BYTESZ],
    uint8_t ct[SIKEp503_CT_BYTESZ],
    const uint8_t pk[SIKEp503_PUB_BYTESZ]);

// SIKE_decaps is a decapsulation function of a SIKE key encapsulation mechnism used
// by possessor of secret key |sk| and corresponding public key |pk| to decapsulate
// ciphertext |ct| in order to get session key written to |ss|.
OPENSSL_EXPORT void SIKE_decaps(
    uint8_t ss[SIKEp503_SS_BYTESZ],
    const uint8_t ct[SIKEp503_CT_BYTESZ],
    const uint8_t pk[SIKEp503_PUB_BYTESZ],
    const uint8_t sk[SIKEp503_PRV_BYTESZ]);

#ifdef __cplusplus
}
#endif

#endif
