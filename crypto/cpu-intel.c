/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

#include <openssl/cpu.h>


#if !defined(OPENSSL_NO_ASM) && (defined(OPENSSL_X86) || defined(OPENSSL_X86_64))

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if defined(OPENSSL_WINDOWS)
#include <immintrin.h>
#include <intrin.h>
#endif


#define INDEX_EAX 0
#define INDEX_EBX 1
#define INDEX_ECX 2
#define INDEX_EDX 3

#if !defined(OPENSSL_WINDOWS)
/* __cpuid runs the cpuid instruction. |info_type| is passed in as EAX and ECX
 * is set to zero. It writes EAX, EBX, ECX, and EDX to |out_cpu_info|, in that
 * order. */
void __cpuid(uint32_t out_cpu_info[4], uint32_t info_type) {
#if defined(__pic__) && defined(__i386__)
  __asm__ volatile (
    "xor %%ecx, %%ecx\n"
    "mov %%ebx, %%edi\n"
    "cpuid\n"
    "xchg %%edi, %%ebx\n"
    : "=a"(out_cpu_info[0]), "=D"(out_cpu_info[1]), "=c"(out_cpu_info[2]),
      "=d"(out_cpu_info[3])
    : "a"(info_type)
  );
#else
  __asm__ volatile (
    "xor %%ecx, %%ecx\n"
    "cpuid\n"
    : "=a"(out_cpu_info[0]), "=b"(out_cpu_info[1]), "=c"(out_cpu_info[2]),
      "=d"(out_cpu_info[3])
    : "a"(info_type)
  );
#endif
}

/* _xgetbv returns the value of an Intel Extended Control Register (XCR).
 * Currently only XCR0 is defined by Intel so |xcr| should always be zero. */
uint64_t _xgetbv(uint32_t xcr) {
  uint32_t eax, edx;

  __asm__ volatile ("xgetbv" : "=a"(eax), "=d"(edx) : "c"(xcr));
  return (((uint64_t)edx) << 32) | eax;
}
#endif /* !OPENSSL_WINDOWS */

/* handle_cpu_env applies the value from |in| to the CPUID values in |out[0]|
 * and |out[1]|. See the comment in |OPENSSL_cpuid_setup| about this. */
static void handle_cpu_env(uint32_t *out, const char *in) {
  const int invert = in[0] == '~';
  uint64_t v;

  if (!sscanf(in + invert, "%" PRIi64, &v)) {
    return;
  }

  if (invert) {
    out[0] &= ~v;
    out[1] &= ~(v >> 32);
  } else {
    out[0] = v;
    out[1] = v >> 32;
  }
}

void OPENSSL_cpuid_setup(void) {
  /* Determine the vendor and maximum input value. */
  uint32_t cpu_info[4];
  __cpuid(cpu_info, 0);

  uint32_t num_ids = cpu_info[INDEX_EAX];

  int is_intel = cpu_info[INDEX_EBX] == 0x756e6547 /* Genu */ &&
                 cpu_info[INDEX_EDX] == 0x49656e69 /* ineI */ &&
                 cpu_info[INDEX_ECX] == 0x6c65746e /* ntel */;
  int is_amd = cpu_info[INDEX_EBX] == 0x68747541 /* Auth */ &&
               cpu_info[INDEX_EDX] == 0x69746e65 /* enti */ &&
               cpu_info[INDEX_ECX] == 0x444d4163 /* cAMD */;

  int has_amd_xop = 0;
  if (is_amd) {
    /* AMD-specific logic.
     * See http://developer.amd.com/wordpress/media/2012/10/254811.pdf */
    __cpuid(cpu_info, 0x80000000);
    uint32_t num_extended_ids = cpu_info[INDEX_EAX];
    if (num_extended_ids >= 0x80000001) {
      __cpuid(cpu_info, 0x80000001);
      if (cpu_info[INDEX_ECX] & (1 << 11)) {
        has_amd_xop = 1;
      }
    }
  }

  uint32_t extended_features = 0;
  if (num_ids >= 7) {
    __cpuid(cpu_info, 7);
    extended_features = cpu_info[INDEX_EBX];
  }

  /* Determine the number of cores sharing an L1 data cache to adjust the
   * hyper-threading bit. */
  uint32_t cores_per_cache = 0;
  if (is_amd) {
    /* AMD CPUs never share an L1 data cache between threads but do set the HTT
     * bit on multi-core CPUs. */
    cores_per_cache = 1;
  } else if (num_ids >= 4) {
    /* TODO(davidben): The Intel manual says this CPUID leaf enumerates all
     * caches using ECX and doesn't say which is first. Does this matter? */
    __cpuid(cpu_info, 4);
    cores_per_cache = 1 + ((cpu_info[INDEX_EAX] >> 14) & 0xfff);
  }

  __cpuid(cpu_info, 1);

  /* Adjust the hyper-threading bit. */
  if (cpu_info[INDEX_EDX] & (1 << 28)) {
    uint32_t num_logical_cores = (cpu_info[INDEX_EBX] >> 16) & 0xff;
    if (cores_per_cache == 1 || num_logical_cores <= 1) {
      cpu_info[INDEX_EDX] &= ~(1 << 28);
    }
  }

  /* Reserved bit #20 was historically repurposed to control the in-memory
   * representation of RC4 state. Always set it to zero. */
  cpu_info[INDEX_EDX] &= ~(1 << 20);

  /* Reserved bit #30 is repurposed to signal an Intel CPU. */
  if (is_intel) {
    cpu_info[INDEX_EDX] |= (1 << 30);
  } else {
    cpu_info[INDEX_EDX] &= ~(1 << 30);
  }

  /* The SDBG bit is repurposed to denote AMD XOP support. */
  if (has_amd_xop) {
    cpu_info[INDEX_ECX] |= (1 << 11);
  } else {
    cpu_info[INDEX_ECX] &= ~(1 << 11);
  }

  uint64_t xcr0 = 0;
  if (cpu_info[INDEX_ECX] & (1 << 27)) {
    /* XCR0 may only be queried if the OSXSAVE bit is set. */
    xcr0 = _xgetbv(0);
  }
  /* TODO(davidben): Should this just be xcr0 & 4? */
  if ((xcr0 & 6) != 6) {
    /* YMM registers cannot be used. */
    cpu_info[INDEX_ECX] &= ~(1 << 28); /* AVX */
    cpu_info[INDEX_ECX] &= ~(1 << 12); /* FMA */
    cpu_info[INDEX_ECX] &= ~(1 << 11); /* AMD XOP */
    extended_features &= ~(1 << 5); /* AVX2 */
  }

  /* TODO(davidben): Should all the XMM-using instructions preadjust for the
   * FXSR bit? Notably, e_aes.c doesn't check it. */

  OPENSSL_ia32cap_P[0] = cpu_info[INDEX_EDX];
  OPENSSL_ia32cap_P[1] = cpu_info[INDEX_ECX];
  OPENSSL_ia32cap_P[2] = extended_features;
  OPENSSL_ia32cap_P[3] = 0;

  const char *env1, *env2;
  env1 = getenv("OPENSSL_ia32cap");
  if (env1 == NULL) {
    return;
  }

  /* OPENSSL_ia32cap can contain zero, one or two values, separated with a ':'.
   * Each value is a 64-bit, unsigned value which may start with "0x" to
   * indicate a hex value. Prior to the 64-bit value, a '~' may be given.
   *
   * If '~' isn't present, then the value is taken as the result of the CPUID.
   * Otherwise the value is inverted and ANDed with the probed CPUID result.
   *
   * The first value determines OPENSSL_ia32cap_P[0] and [1]. The second [2]
   * and [3]. */

  handle_cpu_env(&OPENSSL_ia32cap_P[0], env1);
  env2 = strchr(env1, ':');
  if (env2 != NULL) {
    handle_cpu_env(&OPENSSL_ia32cap_P[2], env2 + 1);
  }
}

#endif  /* !OPENSSL_NO_ASM && (OPENSSL_X86 || OPENSSL_X86_64) */
