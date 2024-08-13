// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <openssl/asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && defined(__APPLE__)
.section	__DATA,__const
.p2align	6


L$bswap_mask:
.octa	0x000102030405060708090a0b0c0d0e0f








L$gfpoly:
.octa	0xc2000000000000000000000000000001


L$gfpoly_and_internal_carrybit:
.octa	0xc2000000000000010000000000000001





L$ctr_pattern:
.octa	0
.octa	1
L$inc_2blocks:
.octa	2
.octa	3
L$inc_4blocks:
.octa	4

.text	
.globl	_gcm_init_vpclmulqdq_avx10
.private_extern _gcm_init_vpclmulqdq_avx10

.p2align	5
_gcm_init_vpclmulqdq_avx10:


_CET_ENDBR

	leaq	256-32(%rdi),%r8



	vmovq	8(%rsi),%xmm3
	vpinsrq	$1,(%rsi),%xmm3,%xmm3
















	vpshufd	$0xd3,%xmm3,%xmm0
	vpsrad	$31,%xmm0,%xmm0
	vpaddq	%xmm3,%xmm3,%xmm3
	vpand	L$gfpoly_and_internal_carrybit(%rip),%xmm0,%xmm0
	vpxor	%xmm0,%xmm3,%xmm3


	vbroadcasti32x4	L$gfpoly(%rip),%ymm5








	vpclmulqdq	$0x00,%xmm3,%xmm3,%xmm0
	vpclmulqdq	$0x01,%xmm3,%xmm3,%xmm1
	vpclmulqdq	$0x10,%xmm3,%xmm3,%xmm2
	vpxord	%xmm2,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm0,%xmm5,%xmm2
	vpshufd	$0x4e,%xmm0,%xmm0
	vpternlogd	$0x96,%xmm2,%xmm0,%xmm1
	vpclmulqdq	$0x11,%xmm3,%xmm3,%xmm4
	vpclmulqdq	$0x01,%xmm1,%xmm5,%xmm0
	vpshufd	$0x4e,%xmm1,%xmm1
	vpternlogd	$0x96,%xmm0,%xmm1,%xmm4



	vinserti128	$1,%xmm3,%ymm4,%ymm3
	vinserti128	$1,%xmm4,%ymm4,%ymm4

	vmovdqu8	%ymm3,(%r8)





	movl	$7,%eax
L$precompute_next1:
	subq	$32,%r8
	vpclmulqdq	$0x00,%ymm4,%ymm3,%ymm0
	vpclmulqdq	$0x01,%ymm4,%ymm3,%ymm1
	vpclmulqdq	$0x10,%ymm4,%ymm3,%ymm2
	vpxord	%ymm2,%ymm1,%ymm1
	vpclmulqdq	$0x01,%ymm0,%ymm5,%ymm2
	vpshufd	$0x4e,%ymm0,%ymm0
	vpternlogd	$0x96,%ymm2,%ymm0,%ymm1
	vpclmulqdq	$0x11,%ymm4,%ymm3,%ymm3
	vpclmulqdq	$0x01,%ymm1,%ymm5,%ymm0
	vpshufd	$0x4e,%ymm1,%ymm1
	vpternlogd	$0x96,%ymm0,%ymm1,%ymm3

	vmovdqu8	%ymm3,(%r8)
	decl	%eax
	jnz	L$precompute_next1

	vzeroupper
	ret



.globl	_aes_gcm_enc_update_vaes_avx10_256
.private_extern _aes_gcm_enc_update_vaes_avx10_256

.p2align	5
_aes_gcm_enc_update_vaes_avx10_256:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12
#ifdef BORINGSSL_DISPATCH_TEST

	movb	$1,_BORINGSSL_function_hit+6(%rip)
#endif

	vbroadcasti32x4	L$bswap_mask(%rip),%ymm8
	vbroadcasti32x4	L$gfpoly(%rip),%ymm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%ymm12
	vpshufb	%ymm8,%ymm12,%ymm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%ymm13
	vbroadcasti32x4	(%r11),%ymm14


	vpaddd	L$ctr_pattern(%rip),%ymm12,%ymm12
	vbroadcasti32x4	L$inc_2blocks(%rip),%ymm11


	cmpq	$128,%rdx
	jb	L$crypt_loop_4x_done1


	vmovdqu8	256-128(%r9),%ymm27
	vmovdqu8	256-96(%r9),%ymm28
	vmovdqu8	256-64(%r9),%ymm29
	vmovdqu8	256-32(%r9),%ymm30




	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	leaq	16(%rcx),%rax
L$vaesenc_4x_loop_1_1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_4x_loop_1_1
	vpxord	0(%rdi),%ymm14,%ymm20
	vpxord	32(%rdi),%ymm14,%ymm21
	vpxord	64(%rdi),%ymm14,%ymm22
	vpxord	96(%rdi),%ymm14,%ymm23
	vaesenclast	%ymm20,%ymm0,%ymm4
	vaesenclast	%ymm21,%ymm1,%ymm5
	vaesenclast	%ymm22,%ymm2,%ymm6
	vaesenclast	%ymm23,%ymm3,%ymm7
	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)
	addq	$128,%rdi
	addq	$128,%rsi
	subq	$128,%rdx
	cmpq	$128,%rdx
	jb	L$ghash_last_ciphertext_4x1

	vbroadcasti32x4	-144(%r11),%ymm15

	vbroadcasti32x4	-128(%r11),%ymm16

	vbroadcasti32x4	-112(%r11),%ymm17

	vbroadcasti32x4	-96(%r11),%ymm18

	vbroadcasti32x4	-80(%r11),%ymm19
L$crypt_loop_4x1:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	cmpl	$24,%r10d
	jl	L$aes128_1
	je	L$aes192_1

	vbroadcasti32x4	-208(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-192(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes192_1:
	vbroadcasti32x4	-176(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-160(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes128_1:
	vpxord	0(%rdi),%ymm14,%ymm20
	vpxord	32(%rdi),%ymm14,%ymm21
	vpxord	64(%rdi),%ymm14,%ymm22
	vpxord	96(%rdi),%ymm14,%ymm23
	vaesenc	%ymm15,%ymm0,%ymm0
	vaesenc	%ymm15,%ymm1,%ymm1
	vaesenc	%ymm15,%ymm2,%ymm2
	vaesenc	%ymm15,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6

	vaesenc	%ymm16,%ymm0,%ymm0
	vaesenc	%ymm16,%ymm1,%ymm1
	vaesenc	%ymm16,%ymm2,%ymm2
	vaesenc	%ymm16,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25

	vaesenc	%ymm17,%ymm0,%ymm0
	vaesenc	%ymm17,%ymm1,%ymm1
	vaesenc	%ymm17,%ymm2,%ymm2
	vaesenc	%ymm17,%ymm3,%ymm3

	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24

	vaesenc	%ymm18,%ymm0,%ymm0
	vaesenc	%ymm18,%ymm1,%ymm1
	vaesenc	%ymm18,%ymm2,%ymm2
	vaesenc	%ymm18,%ymm3,%ymm3

	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25

	vaesenc	%ymm19,%ymm0,%ymm0
	vaesenc	%ymm19,%ymm1,%ymm1
	vaesenc	%ymm19,%ymm2,%ymm2
	vaesenc	%ymm19,%ymm3,%ymm3

	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26

	vbroadcasti32x4	-64(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24

	vbroadcasti32x4	-48(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6

	vbroadcasti32x4	-32(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25

	vbroadcasti32x4	-16(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10

	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10





	vaesenclast	%ymm20,%ymm0,%ymm4
	vaesenclast	%ymm21,%ymm1,%ymm5
	vaesenclast	%ymm22,%ymm2,%ymm6
	vaesenclast	%ymm23,%ymm3,%ymm7


	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)

	addq	$128,%rdi
	addq	$128,%rsi
	subq	$128,%rdx
	cmpq	$128,%rdx
	jae	L$crypt_loop_4x1
L$ghash_last_ciphertext_4x1:
	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6
	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25
	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24
	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25
	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24
	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6
	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25
	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10
	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10

L$crypt_loop_4x_done1:

	testq	%rdx,%rdx
	jz	L$done1




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$32,%rdx
	jb	L$partial_vec1

L$crypt_loop_1x1:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_1_1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_1_1
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi)


	vmovdqu8	(%r8),%ymm30
	vpshufb	%ymm8,%ymm0,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$32,%r8
	addq	$32,%rdi
	addq	$32,%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	L$crypt_loop_1x1

	testq	%rdx,%rdx
	jz	L$reduce1

L$partial_vec1:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k2


	vpshufb	%ymm8,%ymm12,%ymm0
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_2_1:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_2_1
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1{%k1}{z}
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi){%k1}













	vmovdqu8	(%r8),%ymm30{%k2}{z}
	vmovdqu8	%ymm0,%ymm1{%k1}{z}
	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6


L$reduce1:

	vpclmulqdq	$0x01,%ymm4,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm0,%ymm4,%ymm5
	vpclmulqdq	$0x01,%ymm5,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm5,%ymm5
	vpternlogd	$0x96,%ymm0,%ymm5,%ymm6

	vextracti32x4	$1,%ymm6,%xmm0
	vpxord	%xmm0,%xmm6,%xmm10


L$done1:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_aes_gcm_dec_update_vaes_avx10_256
.private_extern _aes_gcm_dec_update_vaes_avx10_256

.p2align	5
_aes_gcm_dec_update_vaes_avx10_256:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12

	vbroadcasti32x4	L$bswap_mask(%rip),%ymm8
	vbroadcasti32x4	L$gfpoly(%rip),%ymm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%ymm12
	vpshufb	%ymm8,%ymm12,%ymm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%ymm13
	vbroadcasti32x4	(%r11),%ymm14


	vpaddd	L$ctr_pattern(%rip),%ymm12,%ymm12
	vbroadcasti32x4	L$inc_2blocks(%rip),%ymm11


	cmpq	$128,%rdx
	jb	L$crypt_loop_4x_done2


	vmovdqu8	256-128(%r9),%ymm27
	vmovdqu8	256-96(%r9),%ymm28
	vmovdqu8	256-64(%r9),%ymm29
	vmovdqu8	256-32(%r9),%ymm30

	vbroadcasti32x4	-144(%r11),%ymm15

	vbroadcasti32x4	-128(%r11),%ymm16

	vbroadcasti32x4	-112(%r11),%ymm17

	vbroadcasti32x4	-96(%r11),%ymm18

	vbroadcasti32x4	-80(%r11),%ymm19
L$crypt_loop_4x2:
	vmovdqu8	0(%rdi),%ymm4
	vmovdqu8	32(%rdi),%ymm5
	vmovdqu8	64(%rdi),%ymm6
	vmovdqu8	96(%rdi),%ymm7



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm1
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm2
	vpaddd	%ymm11,%ymm12,%ymm12
	vpshufb	%ymm8,%ymm12,%ymm3
	vpaddd	%ymm11,%ymm12,%ymm12


	vpxord	%ymm13,%ymm0,%ymm0
	vpxord	%ymm13,%ymm1,%ymm1
	vpxord	%ymm13,%ymm2,%ymm2
	vpxord	%ymm13,%ymm3,%ymm3

	cmpl	$24,%r10d
	jl	L$aes128_2
	je	L$aes192_2

	vbroadcasti32x4	-208(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-192(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes192_2:
	vbroadcasti32x4	-176(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vbroadcasti32x4	-160(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

L$aes128_2:
	vpxord	%ymm4,%ymm14,%ymm20
	vpxord	%ymm5,%ymm14,%ymm21
	vpxord	%ymm6,%ymm14,%ymm22
	vpxord	%ymm7,%ymm14,%ymm23
	vaesenc	%ymm15,%ymm0,%ymm0
	vaesenc	%ymm15,%ymm1,%ymm1
	vaesenc	%ymm15,%ymm2,%ymm2
	vaesenc	%ymm15,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm4,%ymm4
	vpxord	%ymm10,%ymm4,%ymm4
	vpshufb	%ymm8,%ymm5,%ymm5
	vpshufb	%ymm8,%ymm6,%ymm6

	vaesenc	%ymm16,%ymm0,%ymm0
	vaesenc	%ymm16,%ymm1,%ymm1
	vaesenc	%ymm16,%ymm2,%ymm2
	vaesenc	%ymm16,%ymm3,%ymm3

	vpshufb	%ymm8,%ymm7,%ymm7
	vpclmulqdq	$0x00,%ymm27,%ymm4,%ymm10
	vpclmulqdq	$0x00,%ymm28,%ymm5,%ymm24
	vpclmulqdq	$0x00,%ymm29,%ymm6,%ymm25

	vaesenc	%ymm17,%ymm0,%ymm0
	vaesenc	%ymm17,%ymm1,%ymm1
	vaesenc	%ymm17,%ymm2,%ymm2
	vaesenc	%ymm17,%ymm3,%ymm3

	vpxord	%ymm24,%ymm10,%ymm10
	vpclmulqdq	$0x00,%ymm30,%ymm7,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm10
	vpclmulqdq	$0x01,%ymm27,%ymm4,%ymm24

	vaesenc	%ymm18,%ymm0,%ymm0
	vaesenc	%ymm18,%ymm1,%ymm1
	vaesenc	%ymm18,%ymm2,%ymm2
	vaesenc	%ymm18,%ymm3,%ymm3

	vpclmulqdq	$0x01,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x01,%ymm29,%ymm6,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm30,%ymm7,%ymm25

	vaesenc	%ymm19,%ymm0,%ymm0
	vaesenc	%ymm19,%ymm1,%ymm1
	vaesenc	%ymm19,%ymm2,%ymm2
	vaesenc	%ymm19,%ymm3,%ymm3

	vpclmulqdq	$0x10,%ymm27,%ymm4,%ymm26
	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x10,%ymm28,%ymm5,%ymm25
	vpclmulqdq	$0x10,%ymm29,%ymm6,%ymm26

	vbroadcasti32x4	-64(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm25,%ymm24
	vpclmulqdq	$0x01,%ymm10,%ymm31,%ymm26
	vpclmulqdq	$0x10,%ymm30,%ymm7,%ymm25
	vpxord	%ymm25,%ymm24,%ymm24

	vbroadcasti32x4	-48(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpshufd	$0x4e,%ymm10,%ymm10
	vpclmulqdq	$0x11,%ymm27,%ymm4,%ymm4
	vpclmulqdq	$0x11,%ymm28,%ymm5,%ymm5
	vpclmulqdq	$0x11,%ymm29,%ymm6,%ymm6

	vbroadcasti32x4	-32(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpternlogd	$0x96,%ymm26,%ymm10,%ymm24
	vpclmulqdq	$0x11,%ymm30,%ymm7,%ymm7
	vpternlogd	$0x96,%ymm6,%ymm5,%ymm4
	vpclmulqdq	$0x01,%ymm24,%ymm31,%ymm25

	vbroadcasti32x4	-16(%r11),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	vaesenc	%ymm9,%ymm1,%ymm1
	vaesenc	%ymm9,%ymm2,%ymm2
	vaesenc	%ymm9,%ymm3,%ymm3

	vpxord	%ymm7,%ymm4,%ymm10
	vpshufd	$0x4e,%ymm24,%ymm24
	vpternlogd	$0x96,%ymm25,%ymm24,%ymm10

	vextracti32x4	$1,%ymm10,%xmm4
	vpxord	%xmm4,%xmm10,%xmm10





	vaesenclast	%ymm20,%ymm0,%ymm4
	vaesenclast	%ymm21,%ymm1,%ymm5
	vaesenclast	%ymm22,%ymm2,%ymm6
	vaesenclast	%ymm23,%ymm3,%ymm7


	vmovdqu8	%ymm4,0(%rsi)
	vmovdqu8	%ymm5,32(%rsi)
	vmovdqu8	%ymm6,64(%rsi)
	vmovdqu8	%ymm7,96(%rsi)

	addq	$128,%rdi
	addq	$128,%rsi
	subq	$128,%rdx
	cmpq	$128,%rdx
	jae	L$crypt_loop_4x2
L$crypt_loop_4x_done2:

	testq	%rdx,%rdx
	jz	L$done2




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$32,%rdx
	jb	L$partial_vec2

L$crypt_loop_1x2:



	vpshufb	%ymm8,%ymm12,%ymm0
	vpaddd	%ymm11,%ymm12,%ymm12
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_1_2:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_1_2
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi)


	vmovdqu8	(%r8),%ymm30
	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$32,%r8
	addq	$32,%rdi
	addq	$32,%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	L$crypt_loop_1x2

	testq	%rdx,%rdx
	jz	L$reduce2

L$partial_vec2:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovd	%eax,%k2


	vpshufb	%ymm8,%ymm12,%ymm0
	vpxord	%ymm13,%ymm0,%ymm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_2_2:
	vbroadcasti32x4	(%rax),%ymm9
	vaesenc	%ymm9,%ymm0,%ymm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_2_2
	vaesenclast	%ymm14,%ymm0,%ymm0


	vmovdqu8	(%rdi),%ymm1{%k1}{z}
	vpxord	%ymm1,%ymm0,%ymm0
	vmovdqu8	%ymm0,(%rsi){%k1}













	vmovdqu8	(%r8),%ymm30{%k2}{z}
	vpshufb	%ymm8,%ymm1,%ymm0
	vpxord	%ymm10,%ymm0,%ymm0
	vpclmulqdq	$0x00,%ymm30,%ymm0,%ymm7
	vpclmulqdq	$0x01,%ymm30,%ymm0,%ymm1
	vpclmulqdq	$0x10,%ymm30,%ymm0,%ymm2
	vpclmulqdq	$0x11,%ymm30,%ymm0,%ymm3
	vpxord	%ymm7,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm2,%ymm1,%ymm5
	vpxord	%ymm3,%ymm6,%ymm6


L$reduce2:

	vpclmulqdq	$0x01,%ymm4,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm4,%ymm4
	vpternlogd	$0x96,%ymm0,%ymm4,%ymm5
	vpclmulqdq	$0x01,%ymm5,%ymm31,%ymm0
	vpshufd	$0x4e,%ymm5,%ymm5
	vpternlogd	$0x96,%ymm0,%ymm5,%ymm6

	vextracti32x4	$1,%ymm6,%xmm0
	vpxord	%xmm0,%xmm6,%xmm10


L$done2:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_aes_gcm_enc_update_vaes_avx10_512
.private_extern _aes_gcm_enc_update_vaes_avx10_512

.p2align	5
_aes_gcm_enc_update_vaes_avx10_512:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12
#ifdef BORINGSSL_DISPATCH_TEST

	movb	$1,_BORINGSSL_function_hit+7(%rip)
#endif

	vbroadcasti32x4	L$bswap_mask(%rip),%zmm8
	vbroadcasti32x4	L$gfpoly(%rip),%zmm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%zmm12
	vpshufb	%zmm8,%zmm12,%zmm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%zmm13
	vbroadcasti32x4	(%r11),%zmm14


	vpaddd	L$ctr_pattern(%rip),%zmm12,%zmm12
	vbroadcasti32x4	L$inc_4blocks(%rip),%zmm11


	cmpq	$256,%rdx
	jb	L$crypt_loop_4x_done3


	vmovdqu8	256-256(%r9),%zmm27
	vmovdqu8	256-192(%r9),%zmm28
	vmovdqu8	256-128(%r9),%zmm29
	vmovdqu8	256-64(%r9),%zmm30




	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	leaq	16(%rcx),%rax
L$vaesenc_4x_loop_1_3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_4x_loop_1_3
	vpxord	0(%rdi),%zmm14,%zmm20
	vpxord	64(%rdi),%zmm14,%zmm21
	vpxord	128(%rdi),%zmm14,%zmm22
	vpxord	192(%rdi),%zmm14,%zmm23
	vaesenclast	%zmm20,%zmm0,%zmm4
	vaesenclast	%zmm21,%zmm1,%zmm5
	vaesenclast	%zmm22,%zmm2,%zmm6
	vaesenclast	%zmm23,%zmm3,%zmm7
	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)
	addq	$256,%rdi
	addq	$256,%rsi
	subq	$256,%rdx
	cmpq	$256,%rdx
	jb	L$ghash_last_ciphertext_4x3

	vbroadcasti32x4	-144(%r11),%zmm15

	vbroadcasti32x4	-128(%r11),%zmm16

	vbroadcasti32x4	-112(%r11),%zmm17

	vbroadcasti32x4	-96(%r11),%zmm18

	vbroadcasti32x4	-80(%r11),%zmm19
L$crypt_loop_4x3:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	cmpl	$24,%r10d
	jl	L$aes128_3
	je	L$aes192_3

	vbroadcasti32x4	-208(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-192(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes192_3:
	vbroadcasti32x4	-176(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-160(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes128_3:
	vpxord	0(%rdi),%zmm14,%zmm20
	vpxord	64(%rdi),%zmm14,%zmm21
	vpxord	128(%rdi),%zmm14,%zmm22
	vpxord	192(%rdi),%zmm14,%zmm23
	vaesenc	%zmm15,%zmm0,%zmm0
	vaesenc	%zmm15,%zmm1,%zmm1
	vaesenc	%zmm15,%zmm2,%zmm2
	vaesenc	%zmm15,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6

	vaesenc	%zmm16,%zmm0,%zmm0
	vaesenc	%zmm16,%zmm1,%zmm1
	vaesenc	%zmm16,%zmm2,%zmm2
	vaesenc	%zmm16,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25

	vaesenc	%zmm17,%zmm0,%zmm0
	vaesenc	%zmm17,%zmm1,%zmm1
	vaesenc	%zmm17,%zmm2,%zmm2
	vaesenc	%zmm17,%zmm3,%zmm3

	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24

	vaesenc	%zmm18,%zmm0,%zmm0
	vaesenc	%zmm18,%zmm1,%zmm1
	vaesenc	%zmm18,%zmm2,%zmm2
	vaesenc	%zmm18,%zmm3,%zmm3

	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25

	vaesenc	%zmm19,%zmm0,%zmm0
	vaesenc	%zmm19,%zmm1,%zmm1
	vaesenc	%zmm19,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm3,%zmm3

	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26

	vbroadcasti32x4	-64(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24

	vbroadcasti32x4	-48(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6

	vbroadcasti32x4	-32(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25

	vbroadcasti32x4	-16(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10

	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10





	vaesenclast	%zmm20,%zmm0,%zmm4
	vaesenclast	%zmm21,%zmm1,%zmm5
	vaesenclast	%zmm22,%zmm2,%zmm6
	vaesenclast	%zmm23,%zmm3,%zmm7


	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)

	addq	$256,%rdi
	addq	$256,%rsi
	subq	$256,%rdx
	cmpq	$256,%rdx
	jae	L$crypt_loop_4x3
L$ghash_last_ciphertext_4x3:
	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6
	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25
	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24
	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25
	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24
	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6
	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25
	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10
	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10

L$crypt_loop_4x_done3:

	testq	%rdx,%rdx
	jz	L$done3




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$64,%rdx
	jb	L$partial_vec3

L$crypt_loop_1x3:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_1_3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_1_3
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi)


	vmovdqu8	(%r8),%zmm30
	vpshufb	%zmm8,%zmm0,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$64,%r8
	addq	$64,%rdi
	addq	$64,%rsi
	subq	$64,%rdx
	cmpq	$64,%rdx
	jae	L$crypt_loop_1x3

	testq	%rdx,%rdx
	jz	L$reduce3

L$partial_vec3:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k2


	vpshufb	%zmm8,%zmm12,%zmm0
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_2_3:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_2_3
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1{%k1}{z}
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi){%k1}













	vmovdqu8	(%r8),%zmm30{%k2}{z}
	vmovdqu8	%zmm0,%zmm1{%k1}{z}
	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6


L$reduce3:

	vpclmulqdq	$0x01,%zmm4,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm0,%zmm4,%zmm5
	vpclmulqdq	$0x01,%zmm5,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm5,%zmm5
	vpternlogd	$0x96,%zmm0,%zmm5,%zmm6

	vextracti32x4	$1,%zmm6,%xmm0
	vextracti32x4	$2,%zmm6,%xmm1
	vextracti32x4	$3,%zmm6,%xmm2
	vpxord	%xmm0,%xmm6,%xmm10
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm10


L$done3:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_aes_gcm_dec_update_vaes_avx10_512
.private_extern _aes_gcm_dec_update_vaes_avx10_512

.p2align	5
_aes_gcm_dec_update_vaes_avx10_512:


_CET_ENDBR
	pushq	%r12


	movq	16(%rsp),%r12

	vbroadcasti32x4	L$bswap_mask(%rip),%zmm8
	vbroadcasti32x4	L$gfpoly(%rip),%zmm31



	vmovdqu	(%r12),%xmm10
	vpshufb	%xmm8,%xmm10,%xmm10
	vbroadcasti32x4	(%r8),%zmm12
	vpshufb	%zmm8,%zmm12,%zmm12



	movl	240(%rcx),%r10d
	leal	-20(,%r10,4),%r10d




	leaq	96(%rcx,%r10,4),%r11
	vbroadcasti32x4	(%rcx),%zmm13
	vbroadcasti32x4	(%r11),%zmm14


	vpaddd	L$ctr_pattern(%rip),%zmm12,%zmm12
	vbroadcasti32x4	L$inc_4blocks(%rip),%zmm11


	cmpq	$256,%rdx
	jb	L$crypt_loop_4x_done4


	vmovdqu8	256-256(%r9),%zmm27
	vmovdqu8	256-192(%r9),%zmm28
	vmovdqu8	256-128(%r9),%zmm29
	vmovdqu8	256-64(%r9),%zmm30

	vbroadcasti32x4	-144(%r11),%zmm15

	vbroadcasti32x4	-128(%r11),%zmm16

	vbroadcasti32x4	-112(%r11),%zmm17

	vbroadcasti32x4	-96(%r11),%zmm18

	vbroadcasti32x4	-80(%r11),%zmm19
L$crypt_loop_4x4:
	vmovdqu8	0(%rdi),%zmm4
	vmovdqu8	64(%rdi),%zmm5
	vmovdqu8	128(%rdi),%zmm6
	vmovdqu8	192(%rdi),%zmm7



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm1
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm2
	vpaddd	%zmm11,%zmm12,%zmm12
	vpshufb	%zmm8,%zmm12,%zmm3
	vpaddd	%zmm11,%zmm12,%zmm12


	vpxord	%zmm13,%zmm0,%zmm0
	vpxord	%zmm13,%zmm1,%zmm1
	vpxord	%zmm13,%zmm2,%zmm2
	vpxord	%zmm13,%zmm3,%zmm3

	cmpl	$24,%r10d
	jl	L$aes128_4
	je	L$aes192_4

	vbroadcasti32x4	-208(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-192(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes192_4:
	vbroadcasti32x4	-176(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vbroadcasti32x4	-160(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

L$aes128_4:
	vpxord	%zmm4,%zmm14,%zmm20
	vpxord	%zmm5,%zmm14,%zmm21
	vpxord	%zmm6,%zmm14,%zmm22
	vpxord	%zmm7,%zmm14,%zmm23
	vaesenc	%zmm15,%zmm0,%zmm0
	vaesenc	%zmm15,%zmm1,%zmm1
	vaesenc	%zmm15,%zmm2,%zmm2
	vaesenc	%zmm15,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm4,%zmm4
	vpxord	%zmm10,%zmm4,%zmm4
	vpshufb	%zmm8,%zmm5,%zmm5
	vpshufb	%zmm8,%zmm6,%zmm6

	vaesenc	%zmm16,%zmm0,%zmm0
	vaesenc	%zmm16,%zmm1,%zmm1
	vaesenc	%zmm16,%zmm2,%zmm2
	vaesenc	%zmm16,%zmm3,%zmm3

	vpshufb	%zmm8,%zmm7,%zmm7
	vpclmulqdq	$0x00,%zmm27,%zmm4,%zmm10
	vpclmulqdq	$0x00,%zmm28,%zmm5,%zmm24
	vpclmulqdq	$0x00,%zmm29,%zmm6,%zmm25

	vaesenc	%zmm17,%zmm0,%zmm0
	vaesenc	%zmm17,%zmm1,%zmm1
	vaesenc	%zmm17,%zmm2,%zmm2
	vaesenc	%zmm17,%zmm3,%zmm3

	vpxord	%zmm24,%zmm10,%zmm10
	vpclmulqdq	$0x00,%zmm30,%zmm7,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm10
	vpclmulqdq	$0x01,%zmm27,%zmm4,%zmm24

	vaesenc	%zmm18,%zmm0,%zmm0
	vaesenc	%zmm18,%zmm1,%zmm1
	vaesenc	%zmm18,%zmm2,%zmm2
	vaesenc	%zmm18,%zmm3,%zmm3

	vpclmulqdq	$0x01,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x01,%zmm29,%zmm6,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm30,%zmm7,%zmm25

	vaesenc	%zmm19,%zmm0,%zmm0
	vaesenc	%zmm19,%zmm1,%zmm1
	vaesenc	%zmm19,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm3,%zmm3

	vpclmulqdq	$0x10,%zmm27,%zmm4,%zmm26
	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x10,%zmm28,%zmm5,%zmm25
	vpclmulqdq	$0x10,%zmm29,%zmm6,%zmm26

	vbroadcasti32x4	-64(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm25,%zmm24
	vpclmulqdq	$0x01,%zmm10,%zmm31,%zmm26
	vpclmulqdq	$0x10,%zmm30,%zmm7,%zmm25
	vpxord	%zmm25,%zmm24,%zmm24

	vbroadcasti32x4	-48(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpshufd	$0x4e,%zmm10,%zmm10
	vpclmulqdq	$0x11,%zmm27,%zmm4,%zmm4
	vpclmulqdq	$0x11,%zmm28,%zmm5,%zmm5
	vpclmulqdq	$0x11,%zmm29,%zmm6,%zmm6

	vbroadcasti32x4	-32(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpternlogd	$0x96,%zmm26,%zmm10,%zmm24
	vpclmulqdq	$0x11,%zmm30,%zmm7,%zmm7
	vpternlogd	$0x96,%zmm6,%zmm5,%zmm4
	vpclmulqdq	$0x01,%zmm24,%zmm31,%zmm25

	vbroadcasti32x4	-16(%r11),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	vaesenc	%zmm9,%zmm1,%zmm1
	vaesenc	%zmm9,%zmm2,%zmm2
	vaesenc	%zmm9,%zmm3,%zmm3

	vpxord	%zmm7,%zmm4,%zmm10
	vpshufd	$0x4e,%zmm24,%zmm24
	vpternlogd	$0x96,%zmm25,%zmm24,%zmm10

	vextracti32x4	$1,%zmm10,%xmm4
	vextracti32x4	$2,%zmm10,%xmm5
	vextracti32x4	$3,%zmm10,%xmm6
	vpxord	%xmm4,%xmm10,%xmm10
	vpternlogd	$0x96,%xmm5,%xmm6,%xmm10





	vaesenclast	%zmm20,%zmm0,%zmm4
	vaesenclast	%zmm21,%zmm1,%zmm5
	vaesenclast	%zmm22,%zmm2,%zmm6
	vaesenclast	%zmm23,%zmm3,%zmm7


	vmovdqu8	%zmm4,0(%rsi)
	vmovdqu8	%zmm5,64(%rsi)
	vmovdqu8	%zmm6,128(%rsi)
	vmovdqu8	%zmm7,192(%rsi)

	addq	$256,%rdi
	addq	$256,%rsi
	subq	$256,%rdx
	cmpq	$256,%rdx
	jae	L$crypt_loop_4x4
L$crypt_loop_4x_done4:

	testq	%rdx,%rdx
	jz	L$done4




















	movq	%rdx,%rax
	negq	%rax
	andq	$-16,%rax
	leaq	256(%r9,%rax,1),%r8
	vpxor	%xmm4,%xmm4,%xmm4
	vpxor	%xmm5,%xmm5,%xmm5
	vpxor	%xmm6,%xmm6,%xmm6

	cmpq	$64,%rdx
	jb	L$partial_vec4

L$crypt_loop_1x4:



	vpshufb	%zmm8,%zmm12,%zmm0
	vpaddd	%zmm11,%zmm12,%zmm12
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_1_4:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_1_4
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi)


	vmovdqu8	(%r8),%zmm30
	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6

	vpxor	%xmm10,%xmm10,%xmm10

	addq	$64,%r8
	addq	$64,%rdi
	addq	$64,%rsi
	subq	$64,%rdx
	cmpq	$64,%rdx
	jae	L$crypt_loop_1x4

	testq	%rdx,%rdx
	jz	L$reduce4

L$partial_vec4:




	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k1
	addq	$15,%rdx
	andq	$-16,%rdx
	movq	$-1,%rax
	bzhiq	%rdx,%rax,%rax
	kmovq	%rax,%k2


	vpshufb	%zmm8,%zmm12,%zmm0
	vpxord	%zmm13,%zmm0,%zmm0
	leaq	16(%rcx),%rax
L$vaesenc_1x_loop_2_4:
	vbroadcasti32x4	(%rax),%zmm9
	vaesenc	%zmm9,%zmm0,%zmm0
	addq	$16,%rax
	cmpq	%rax,%r11
	jne	L$vaesenc_1x_loop_2_4
	vaesenclast	%zmm14,%zmm0,%zmm0


	vmovdqu8	(%rdi),%zmm1{%k1}{z}
	vpxord	%zmm1,%zmm0,%zmm0
	vmovdqu8	%zmm0,(%rsi){%k1}













	vmovdqu8	(%r8),%zmm30{%k2}{z}
	vpshufb	%zmm8,%zmm1,%zmm0
	vpxord	%zmm10,%zmm0,%zmm0
	vpclmulqdq	$0x00,%zmm30,%zmm0,%zmm7
	vpclmulqdq	$0x01,%zmm30,%zmm0,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm0,%zmm2
	vpclmulqdq	$0x11,%zmm30,%zmm0,%zmm3
	vpxord	%zmm7,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm2,%zmm1,%zmm5
	vpxord	%zmm3,%zmm6,%zmm6


L$reduce4:

	vpclmulqdq	$0x01,%zmm4,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm4,%zmm4
	vpternlogd	$0x96,%zmm0,%zmm4,%zmm5
	vpclmulqdq	$0x01,%zmm5,%zmm31,%zmm0
	vpshufd	$0x4e,%zmm5,%zmm5
	vpternlogd	$0x96,%zmm0,%zmm5,%zmm6

	vextracti32x4	$1,%zmm6,%xmm0
	vextracti32x4	$2,%zmm6,%xmm1
	vextracti32x4	$3,%zmm6,%xmm2
	vpxord	%xmm0,%xmm6,%xmm10
	vpternlogd	$0x96,%xmm1,%xmm2,%xmm10


L$done4:

	vpshufb	%xmm8,%xmm10,%xmm10
	vmovdqu	%xmm10,(%r12)

	vzeroupper
	popq	%r12

	ret



.globl	_gcm_gmult_vpclmulqdq_avx10
.private_extern _gcm_gmult_vpclmulqdq_avx10

.p2align	5
_gcm_gmult_vpclmulqdq_avx10:


_CET_ENDBR



	vmovdqu	(%rdi),%xmm0
	vmovdqu	L$bswap_mask(%rip),%xmm1
	vmovdqu	256-16(%rsi),%xmm2
	vmovdqu	L$gfpoly(%rip),%xmm3
	vpshufb	%xmm1,%xmm0,%xmm0

	vpclmulqdq	$0x00,%xmm2,%xmm0,%xmm4
	vpclmulqdq	$0x01,%xmm2,%xmm0,%xmm5
	vpclmulqdq	$0x10,%xmm2,%xmm0,%xmm6
	vpxord	%xmm6,%xmm5,%xmm5
	vpclmulqdq	$0x01,%xmm4,%xmm3,%xmm6
	vpshufd	$0x4e,%xmm4,%xmm4
	vpternlogd	$0x96,%xmm6,%xmm4,%xmm5
	vpclmulqdq	$0x11,%xmm2,%xmm0,%xmm0
	vpclmulqdq	$0x01,%xmm5,%xmm3,%xmm4
	vpshufd	$0x4e,%xmm5,%xmm5
	vpternlogd	$0x96,%xmm4,%xmm5,%xmm0


	vpshufb	%xmm1,%xmm0,%xmm0
	vmovdqu	%xmm0,(%rdi)
	ret



.globl	_gcm_ghash_vpclmulqdq_avx10
.private_extern _gcm_ghash_vpclmulqdq_avx10

.p2align	5
_gcm_ghash_vpclmulqdq_avx10:


_CET_ENDBR




	vmovdqu	L$bswap_mask(%rip),%xmm4
	vmovdqu	L$gfpoly(%rip),%xmm5


	vmovdqu	(%rdi),%xmm6
	vpshufb	%xmm4,%xmm6,%xmm6


	testq	%rcx,%rcx
	jz	L$aad_done
	vmovdqu8	256-16(%rsi),%xmm7
L$aad_loop_1x:
	vmovdqu	(%rdx),%xmm0
	vpshufb	%xmm4,%xmm0,%xmm0
	vpxor	%xmm0,%xmm6,%xmm6
	vpclmulqdq	$0x00,%xmm7,%xmm6,%xmm0
	vpclmulqdq	$0x01,%xmm7,%xmm6,%xmm1
	vpclmulqdq	$0x10,%xmm7,%xmm6,%xmm2
	vpxord	%xmm2,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm0,%xmm5,%xmm2
	vpshufd	$0x4e,%xmm0,%xmm0
	vpternlogd	$0x96,%xmm2,%xmm0,%xmm1
	vpclmulqdq	$0x11,%xmm7,%xmm6,%xmm6
	vpclmulqdq	$0x01,%xmm1,%xmm5,%xmm0
	vpshufd	$0x4e,%xmm1,%xmm1
	vpternlogd	$0x96,%xmm0,%xmm1,%xmm6

	addq	$16,%rdx
	subq	$16,%rcx
	jnz	L$aad_loop_1x

L$aad_done:

	vpshufb	%xmm4,%xmm6,%xmm6
	vmovdqu	%xmm6,(%rdi)
	ret



#endif
