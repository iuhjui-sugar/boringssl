// This file is generated from a similarly-named Perl script in the BoringSSL
// source tree. Do not edit by hand.

#include <openssl/asm_base.h>

#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && defined(__ELF__)
.text	

.section	.rodata

.align	64

.Lpoly:
.quad	0xc200000000000000, 0x0000000000000001

.Lbswap:
.byte	7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8

.Linc:
.long	0,0,4,0

.align	64

.Linc_init:
.long	0,0,0,0
.long	0,0,1,0
.long	0,0,2,0
.long	0,0,3,0

.text	
.align	64
.globl	gcm_init_avx512
.hidden gcm_init_avx512
.type	gcm_init_avx512,@function
gcm_init_avx512:
.cfi_startproc	

	vzeroupper

	vmovdqu	(%rsi),%xmm5
	vmovdqa	.Lpoly(%rip),%xmm6
	vmovdqa	.Lbswap(%rip),%xmm7

	leaq	240(%rdi),%rdi


	vmovq	%xmm5,%rcx
	sarq	$63,%rcx
	vmovq	%rcx,%xmm4
	vpshufd	$0x44,%xmm4,%xmm4
	vpand	%xmm6,%xmm4,%xmm4
	vpsrlq	$63,%xmm5,%xmm3
	vpsrldq	$8,%xmm3,%xmm3
	vpsllq	$1,%xmm5,%xmm5
	vpxor	%xmm4,%xmm5,%xmm5
	vpxor	%xmm3,%xmm5,%xmm5

	vmovdqu	%xmm5,(%rdi)
	leaq	-16(%rdi),%rdi

	movq	$15,%rcx
	vmovdqa	%xmm5,%xmm3



.align	16
.Laes_gcm_init_loop:
	vpclmulqdq	$0x01,%xmm5,%xmm3,%xmm2
	vpclmulqdq	$0x00,%xmm5,%xmm3,%xmm0
	vpclmulqdq	$0x11,%xmm5,%xmm3,%xmm1
	vpclmulqdq	$0x10,%xmm5,%xmm3,%xmm3
	vpxor	%xmm3,%xmm2,%xmm2

	vpsrldq	$8,%xmm2,%xmm3
	vpslldq	$8,%xmm2,%xmm2
	vpxor	%xmm2,%xmm1,%xmm1
	vpxor	%xmm3,%xmm0,%xmm0

	vpclmulqdq	$0x00,%xmm6,%xmm1,%xmm2
	vpshufd	$0x4e,%xmm1,%xmm1
	vpxor	%xmm2,%xmm1,%xmm1

	vpclmulqdq	$0x00,%xmm6,%xmm1,%xmm2
	vpshufd	$0x4e,%xmm1,%xmm1
	vpxor	%xmm2,%xmm1,%xmm1

	vpxor	%xmm0,%xmm1,%xmm3
	vpshufd	$0x4e,%xmm3,%xmm3

	vmovdqu	%xmm3,(%rdi)
	leaq	-16(%rdi),%rdi

	decq	%rcx
	jne	.Laes_gcm_init_loop

	vzeroupper

	ret

.cfi_endproc	
.size	gcm_init_avx512,.-gcm_init_avx512
.align	64
.globl	gcm_gmult_avx512
.hidden gcm_gmult_avx512
.type	gcm_gmult_avx512,@function
gcm_gmult_avx512:
.cfi_startproc	
	vzeroupper

	vmovdqu	(%rdi),%xmm5
	vmovdqu	240(%rsi),%xmm8

	vmovdqa	.Lpoly(%rip),%xmm6
	vmovdqa	.Lbswap(%rip),%xmm7

	vpshufb	%xmm7,%xmm5,%xmm5

	vpclmulqdq	$0x01,%xmm5,%xmm8,%xmm2
	vpclmulqdq	$0x10,%xmm5,%xmm8,%xmm4
	vpclmulqdq	$0x00,%xmm5,%xmm8,%xmm1
	vpclmulqdq	$0x11,%xmm5,%xmm8,%xmm0

	vpxor	%xmm4,%xmm2,%xmm2

	vpsrldq	$8,%xmm2,%xmm3
	vpslldq	$8,%xmm2,%xmm2

	vpxor	%xmm2,%xmm0,%xmm0
	vpxor	%xmm3,%xmm1,%xmm1

	vpclmulqdq	$0x00,%xmm6,%xmm0,%xmm3
	vpshufd	$0x4e,%xmm0,%xmm0
	vpxor	%xmm3,%xmm0,%xmm0
	vpclmulqdq	$0x00,%xmm6,%xmm0,%xmm3
	vpxor	%xmm3,%xmm1,%xmm1
	vpshufd	$0x4e,%xmm1,%xmm1
	vpxor	%xmm1,%xmm0,%xmm0

	vpshufb	%xmm7,%xmm0,%xmm5
	vmovdqu	%xmm5,(%rdi)

	vzeroupper

	ret
.cfi_endproc	
.size	gcm_gmult_avx512,.-gcm_gmult_avx512
.align	64
.globl	gcm_ghash_avx512
.hidden gcm_ghash_avx512
.type	gcm_ghash_avx512,@function
gcm_ghash_avx512:
.cfi_startproc	

	shrq	$4,%rcx
	jz	.Lgcm_ghash_avx512_bail






	vzeroupper

	vmovdqu	(%rdi),%xmm5

	vmovdqa	.Lpoly(%rip),%xmm6
	vmovdqa	.Lbswap(%rip),%xmm7

	vpshufb	%xmm7,%xmm5,%xmm5




	leaq	256(%rsi),%rsi

.align	16
.Lgcm_ghash_avx512_loop:



	movq	$16,%r8
	cmpq	$16,%rcx
	cmovbeq	%rcx,%r8

	subq	%r8,%rcx

	shlq	$4,%r8
	subq	%r8,%rsi


	vmovdqu	0(%rsi),%xmm8
	vmovdqu	0(%rdx),%xmm9
	vpshufb	%xmm7,%xmm9,%xmm9
	leaq	16(%rsi),%rsi
	leaq	16(%rdx),%rdx
	subq	$16,%r8

	vpxor	%xmm5,%xmm9,%xmm9

	vpclmulqdq	$0x01,%xmm9,%xmm8,%xmm2
	vpclmulqdq	$0x00,%xmm9,%xmm8,%xmm1
	vpclmulqdq	$0x11,%xmm9,%xmm8,%xmm0
	vpclmulqdq	$0x10,%xmm9,%xmm8,%xmm3
	vpxor	%xmm3,%xmm2,%xmm2


	jz	.Lgcm_ghash_avx512_loop_reduce

.align	16
.Lgcm_ghash_avx512_loop_inner:
	vmovdqu	0(%rsi),%xmm8
	vmovdqu	0(%rdx),%xmm9
	vpshufb	%xmm7,%xmm9,%xmm9

	vpclmulqdq	$0x00,%xmm9,%xmm8,%xmm3
	vpxor	%xmm3,%xmm1,%xmm1
	vpclmulqdq	$0x01,%xmm9,%xmm8,%xmm3
	vpxor	%xmm3,%xmm2,%xmm2
	vpclmulqdq	$0x11,%xmm9,%xmm8,%xmm3
	vpxor	%xmm3,%xmm0,%xmm0
	vpclmulqdq	$0x10,%xmm9,%xmm8,%xmm3
	vpxor	%xmm3,%xmm2,%xmm2

	leaq	16(%rsi),%rsi
	leaq	16(%rdx),%rdx
	subq	$16,%r8

	jnz	.Lgcm_ghash_avx512_loop_inner

.Lgcm_ghash_avx512_loop_reduce:
	vpsrldq	$8,%xmm2,%xmm3
	vpslldq	$8,%xmm2,%xmm2

	vpxor	%xmm2,%xmm0,%xmm0
	vpxor	%xmm3,%xmm1,%xmm1

	vpclmulqdq	$0x00,%xmm6,%xmm0,%xmm3
	vpshufd	$0x4e,%xmm0,%xmm0
	vpxor	%xmm3,%xmm0,%xmm0

	vpclmulqdq	$0x00,%xmm6,%xmm0,%xmm3
	vpxor	%xmm3,%xmm1,%xmm1
	vpshufd	$0x4e,%xmm1,%xmm1
	vpxor	%xmm1,%xmm0,%xmm5

	cmpq	$0,%rcx
	jnz	.Lgcm_ghash_avx512_loop

	vpshufb	%xmm7,%xmm5,%xmm5
	vmovdqu	%xmm5,(%rdi)

	vzeroupper

.Lgcm_ghash_avx512_bail:

	ret
.cfi_endproc	
.size	gcm_ghash_avx512,.-gcm_ghash_avx512
.align	64
.globl	gcm_enc_avx512
.hidden gcm_enc_avx512
.type	gcm_enc_avx512,@function
gcm_enc_avx512:
.cfi_startproc	

	movq	%rcx,%rax

	cmpq	$0,%rcx
	je	.Lgcm_enc_avx512_bail

	vzeroupper

	vbroadcasti64x2	.Lbswap(%rip),%zmm7
	vbroadcasti64x2	.Lpoly(%rip),%zmm6
	vbroadcasti64x2	.Linc(%rip),%zmm8


	movq	8(%rsp),%r10
	vmovdqu64	(%r10),%xmm5

	vbroadcasti64x2	(%r8),%zmm9
	movl	240(%rdx),%r11d

	vpshufb	%xmm7,%xmm5,%xmm5
	vpshufb	%zmm7,%zmm9,%zmm9


	vbroadcasti64x2	0(%rdx),%zmm18
	vbroadcasti64x2	16(%rdx),%zmm19
	vbroadcasti64x2	32(%rdx),%zmm20
	vbroadcasti64x2	48(%rdx),%zmm21
	vbroadcasti64x2	64(%rdx),%zmm22
	vbroadcasti64x2	80(%rdx),%zmm23
	vbroadcasti64x2	96(%rdx),%zmm24
	vbroadcasti64x2	112(%rdx),%zmm25
	vbroadcasti64x2	128(%rdx),%zmm26
	subq	$8,%r11
	shlq	$4,%r11
	vbroadcasti64x2	144(%rdx,%r11), %zmm27



	movq	%rcx,%r10
	addq	$15,%r10
	shrq	$4,%r10

	vpxor	%xmm3,%xmm3,%xmm3
	vpinsrd	$2,%r10d,%xmm3,%xmm3


	vpaddd	.Linc_init(%rip),%zmm9,%zmm10
	vpaddd	%xmm3,%xmm9,%xmm3
	vpaddd	%zmm8,%zmm10,%zmm11
	vpaddd	%zmm8,%zmm11,%zmm12
	vpaddd	%zmm8,%zmm12,%zmm13
	vpaddd	%zmm8,%zmm13,%zmm9
	vpshufb	%xmm7,%xmm3,%xmm3
	vmovdqu	%xmm3,(%r8)

	vpshufb	%zmm7,%zmm10,%zmm10
	vpshufb	%zmm7,%zmm11,%zmm11
	vpshufb	%zmm7,%zmm12,%zmm12
	vpshufb	%zmm7,%zmm13,%zmm13

	movq	$-1,%r10
	kmovq	%r10,%k1
	kmovq	%r10,%k2
	kmovq	%r10,%k3
	kmovq	%r10,%k4

	cmpq	$256,%rcx
	jae	1f

	cmpq	$128,%rcx
	jbe	.Lgcm_enc_avx512_128B_block



	vmovdqu8	0(%rdi),%zmm28
	vmovdqu8	64(%rdi),%zmm29
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$192,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$128,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k3
	vmovdqu8	128(%rdi),%zmm30{%k3}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$256,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$192,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k4
	vmovdqu8	192(%rdi),%zmm31{%k4}{z}

	jmp	2f
1:
	vmovdqu64	0(%rdi),%zmm28
	vmovdqu64	64(%rdi),%zmm29
	vmovdqu64	128(%rdi),%zmm30
	vmovdqu64	192(%rdi),%zmm31
2:
	leaq	256(%rdi),%rdi
	vpxorq	%zmm18,%zmm10,%zmm10
	vpxorq	%zmm18,%zmm11,%zmm11
	vpxorq	%zmm18,%zmm12,%zmm12
	vpxorq	%zmm18,%zmm13,%zmm13
	vaesenc	%zmm19,%zmm10,%zmm10
	vaesenc	%zmm19,%zmm11,%zmm11
	vaesenc	%zmm19,%zmm12,%zmm12
	vaesenc	%zmm19,%zmm13,%zmm13
	vaesenc	%zmm20,%zmm10,%zmm10
	vaesenc	%zmm20,%zmm11,%zmm11
	vaesenc	%zmm20,%zmm12,%zmm12
	vaesenc	%zmm20,%zmm13,%zmm13
	vaesenc	%zmm21,%zmm10,%zmm10
	vaesenc	%zmm21,%zmm11,%zmm11
	vaesenc	%zmm21,%zmm12,%zmm12
	vaesenc	%zmm21,%zmm13,%zmm13
	vaesenc	%zmm22,%zmm10,%zmm10
	vaesenc	%zmm22,%zmm11,%zmm11
	vaesenc	%zmm22,%zmm12,%zmm12
	vaesenc	%zmm22,%zmm13,%zmm13
	vaesenc	%zmm23,%zmm10,%zmm10
	vaesenc	%zmm23,%zmm11,%zmm11
	vaesenc	%zmm23,%zmm12,%zmm12
	vaesenc	%zmm23,%zmm13,%zmm13
	vaesenc	%zmm24,%zmm10,%zmm10
	vaesenc	%zmm24,%zmm11,%zmm11
	vaesenc	%zmm24,%zmm12,%zmm12
	vaesenc	%zmm24,%zmm13,%zmm13
	vaesenc	%zmm25,%zmm10,%zmm10
	vaesenc	%zmm25,%zmm11,%zmm11
	vaesenc	%zmm25,%zmm12,%zmm12
	vaesenc	%zmm25,%zmm13,%zmm13
	vaesenc	%zmm26,%zmm10,%zmm10
	vaesenc	%zmm26,%zmm11,%zmm11
	vaesenc	%zmm26,%zmm12,%zmm12
	vaesenc	%zmm26,%zmm13,%zmm13
	xorq	%r10,%r10
1:
	vbroadcasti64x2	144(%rdx,%r10), %zmm3
	addq	$16,%r10
	vaesenc	%zmm3,%zmm10,%zmm10
	vaesenc	%zmm3,%zmm11,%zmm11
	vaesenc	%zmm3,%zmm12,%zmm12
	vaesenc	%zmm3,%zmm13,%zmm13

	cmpq	%r10,%r11
	jnz	1b
	vaesenclast	%zmm27,%zmm10,%zmm10
	vaesenclast	%zmm27,%zmm11,%zmm11
	vaesenclast	%zmm27,%zmm12,%zmm12
	vaesenclast	%zmm27,%zmm13,%zmm13

	vpxorq	%zmm28,%zmm10,%zmm28
	vpxorq	%zmm29,%zmm11,%zmm29
	vpxorq	%zmm30,%zmm12,%zmm30
	vpxorq	%zmm31,%zmm13,%zmm31


	vmovdqu64	0(%r9),%zmm14
	vmovdqu64	64(%r9),%zmm15
	vmovdqu64	128(%r9),%zmm16
	vmovdqu64	192(%r9),%zmm17

.align	16
.Lgcm_enc_avx512_main_loop:
	cmpq	$256,%rcx
	jbe	.Lgcm_enc_avx512_hash_tail



	subq	$256,%rcx

	vmovdqa64	%zmm9,%zmm10
	vmovdqu8	%zmm28,0(%rsi)
	vpaddd	%zmm8,%zmm9,%zmm11
	vmovdqu8	%zmm29,64(%rsi)
	vpaddd	%zmm8,%zmm11,%zmm12
	vmovdqu8	%zmm30,128(%rsi)
	vpaddd	%zmm8,%zmm12,%zmm13
	vmovdqu8	%zmm31,192(%rsi)
	vpaddd	%zmm8,%zmm13,%zmm9

	leaq	256(%rsi),%rsi
	vpshufb	%zmm7,%zmm28,%zmm28
	vpshufb	%zmm7,%zmm10,%zmm10
	vpshufb	%zmm7,%zmm11,%zmm11
	vpshufb	%zmm7,%zmm12,%zmm12
	vpshufb	%zmm7,%zmm13,%zmm13
	vpxorq	%zmm5,%zmm28,%zmm28
	vpxorq	%zmm18,%zmm10,%zmm10
	vpxorq	%zmm18,%zmm11,%zmm11
	vpxorq	%zmm18,%zmm12,%zmm12
	vpxorq	%zmm18,%zmm13,%zmm13
	vpshufb	%zmm7,%zmm29,%zmm29
	vpclmulqdq	$0x01,%zmm28,%zmm14,%zmm2
	vpclmulqdq	$0x10,%zmm28,%zmm14,%zmm3
	vpclmulqdq	$0x00,%zmm28,%zmm14,%zmm1
	vpclmulqdq	$0x11,%zmm28,%zmm14,%zmm5
	vpxorq	%zmm3,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm10,%zmm10
	vaesenc	%zmm19,%zmm11,%zmm11
	vaesenc	%zmm19,%zmm12,%zmm12
	vaesenc	%zmm19,%zmm13,%zmm13
	vaesenc	%zmm20,%zmm10,%zmm10
	vaesenc	%zmm20,%zmm11,%zmm11
	vaesenc	%zmm20,%zmm12,%zmm12
	vaesenc	%zmm20,%zmm13,%zmm13
	vpshufb	%zmm7,%zmm30,%zmm30
	vpclmulqdq	$0x01,%zmm29,%zmm15,%zmm4
	vpclmulqdq	$0x11,%zmm29,%zmm15,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm29,%zmm15,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm29,%zmm15,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
	vaesenc	%zmm21,%zmm10,%zmm10
	vaesenc	%zmm21,%zmm11,%zmm11
	vaesenc	%zmm21,%zmm12,%zmm12
	vaesenc	%zmm21,%zmm13,%zmm13
	vaesenc	%zmm22,%zmm10,%zmm10
	vaesenc	%zmm22,%zmm11,%zmm11
	vaesenc	%zmm22,%zmm12,%zmm12
	vaesenc	%zmm22,%zmm13,%zmm13
	vpshufb	%zmm7,%zmm31,%zmm31
	vpclmulqdq	$0x01,%zmm30,%zmm16,%zmm4
	vpclmulqdq	$0x11,%zmm30,%zmm16,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm30,%zmm16,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm30,%zmm16,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
	vaesenc	%zmm23,%zmm10,%zmm10
	vaesenc	%zmm23,%zmm11,%zmm11
	vaesenc	%zmm23,%zmm12,%zmm12
	vaesenc	%zmm23,%zmm13,%zmm13
	vaesenc	%zmm24,%zmm10,%zmm10
	vaesenc	%zmm24,%zmm11,%zmm11
	vaesenc	%zmm24,%zmm12,%zmm12
	vaesenc	%zmm24,%zmm13,%zmm13
	vpclmulqdq	$0x01,%zmm31,%zmm17,%zmm4
	vpclmulqdq	$0x11,%zmm31,%zmm17,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm31,%zmm17,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm31,%zmm17,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2

	cmpq	$256,%rcx
	jae	1f



	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$64,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	kmovq	%r8,%k1
	vmovdqu8	0(%rdi),%zmm28{%k1}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$128,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$64,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k2
	vmovdqu8	64(%rdi),%zmm29{%k2}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$192,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$128,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k3
	vmovdqu8	128(%rdi),%zmm30{%k3}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$256,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$192,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k4
	vmovdqu8	192(%rdi),%zmm31{%k4}{z}

	jmp	2f
1:

	vmovdqu64	0(%rdi),%zmm28
	vmovdqu64	64(%rdi),%zmm29
	vmovdqu64	128(%rdi),%zmm30
	vmovdqu64	192(%rdi),%zmm31
2:
	leaq	256(%rdi),%rdi
	vaesenc	%zmm25,%zmm10,%zmm10
	vaesenc	%zmm25,%zmm11,%zmm11
	vaesenc	%zmm25,%zmm12,%zmm12
	vaesenc	%zmm25,%zmm13,%zmm13
	vaesenc	%zmm26,%zmm10,%zmm10
	vaesenc	%zmm26,%zmm11,%zmm11
	vaesenc	%zmm26,%zmm12,%zmm12
	vaesenc	%zmm26,%zmm13,%zmm13
	vpsrldq	$8,%zmm2,%zmm3
	vpslldq	$8,%zmm2,%zmm2

	vpxorq	%zmm2,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpshufd	$0x4e,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm5,%zmm5
	xorq	%r10,%r10
.align	16
1:
	vbroadcasti64x2	144(%rdx,%r10), %zmm3
	addq	$16,%r10
	vaesenc	%zmm3,%zmm10,%zmm10
	vaesenc	%zmm3,%zmm11,%zmm11
	vaesenc	%zmm3,%zmm12,%zmm12
	vaesenc	%zmm3,%zmm13,%zmm13

	cmpq	%r10,%r11
	jnz	1b
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpshufd	$0x4e,%zmm1,%zmm1
	vpxorq	%zmm1,%zmm5,%zmm5

	vshufi64x2	$0xe,%zmm5,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vaesenclast	%zmm27,%zmm10,%zmm10
	vaesenclast	%zmm27,%zmm11,%zmm11
	vaesenclast	%zmm27,%zmm12,%zmm12
	vaesenclast	%zmm27,%zmm13,%zmm13
	vshufi64x2	$0x1,%ymm5,%ymm5,%ymm3

	vpxorq	%zmm10,%zmm28,%zmm28
	vpxorq	%zmm11,%zmm29,%zmm29
	vpxorq	%zmm12,%zmm30,%zmm30
	vpxorq	%zmm13,%zmm31,%zmm31

	vpxorq	%ymm3,%ymm5,%ymm5

	vmovdqa64	%xmm5,%xmm5

	jmp	.Lgcm_enc_avx512_main_loop

.Lgcm_enc_avx512_hash_tail:



	addq	$15,%rcx
	andq	$0x1f0,%rcx
	movq	%rcx,%r8
	negq	%r8

	movq	$-1,%r10
	shrq	$3,%rcx

	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu8	%zmm28,0(%rsi){%k1}
	vmovdqu64	256(%r9,%r8), %zmm14 {%k5}{z}
	vmovdqu8	%zmm28,%zmm28{%k1}{z}
	vpshufb	%zmm7,%zmm28,%zmm28
	vpxorq	%zmm5,%zmm28,%zmm28
	vpclmulqdq	$0x01,%zmm28,%zmm14,%zmm2
	vpclmulqdq	$0x10,%zmm28,%zmm14,%zmm3
	vpclmulqdq	$0x00,%zmm28,%zmm14,%zmm1
	vpclmulqdq	$0x11,%zmm28,%zmm14,%zmm5
	vpxorq	%zmm3,%zmm2,%zmm2

	subq	$8,%rcx
	jle	.Lgcm_enc_avx512_final_reduce

6:
	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu8	%zmm29,64(%rsi){%k2}
	vmovdqu64	320(%r9,%r8), %zmm14 {%k5}{z}
	vmovdqu8	%zmm29,%zmm29{%k2}{z}
	vpshufb	%zmm7,%zmm29,%zmm29
	vpclmulqdq	$0x01,%zmm29,%zmm14,%zmm4
	vpclmulqdq	$0x11,%zmm29,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm29,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm29,%zmm14,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2

	subq	$8,%rcx
	jle	.Lgcm_enc_avx512_final_reduce

	addq	$64,%r8

	vmovdqa64	%zmm30,%zmm29
	vmovdqa64	%zmm31,%zmm30
	kmovq	%k3,%k2
	kmovq	%k4,%k3
	leaq	64(%rsi),%rsi

	jmp	6b

.Lgcm_enc_avx512_final_reduce:
	vpsrldq	$8,%zmm2,%zmm3
	vpslldq	$8,%zmm2,%zmm2

	vpxorq	%zmm2,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpshufd	$0x4e,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpshufd	$0x4e,%zmm1,%zmm1
	vpxorq	%zmm1,%zmm5,%zmm5

	vshufi64x2	$0xe,%zmm5,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vshufi64x2	$0x1,%ymm5,%ymm5,%ymm3
	vpxorq	%ymm3,%ymm5,%ymm5

	vpshufb	%xmm7,%xmm5,%xmm5

	movq	8(%rsp),%r10
	vmovdqu	%xmm5,(%r10)

	vzeroupper
.Lgcm_enc_avx512_bail:

	ret

.Lgcm_enc_avx512_128B_block:

	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$64,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	kmovq	%r8,%k1
	vmovdqu8	0(%rdi),%zmm28{%k1}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$128,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$64,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k2
	vmovdqu8	64(%rdi),%zmm29{%k2}{z}
	vpxorq	%zmm18,%zmm10,%zmm10
	vpxorq	%zmm18,%zmm11,%zmm11
	vaesenc	%zmm19,%zmm10,%zmm10
	vaesenc	%zmm19,%zmm11,%zmm11
	vaesenc	%zmm20,%zmm10,%zmm10
	vaesenc	%zmm20,%zmm11,%zmm11
	vaesenc	%zmm21,%zmm10,%zmm10
	vaesenc	%zmm21,%zmm11,%zmm11
	vaesenc	%zmm22,%zmm10,%zmm10
	vaesenc	%zmm22,%zmm11,%zmm11
	vaesenc	%zmm23,%zmm10,%zmm10
	vaesenc	%zmm23,%zmm11,%zmm11
	vaesenc	%zmm24,%zmm10,%zmm10
	vaesenc	%zmm24,%zmm11,%zmm11
	vaesenc	%zmm25,%zmm10,%zmm10
	vaesenc	%zmm25,%zmm11,%zmm11
	vaesenc	%zmm26,%zmm10,%zmm10
	vaesenc	%zmm26,%zmm11,%zmm11
	xorq	%r10,%r10
1:
	vbroadcasti64x2	144(%rdx,%r10), %zmm3
	addq	$16,%r10
	vaesenc	%zmm3,%zmm10,%zmm10
	vaesenc	%zmm3,%zmm11,%zmm11

	cmpq	%r10,%r11
	jnz	1b

	vaesenclast	%zmm27,%zmm10,%zmm10
	vaesenclast	%zmm27,%zmm11,%zmm11

	vpxorq	%zmm28,%zmm10,%zmm28
	vpxorq	%zmm29,%zmm11,%zmm29
	jmp	.Lgcm_enc_avx512_hash_tail

.cfi_endproc	
.size	gcm_enc_avx512,.-gcm_enc_avx512
.align	64
.globl	gcm_dec_avx512
.hidden gcm_dec_avx512
.type	gcm_dec_avx512,@function
gcm_dec_avx512:
.cfi_startproc	

	movq	%rcx,%rax

	cmpq	$0,%rcx
	je	.Lgcm_dec_avx512_bail

	vzeroupper

	vbroadcasti64x2	.Lbswap(%rip),%zmm7
	vbroadcasti64x2	.Lpoly(%rip),%zmm6
	vbroadcasti64x2	.Linc(%rip),%zmm8


	movq	8(%rsp),%r10
	vmovdqu64	(%r10),%xmm5

	vbroadcasti64x2	(%r8),%zmm9
	movl	240(%rdx),%r11d

	vpshufb	%xmm7,%xmm5,%xmm5
	vpshufb	%zmm7,%zmm9,%zmm9


	vbroadcasti64x2	0(%rdx),%zmm18
	vbroadcasti64x2	16(%rdx),%zmm19
	vbroadcasti64x2	32(%rdx),%zmm20
	vbroadcasti64x2	48(%rdx),%zmm21
	vbroadcasti64x2	64(%rdx),%zmm22
	vbroadcasti64x2	80(%rdx),%zmm23
	vbroadcasti64x2	96(%rdx),%zmm24
	vbroadcasti64x2	112(%rdx),%zmm25
	vbroadcasti64x2	128(%rdx),%zmm26
	subq	$8,%r11
	shlq	$4,%r11
	vbroadcasti64x2	144(%rdx,%r11), %zmm27



	movq	%rcx,%r10
	addq	$15,%r10
	shrq	$4,%r10

	vpxor	%xmm3,%xmm3,%xmm3
	vpinsrd	$2,%r10d,%xmm3,%xmm3

	vpaddd	%xmm3,%xmm9,%xmm3
	vpshufb	%xmm7,%xmm3,%xmm3
	vmovdqu	%xmm3,(%r8)


	vpaddd	.Linc_init(%rip),%zmm9,%zmm9

	movq	$-1,%r10
	kmovq	%r10,%k1
	kmovq	%r10,%k2
	kmovq	%r10,%k3
	kmovq	%r10,%k4

	cmpq	$256,%rcx
	jb	.Lgcm_dec_avx512_last_block


	vmovdqu64	0(%r9),%zmm14
	vmovdqu64	64(%r9),%zmm15
	vmovdqu64	128(%r9),%zmm16
	vmovdqu64	192(%r9),%zmm17

.align	16
.Lgcm_dec_avx512_main_loop:
	subq	$256,%rcx

	vmovdqu64	0(%rdi),%zmm28

	vmovdqa64	%zmm9,%zmm10
	vpaddd	%zmm8,%zmm10,%zmm11
	vpaddd	%zmm8,%zmm11,%zmm12
	vpaddd	%zmm8,%zmm12,%zmm13
	vpaddd	%zmm8,%zmm13,%zmm9

	vpshufb	%zmm7,%zmm10,%zmm10
	vpshufb	%zmm7,%zmm11,%zmm11
	vpshufb	%zmm7,%zmm12,%zmm12
	vpshufb	%zmm7,%zmm13,%zmm13
	vpxorq	%zmm18,%zmm10,%zmm10
	vpxorq	%zmm18,%zmm11,%zmm11
	vpxorq	%zmm18,%zmm12,%zmm12
	vpxorq	%zmm18,%zmm13,%zmm13
	vmovdqu64	64(%rdi),%zmm29

	vpshufb	%zmm7,%zmm28,%zmm0
	vpxorq	%zmm5,%zmm0,%zmm0
	vpclmulqdq	$0x01,%zmm0,%zmm14,%zmm2
	vpclmulqdq	$0x10,%zmm0,%zmm14,%zmm3
	vpclmulqdq	$0x00,%zmm0,%zmm14,%zmm1
	vpclmulqdq	$0x11,%zmm0,%zmm14,%zmm5
	vpxorq	%zmm3,%zmm2,%zmm2
	vaesenc	%zmm19,%zmm10,%zmm10
	vaesenc	%zmm19,%zmm11,%zmm11
	vaesenc	%zmm19,%zmm12,%zmm12
	vaesenc	%zmm19,%zmm13,%zmm13
	vaesenc	%zmm20,%zmm10,%zmm10
	vaesenc	%zmm20,%zmm11,%zmm11
	vaesenc	%zmm20,%zmm12,%zmm12
	vaesenc	%zmm20,%zmm13,%zmm13

	vmovdqu64	128(%rdi),%zmm30
	vpshufb	%zmm7,%zmm29,%zmm0
	vpclmulqdq	$0x01,%zmm0,%zmm15,%zmm4
	vpclmulqdq	$0x11,%zmm0,%zmm15,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm0,%zmm15,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm0,%zmm15,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
	vaesenc	%zmm21,%zmm10,%zmm10
	vaesenc	%zmm21,%zmm11,%zmm11
	vaesenc	%zmm21,%zmm12,%zmm12
	vaesenc	%zmm21,%zmm13,%zmm13
	vaesenc	%zmm22,%zmm10,%zmm10
	vaesenc	%zmm22,%zmm11,%zmm11
	vaesenc	%zmm22,%zmm12,%zmm12
	vaesenc	%zmm22,%zmm13,%zmm13
	vmovdqu64	192(%rdi),%zmm31
	vpshufb	%zmm7,%zmm30,%zmm0
	vpclmulqdq	$0x01,%zmm0,%zmm16,%zmm4
	vpclmulqdq	$0x11,%zmm0,%zmm16,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm0,%zmm16,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm0,%zmm16,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
	vaesenc	%zmm23,%zmm10,%zmm10
	vaesenc	%zmm23,%zmm11,%zmm11
	vaesenc	%zmm23,%zmm12,%zmm12
	vaesenc	%zmm23,%zmm13,%zmm13
	vaesenc	%zmm24,%zmm10,%zmm10
	vaesenc	%zmm24,%zmm11,%zmm11
	vaesenc	%zmm24,%zmm12,%zmm12
	vaesenc	%zmm24,%zmm13,%zmm13

	vpshufb	%zmm7,%zmm31,%zmm0
	vpclmulqdq	$0x01,%zmm0,%zmm17,%zmm4
	vpclmulqdq	$0x11,%zmm0,%zmm17,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm0,%zmm17,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm0,%zmm17,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2

	leaq	256(%rdi),%rdi
	vaesenc	%zmm25,%zmm10,%zmm10
	vaesenc	%zmm25,%zmm11,%zmm11
	vaesenc	%zmm25,%zmm12,%zmm12
	vaesenc	%zmm25,%zmm13,%zmm13
	vaesenc	%zmm26,%zmm10,%zmm10
	vaesenc	%zmm26,%zmm11,%zmm11
	vaesenc	%zmm26,%zmm12,%zmm12
	vaesenc	%zmm26,%zmm13,%zmm13
	vpsrldq	$8,%zmm2,%zmm3
	vpslldq	$8,%zmm2,%zmm2

	vpxorq	%zmm2,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpshufd	$0x4e,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm5,%zmm5
	xorq	%r10,%r10
.align	16
1:
	vbroadcasti64x2	144(%rdx,%r10), %zmm3
	addq	$16,%r10
	vaesenc	%zmm3,%zmm10,%zmm10
	vaesenc	%zmm3,%zmm11,%zmm11
	vaesenc	%zmm3,%zmm12,%zmm12
	vaesenc	%zmm3,%zmm13,%zmm13
	cmpq	%r10,%r11
	jnz	1b
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpshufd	$0x4e,%zmm1,%zmm1
	vpxorq	%zmm1,%zmm5,%zmm5

	vshufi64x2	$0xe,%zmm5,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vaesenclast	%zmm27,%zmm10,%zmm10
	vaesenclast	%zmm27,%zmm11,%zmm11
	vaesenclast	%zmm27,%zmm12,%zmm12
	vaesenclast	%zmm27,%zmm13,%zmm13

	vshufi64x2	$0x1,%ymm5,%ymm5,%ymm3
	vpxorq	%ymm3,%ymm5,%ymm5

	vmovdqa	%xmm5,%xmm5

	vpxorq	%zmm10,%zmm28,%zmm28
	vpxorq	%zmm11,%zmm29,%zmm29
	vpxorq	%zmm12,%zmm30,%zmm30
	vpxorq	%zmm13,%zmm31,%zmm31

	vmovdqu64	%zmm28,0(%rsi)
	vmovdqu64	%zmm29,64(%rsi)
	vmovdqu64	%zmm30,128(%rsi)
	vmovdqu64	%zmm31,192(%rsi)
	leaq	256(%rsi),%rsi

	cmpq	$256,%rcx
	jge	.Lgcm_dec_avx512_main_loop

.Lgcm_dec_avx512_last_block:
	cmpq	$0,%rcx
	jz	.Lgcm_dec_avx512_finish

	vmovdqa64	%zmm9,%zmm10
	vpaddd	%zmm8,%zmm10,%zmm11
	vpaddd	%zmm8,%zmm11,%zmm12
	vpaddd	%zmm8,%zmm12,%zmm13
	vpaddd	%zmm8,%zmm13,%zmm9

	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$64,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	kmovq	%r8,%k1
	vmovdqu8	0(%rdi),%zmm28{%k1}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$128,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$64,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k2
	vmovdqu8	64(%rdi),%zmm29{%k2}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$192,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$128,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k3
	vmovdqu8	128(%rdi),%zmm30{%k3}{z}
	movq	%rcx,%r8
	movq	$-1,%r10
	negq	%r8
	cmpq	$256,%rcx
	shrxq	%r8,%r10,%r8
	cmovaq	%r10,%r8
	xorq	%r10,%r10
	cmpq	$192,%rcx
	cmovbeq	%r10,%r8
	kmovq	%r8,%k4
	vmovdqu8	192(%rdi),%zmm31{%k4}{z}

	addq	$15,%rcx
	andq	$0x1f0,%rcx
	movq	%rcx,%r8
	negq	%r8

	movq	$-1,%r10
	shrq	$3,%rcx
	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu64	256(%r9,%r8), %zmm14 {%k5}{z}
	vpshufb	%zmm7,%zmm28,%zmm15
	vpxorq	%zmm5,%zmm15,%zmm15
	vpclmulqdq	$0x01,%zmm15,%zmm14,%zmm2
	vpclmulqdq	$0x10,%zmm15,%zmm14,%zmm3
	vpclmulqdq	$0x00,%zmm15,%zmm14,%zmm1
	vpclmulqdq	$0x11,%zmm15,%zmm14,%zmm5
	vpxorq	%zmm3,%zmm2,%zmm2
	vpshufb	%zmm7,%zmm10,%zmm10
	vpshufb	%zmm7,%zmm11,%zmm11
	vpshufb	%zmm7,%zmm12,%zmm12
	vpshufb	%zmm7,%zmm13,%zmm13
	vpxorq	%zmm18,%zmm10,%zmm10
	vpxorq	%zmm18,%zmm11,%zmm11
	vpxorq	%zmm18,%zmm12,%zmm12
	vpxorq	%zmm18,%zmm13,%zmm13
	vaesenc	%zmm19,%zmm10,%zmm10
	vaesenc	%zmm19,%zmm11,%zmm11
	vaesenc	%zmm19,%zmm12,%zmm12
	vaesenc	%zmm19,%zmm13,%zmm13
	vaesenc	%zmm20,%zmm10,%zmm10
	vaesenc	%zmm20,%zmm11,%zmm11
	vaesenc	%zmm20,%zmm12,%zmm12
	vaesenc	%zmm20,%zmm13,%zmm13

	subq	$8,%rcx
	jle	3f
	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu64	320(%r9,%r8), %zmm14 {%k5}{z}
	vpshufb	%zmm7,%zmm29,%zmm15
	vpclmulqdq	$0x01,%zmm15,%zmm14,%zmm4
	vpclmulqdq	$0x11,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm15,%zmm14,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
3:
	vaesenc	%zmm21,%zmm10,%zmm10
	vaesenc	%zmm21,%zmm11,%zmm11
	vaesenc	%zmm21,%zmm12,%zmm12
	vaesenc	%zmm21,%zmm13,%zmm13
	vaesenc	%zmm22,%zmm10,%zmm10
	vaesenc	%zmm22,%zmm11,%zmm11
	vaesenc	%zmm22,%zmm12,%zmm12
	vaesenc	%zmm22,%zmm13,%zmm13

	subq	$8,%rcx
	jle	3f

	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu64	384(%r9,%r8), %zmm14 {%k5}{z}
	vpshufb	%zmm7,%zmm30,%zmm15
	vpclmulqdq	$0x01,%zmm15,%zmm14,%zmm4
	vpclmulqdq	$0x11,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm15,%zmm14,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
3:
	vaesenc	%zmm23,%zmm10,%zmm10
	vaesenc	%zmm23,%zmm11,%zmm11
	vaesenc	%zmm23,%zmm12,%zmm12
	vaesenc	%zmm23,%zmm13,%zmm13
	vaesenc	%zmm24,%zmm10,%zmm10
	vaesenc	%zmm24,%zmm11,%zmm11
	vaesenc	%zmm24,%zmm12,%zmm12
	vaesenc	%zmm24,%zmm13,%zmm13

	subq	$8,%rcx
	jle	3f

	bzhiq	%rcx,%r10,%r10
	kmovq	%r10,%k5

	vmovdqu64	448(%r9,%r8), %zmm14 {%k5}{z}
	vpshufb	%zmm7,%zmm31,%zmm15
	vpclmulqdq	$0x01,%zmm15,%zmm14,%zmm4
	vpclmulqdq	$0x11,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm15,%zmm14,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x10,%zmm15,%zmm14,%zmm3
	vpternlogq	$0x96,%zmm3,%zmm4,%zmm2
3:
	vaesenc	%zmm25,%zmm10,%zmm10
	vaesenc	%zmm25,%zmm11,%zmm11
	vaesenc	%zmm25,%zmm12,%zmm12
	vaesenc	%zmm25,%zmm13,%zmm13
	vaesenc	%zmm26,%zmm10,%zmm10
	vaesenc	%zmm26,%zmm11,%zmm11
	vaesenc	%zmm26,%zmm12,%zmm12
	vaesenc	%zmm26,%zmm13,%zmm13
	xorq	%r10,%r10
.align	16
1:
	vbroadcasti64x2	144(%rdx,%r10), %zmm3
	addq	$16,%r10
	vaesenc	%zmm3,%zmm10,%zmm10
	vaesenc	%zmm3,%zmm11,%zmm11
	vaesenc	%zmm3,%zmm12,%zmm12
	vaesenc	%zmm3,%zmm13,%zmm13
	cmpq	%r10,%r11
	jnz	1b
	vaesenclast	%zmm27,%zmm10,%zmm10
	vaesenclast	%zmm27,%zmm11,%zmm11
	vaesenclast	%zmm27,%zmm12,%zmm12
	vaesenclast	%zmm27,%zmm13,%zmm13
	vpxorq	%zmm10,%zmm28,%zmm28
	vpxorq	%zmm11,%zmm29,%zmm29
	vpxorq	%zmm12,%zmm30,%zmm30
	vpxorq	%zmm13,%zmm31,%zmm31

	vmovdqu8	%zmm28,0(%rsi){%k1}
	vmovdqu8	%zmm29,64(%rsi){%k2}
	vmovdqu8	%zmm30,128(%rsi){%k3}
	vmovdqu8	%zmm31,192(%rsi){%k4}
	vpsrldq	$8,%zmm2,%zmm3
	vpslldq	$8,%zmm2,%zmm2

	vpxorq	%zmm2,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm1,%zmm1
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpshufd	$0x4e,%zmm5,%zmm5
	vpxorq	%zmm3,%zmm5,%zmm5
	vpclmulqdq	$0x00,%zmm6,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm1,%zmm1
	vpshufd	$0x4e,%zmm1,%zmm1
	vpxorq	%zmm1,%zmm5,%zmm5

	vshufi64x2	$0xe,%zmm5,%zmm5,%zmm3
	vpxorq	%zmm3,%zmm5,%zmm5
	vshufi64x2	$0x1,%ymm5,%ymm5,%ymm3
	vpxorq	%ymm3,%ymm5,%ymm5

.Lgcm_dec_avx512_finish:

	vpshufb	%xmm7,%xmm5,%xmm5

	movq	8(%rsp),%r10
	vmovdqu	%xmm5,(%r10)

	vzeroupper
.Lgcm_dec_avx512_bail:
	ret
.cfi_endproc	
.size	gcm_dec_avx512,.-gcm_dec_avx512
#endif
