; This file is generated from a similarly-named Perl script in the BoringSSL
; source tree. Do not edit by hand.

%ifidn __OUTPUT_FORMAT__, win64
default	rel
%define XMMWORD
%define YMMWORD
%define ZMMWORD
%define _CET_ENDBR

%ifdef BORINGSSL_PREFIX
%include "boringssl_prefix_symbols_nasm.inc"
%endif
section	.text code align=64


section	.rdata rdata align=8

ALIGN	64

$L$poly:
	DQ	0xc200000000000000,0x0000000000000001

$L$bswap:
	DB	7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8

$L$inc:
	DD	0,0,4,0

ALIGN	64

$L$inc_init:
	DD	0,0,0,0
	DD	0,0,1,0
	DD	0,0,2,0
	DD	0,0,3,0

section	.text

ALIGN	64
global	gcm_init_avx512

gcm_init_avx512:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_gcm_init_avx512:
	mov	rdi,rcx
	mov	rsi,rdx




	vzeroupper

	vmovdqu	xmm5,XMMWORD[rsi]
	vmovdqa	xmm6,XMMWORD[$L$poly]
	vmovdqa	xmm7,XMMWORD[$L$bswap]

	lea	rdi,[240+rdi]


	vmovq	rcx,xmm5
	sar	rcx,63
	vmovq	xmm4,rcx
	vpshufd	xmm4,xmm4,0x44
	vpand	xmm4,xmm4,xmm6
	vpsrlq	xmm3,xmm5,63
	vpsrldq	xmm3,xmm3,8
	vpsllq	xmm5,xmm5,1
	vpxor	xmm5,xmm5,xmm4
	vpxor	xmm5,xmm5,xmm3

	vmovdqu	XMMWORD[rdi],xmm5
	lea	rdi,[((-16))+rdi]

	mov	rcx,15
	vmovdqa	xmm3,xmm5



ALIGN	16
$L$aes_gcm_init_loop:
	vpclmulqdq	xmm2,xmm3,xmm5,0x01
	vpclmulqdq	xmm0,xmm3,xmm5,0x00
	vpclmulqdq	xmm1,xmm3,xmm5,0x11
	vpclmulqdq	xmm3,xmm3,xmm5,0x10
	vpxor	xmm2,xmm2,xmm3

	vpsrldq	xmm3,xmm2,8
	vpslldq	xmm2,xmm2,8
	vpxor	xmm1,xmm1,xmm2
	vpxor	xmm0,xmm0,xmm3

	vpclmulqdq	xmm2,xmm1,xmm6,0x00
	vpshufd	xmm1,xmm1,0x4e
	vpxor	xmm1,xmm1,xmm2

	vpclmulqdq	xmm2,xmm1,xmm6,0x00
	vpshufd	xmm1,xmm1,0x4e
	vpxor	xmm1,xmm1,xmm2

	vpxor	xmm3,xmm1,xmm0
	vpshufd	xmm3,xmm3,0x4e

	vmovdqu	XMMWORD[rdi],xmm3
	lea	rdi,[((-16))+rdi]

	dec	rcx
	jne	NEAR $L$aes_gcm_init_loop

	vzeroupper

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	ret


$L$SEH_end_gcm_init_avx512:
ALIGN	64
global	gcm_gmult_avx512

gcm_gmult_avx512:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_gcm_gmult_avx512:
	mov	rdi,rcx
	mov	rsi,rdx



	vzeroupper

	vmovdqu	xmm5,XMMWORD[rdi]
	vmovdqu	xmm8,XMMWORD[240+rsi]

	vmovdqa	xmm6,XMMWORD[$L$poly]
	vmovdqa	xmm7,XMMWORD[$L$bswap]

	vpshufb	xmm5,xmm5,xmm7

	vpclmulqdq	xmm2,xmm8,xmm5,0x01
	vpclmulqdq	xmm4,xmm8,xmm5,0x10
	vpclmulqdq	xmm1,xmm8,xmm5,0x00
	vpclmulqdq	xmm0,xmm8,xmm5,0x11

	vpxor	xmm2,xmm2,xmm4

	vpsrldq	xmm3,xmm2,8
	vpslldq	xmm2,xmm2,8

	vpxor	xmm0,xmm0,xmm2
	vpxor	xmm1,xmm1,xmm3

	vpclmulqdq	xmm3,xmm0,xmm6,0x00
	vpshufd	xmm0,xmm0,0x4e
	vpxor	xmm0,xmm0,xmm3
	vpclmulqdq	xmm3,xmm0,xmm6,0x00
	vpxor	xmm1,xmm1,xmm3
	vpshufd	xmm1,xmm1,0x4e
	vpxor	xmm0,xmm0,xmm1

	vpshufb	xmm5,xmm0,xmm7
	vmovdqu	XMMWORD[rdi],xmm5

	vzeroupper

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	ret

$L$SEH_end_gcm_gmult_avx512:
ALIGN	64
global	gcm_ghash_avx512

gcm_ghash_avx512:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_gcm_ghash_avx512:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9




	shr	rcx,4
	jz	NEAR $L$gcm_ghash_avx512_bail






	vzeroupper

	vmovdqu	xmm5,XMMWORD[rdi]

	vmovdqa	xmm6,XMMWORD[$L$poly]
	vmovdqa	xmm7,XMMWORD[$L$bswap]

	vpshufb	xmm5,xmm5,xmm7




	lea	rsi,[256+rsi]

ALIGN	16
$L$gcm_ghash_avx512_loop:



	mov	r8,16
	cmp	rcx,16
	cmovbe	r8,rcx

	sub	rcx,r8

	shl	r8,4
	sub	rsi,r8


	vmovdqu	xmm8,XMMWORD[rsi]
	vmovdqu	xmm9,XMMWORD[rdx]
	vpshufb	xmm9,xmm9,xmm7
	lea	rsi,[16+rsi]
	lea	rdx,[16+rdx]
	sub	r8,16

	vpxor	xmm9,xmm9,xmm5

	vpclmulqdq	xmm2,xmm8,xmm9,0x01
	vpclmulqdq	xmm1,xmm8,xmm9,0x00
	vpclmulqdq	xmm0,xmm8,xmm9,0x11
	vpclmulqdq	xmm3,xmm8,xmm9,0x10
	vpxor	xmm2,xmm2,xmm3


	jz	NEAR $L$gcm_ghash_avx512_loop_reduce

ALIGN	16
$L$gcm_ghash_avx512_loop_inner:
	vmovdqu	xmm8,XMMWORD[rsi]
	vmovdqu	xmm9,XMMWORD[rdx]
	vpshufb	xmm9,xmm9,xmm7

	vpclmulqdq	xmm3,xmm8,xmm9,0x00
	vpxor	xmm1,xmm1,xmm3
	vpclmulqdq	xmm3,xmm8,xmm9,0x01
	vpxor	xmm2,xmm2,xmm3
	vpclmulqdq	xmm3,xmm8,xmm9,0x11
	vpxor	xmm0,xmm0,xmm3
	vpclmulqdq	xmm3,xmm8,xmm9,0x10
	vpxor	xmm2,xmm2,xmm3

	lea	rsi,[16+rsi]
	lea	rdx,[16+rdx]
	sub	r8,16

	jnz	NEAR $L$gcm_ghash_avx512_loop_inner

$L$gcm_ghash_avx512_loop_reduce:
	vpsrldq	xmm3,xmm2,8
	vpslldq	xmm2,xmm2,8

	vpxor	xmm0,xmm0,xmm2
	vpxor	xmm1,xmm1,xmm3

	vpclmulqdq	xmm3,xmm0,xmm6,0x00
	vpshufd	xmm0,xmm0,0x4e
	vpxor	xmm0,xmm0,xmm3

	vpclmulqdq	xmm3,xmm0,xmm6,0x00
	vpxor	xmm1,xmm1,xmm3
	vpshufd	xmm1,xmm1,0x4e
	vpxor	xmm5,xmm0,xmm1

	cmp	rcx,0
	jnz	NEAR $L$gcm_ghash_avx512_loop

	vpshufb	xmm5,xmm5,xmm7
	vmovdqu	XMMWORD[rdi],xmm5

	vzeroupper

$L$gcm_ghash_avx512_bail:

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	ret

$L$SEH_end_gcm_ghash_avx512:
ALIGN	64
global	gcm_enc_avx512

gcm_enc_avx512:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_gcm_enc_avx512:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD[40+rsp]
	mov	r9,QWORD[48+rsp]




	mov	rax,rcx

	cmp	rcx,0
	je	NEAR $L$gcm_enc_avx512_bail

	vzeroupper

	vbroadcasti64x2	zmm7,ZMMWORD[$L$bswap]
	vbroadcasti64x2	zmm6,ZMMWORD[$L$poly]
	vbroadcasti64x2	zmm8,ZMMWORD[$L$inc]


	mov	r10,QWORD[8+rsp]
	vmovdqu64	xmm5,XMMWORD[r10]

	vbroadcasti64x2	zmm9,ZMMWORD[r8]
	mov	r11d,DWORD[240+rdx]

	vpshufb	xmm5,xmm5,xmm7
	vpshufb	zmm9,zmm9,zmm7


	vbroadcasti64x2	zmm18,ZMMWORD[rdx]
	vbroadcasti64x2	zmm19,ZMMWORD[16+rdx]
	vbroadcasti64x2	zmm20,ZMMWORD[32+rdx]
	vbroadcasti64x2	zmm21,ZMMWORD[48+rdx]
	vbroadcasti64x2	zmm22,ZMMWORD[64+rdx]
	vbroadcasti64x2	zmm23,ZMMWORD[80+rdx]
	vbroadcasti64x2	zmm24,ZMMWORD[96+rdx]
	vbroadcasti64x2	zmm25,ZMMWORD[112+rdx]
	vbroadcasti64x2	zmm26,ZMMWORD[128+rdx]
	sub	r11,8
	shl	r11,4
	vbroadcasti64x2	r11,144(%rdx), %zmm27



	mov	r10,rcx
	add	r10,15
	shr	r10,4

	vpxor	xmm3,xmm3,xmm3
	vpinsrd	xmm3,xmm3,r10d,2


	vpaddd	zmm10,zmm9,ZMMWORD[$L$inc_init]
	vpaddd	xmm3,xmm9,xmm3
	vpaddd	zmm11,zmm10,zmm8
	vpaddd	zmm12,zmm11,zmm8
	vpaddd	zmm13,zmm12,zmm8
	vpaddd	zmm9,zmm13,zmm8
	vpshufb	xmm3,xmm3,xmm7
	vmovdqu	XMMWORD[r8],xmm3

	vpshufb	zmm10,zmm10,zmm7
	vpshufb	zmm11,zmm11,zmm7
	vpshufb	zmm12,zmm12,zmm7
	vpshufb	zmm13,zmm13,zmm7

	mov	r10,-1
	kmovq	k1,r10
	kmovq	k2,r10
	kmovq	k3,r10
	kmovq	k4,r10

	cmp	rcx,16*16
	jae	NEAR 1f

	cmp	rcx,8*16
	jbe	NEAR $L$gcm_enc_avx512_128B_block



	vmovdqu8	zmm28,ZMMWORD[rdi]
	vmovdqu8	zmm29,ZMMWORD[64+rdi]
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,192
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,128
	cmovbe	r8,r10
	kmovq	k3,r8
	vmovdqu8	zmm30,ZMMWORD[128+rdi]{%k3}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,256
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,192
	cmovbe	r8,r10
	kmovq	k4,r8
	vmovdqu8	zmm31,ZMMWORD[192+rdi]{%k4}{z}

	jmp	NEAR 2f
1:
	vmovdqu64	zmm28,ZMMWORD[rdi]
	vmovdqu64	zmm29,ZMMWORD[64+rdi]
	vmovdqu64	zmm30,ZMMWORD[128+rdi]
	vmovdqu64	zmm31,ZMMWORD[192+rdi]
2:
	lea	rdi,[256+rdi]
	vpxorq	zmm10,zmm10,zmm18
	vpxorq	zmm11,zmm11,zmm18
	vpxorq	zmm12,zmm12,zmm18
	vpxorq	zmm13,zmm13,zmm18
	vaesenc	zmm10,zmm10,zmm19
	vaesenc	zmm11,zmm11,zmm19
	vaesenc	zmm12,zmm12,zmm19
	vaesenc	zmm13,zmm13,zmm19
	vaesenc	zmm10,zmm10,zmm20
	vaesenc	zmm11,zmm11,zmm20
	vaesenc	zmm12,zmm12,zmm20
	vaesenc	zmm13,zmm13,zmm20
	vaesenc	zmm10,zmm10,zmm21
	vaesenc	zmm11,zmm11,zmm21
	vaesenc	zmm12,zmm12,zmm21
	vaesenc	zmm13,zmm13,zmm21
	vaesenc	zmm10,zmm10,zmm22
	vaesenc	zmm11,zmm11,zmm22
	vaesenc	zmm12,zmm12,zmm22
	vaesenc	zmm13,zmm13,zmm22
	vaesenc	zmm10,zmm10,zmm23
	vaesenc	zmm11,zmm11,zmm23
	vaesenc	zmm12,zmm12,zmm23
	vaesenc	zmm13,zmm13,zmm23
	vaesenc	zmm10,zmm10,zmm24
	vaesenc	zmm11,zmm11,zmm24
	vaesenc	zmm12,zmm12,zmm24
	vaesenc	zmm13,zmm13,zmm24
	vaesenc	zmm10,zmm10,zmm25
	vaesenc	zmm11,zmm11,zmm25
	vaesenc	zmm12,zmm12,zmm25
	vaesenc	zmm13,zmm13,zmm25
	vaesenc	zmm10,zmm10,zmm26
	vaesenc	zmm11,zmm11,zmm26
	vaesenc	zmm12,zmm12,zmm26
	vaesenc	zmm13,zmm13,zmm26
	xor	r10,r10
1:
	vbroadcasti64x2	r10,144(%rdx), %zmm3
	add	r10,16
	vaesenc	zmm10,zmm10,zmm3
	vaesenc	zmm11,zmm11,zmm3
	vaesenc	zmm12,zmm12,zmm3
	vaesenc	zmm13,zmm13,zmm3

	cmp	r11,r10
	jnz	NEAR 1b
	vaesenclast	zmm10,zmm10,zmm27
	vaesenclast	zmm11,zmm11,zmm27
	vaesenclast	zmm12,zmm12,zmm27
	vaesenclast	zmm13,zmm13,zmm27

	vpxorq	zmm28,zmm10,zmm28
	vpxorq	zmm29,zmm11,zmm29
	vpxorq	zmm30,zmm12,zmm30
	vpxorq	zmm31,zmm13,zmm31


	vmovdqu64	zmm14,ZMMWORD[r9]
	vmovdqu64	zmm15,ZMMWORD[64+r9]
	vmovdqu64	zmm16,ZMMWORD[128+r9]
	vmovdqu64	zmm17,ZMMWORD[192+r9]

ALIGN	16
$L$gcm_enc_avx512_main_loop:
	cmp	rcx,256
	jbe	NEAR $L$gcm_enc_avx512_hash_tail



	sub	rcx,256

	vmovdqa64	zmm10,zmm9
	vmovdqu8	ZMMWORD[rsi],zmm28
	vpaddd	zmm11,zmm9,zmm8
	vmovdqu8	ZMMWORD[64+rsi],zmm29
	vpaddd	zmm12,zmm11,zmm8
	vmovdqu8	ZMMWORD[128+rsi],zmm30
	vpaddd	zmm13,zmm12,zmm8
	vmovdqu8	ZMMWORD[192+rsi],zmm31
	vpaddd	zmm9,zmm13,zmm8

	lea	rsi,[256+rsi]
	vpshufb	zmm28,zmm28,zmm7
	vpshufb	zmm10,zmm10,zmm7
	vpshufb	zmm11,zmm11,zmm7
	vpshufb	zmm12,zmm12,zmm7
	vpshufb	zmm13,zmm13,zmm7
	vpxorq	zmm28,zmm28,zmm5
	vpxorq	zmm10,zmm10,zmm18
	vpxorq	zmm11,zmm11,zmm18
	vpxorq	zmm12,zmm12,zmm18
	vpxorq	zmm13,zmm13,zmm18
	vpshufb	zmm29,zmm29,zmm7
	vpclmulqdq	zmm2,zmm14,zmm28,0x01
	vpclmulqdq	zmm3,zmm14,zmm28,0x10
	vpclmulqdq	zmm1,zmm14,zmm28,0x00
	vpclmulqdq	zmm5,zmm14,zmm28,0x11
	vpxorq	zmm2,zmm2,zmm3
	vaesenc	zmm10,zmm10,zmm19
	vaesenc	zmm11,zmm11,zmm19
	vaesenc	zmm12,zmm12,zmm19
	vaesenc	zmm13,zmm13,zmm19
	vaesenc	zmm10,zmm10,zmm20
	vaesenc	zmm11,zmm11,zmm20
	vaesenc	zmm12,zmm12,zmm20
	vaesenc	zmm13,zmm13,zmm20
	vpshufb	zmm30,zmm30,zmm7
	vpclmulqdq	zmm4,zmm15,zmm29,0x01
	vpclmulqdq	zmm3,zmm15,zmm29,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm15,zmm29,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm15,zmm29,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
	vaesenc	zmm10,zmm10,zmm21
	vaesenc	zmm11,zmm11,zmm21
	vaesenc	zmm12,zmm12,zmm21
	vaesenc	zmm13,zmm13,zmm21
	vaesenc	zmm10,zmm10,zmm22
	vaesenc	zmm11,zmm11,zmm22
	vaesenc	zmm12,zmm12,zmm22
	vaesenc	zmm13,zmm13,zmm22
	vpshufb	zmm31,zmm31,zmm7
	vpclmulqdq	zmm4,zmm16,zmm30,0x01
	vpclmulqdq	zmm3,zmm16,zmm30,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm16,zmm30,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm16,zmm30,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
	vaesenc	zmm10,zmm10,zmm23
	vaesenc	zmm11,zmm11,zmm23
	vaesenc	zmm12,zmm12,zmm23
	vaesenc	zmm13,zmm13,zmm23
	vaesenc	zmm10,zmm10,zmm24
	vaesenc	zmm11,zmm11,zmm24
	vaesenc	zmm12,zmm12,zmm24
	vaesenc	zmm13,zmm13,zmm24
	vpclmulqdq	zmm4,zmm17,zmm31,0x01
	vpclmulqdq	zmm3,zmm17,zmm31,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm17,zmm31,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm17,zmm31,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96

	cmp	rcx,256
	jae	NEAR 1f



	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,64
	shrx	r8,r10,r8
	cmova	r8,r10
	kmovq	k1,r8
	vmovdqu8	zmm28,ZMMWORD[rdi]{%k1}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,128
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,64
	cmovbe	r8,r10
	kmovq	k2,r8
	vmovdqu8	zmm29,ZMMWORD[64+rdi]{%k2}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,192
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,128
	cmovbe	r8,r10
	kmovq	k3,r8
	vmovdqu8	zmm30,ZMMWORD[128+rdi]{%k3}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,256
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,192
	cmovbe	r8,r10
	kmovq	k4,r8
	vmovdqu8	zmm31,ZMMWORD[192+rdi]{%k4}{z}

	jmp	NEAR 2f
1:

	vmovdqu64	zmm28,ZMMWORD[rdi]
	vmovdqu64	zmm29,ZMMWORD[64+rdi]
	vmovdqu64	zmm30,ZMMWORD[128+rdi]
	vmovdqu64	zmm31,ZMMWORD[192+rdi]
2:
	lea	rdi,[256+rdi]
	vaesenc	zmm10,zmm10,zmm25
	vaesenc	zmm11,zmm11,zmm25
	vaesenc	zmm12,zmm12,zmm25
	vaesenc	zmm13,zmm13,zmm25
	vaesenc	zmm10,zmm10,zmm26
	vaesenc	zmm11,zmm11,zmm26
	vaesenc	zmm12,zmm12,zmm26
	vaesenc	zmm13,zmm13,zmm26
	vpsrldq	zmm3,zmm2,8
	vpslldq	zmm2,zmm2,8

	vpxorq	zmm5,zmm5,zmm2
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpshufd	zmm5,zmm5,0x4e
	vpxorq	zmm5,zmm5,zmm3
	xor	r10,r10
ALIGN	16
1:
	vbroadcasti64x2	r10,144(%rdx), %zmm3
	add	r10,16
	vaesenc	zmm10,zmm10,zmm3
	vaesenc	zmm11,zmm11,zmm3
	vaesenc	zmm12,zmm12,zmm3
	vaesenc	zmm13,zmm13,zmm3

	cmp	r11,r10
	jnz	NEAR 1b
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpshufd	zmm1,zmm1,0x4e
	vpxorq	zmm5,zmm5,zmm1

	vshufi64x2	zmm3,zmm5,zmm5,0xe
	vpxorq	zmm5,zmm5,zmm3
	vaesenclast	zmm10,zmm10,zmm27
	vaesenclast	zmm11,zmm11,zmm27
	vaesenclast	zmm12,zmm12,zmm27
	vaesenclast	zmm13,zmm13,zmm27
	vshufi64x2	ymm3,ymm5,ymm5,0x1

	vpxorq	zmm28,zmm28,zmm10
	vpxorq	zmm29,zmm29,zmm11
	vpxorq	zmm30,zmm30,zmm12
	vpxorq	zmm31,zmm31,zmm13

	vpxorq	ymm5,ymm5,ymm3

	vmovdqa64	xmm5,xmm5

	jmp	NEAR $L$gcm_enc_avx512_main_loop

$L$gcm_enc_avx512_hash_tail:



	add	rcx,15
	and	rcx,0x1f0
	mov	r8,rcx
	neg	r8

	mov	r10,-1
	shr	rcx,3

	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu8	ZMMWORD[rsi]{k1},zmm28
	vmovdqu64	r8,256(%r9), %zmm14 {%k5}{z}
	vmovdqu8	zmm28,zmm28{%k1}{z}
	vpshufb	zmm28,zmm28,zmm7
	vpxorq	zmm28,zmm28,zmm5
	vpclmulqdq	zmm2,zmm14,zmm28,0x01
	vpclmulqdq	zmm3,zmm14,zmm28,0x10
	vpclmulqdq	zmm1,zmm14,zmm28,0x00
	vpclmulqdq	zmm5,zmm14,zmm28,0x11
	vpxorq	zmm2,zmm2,zmm3

	sub	rcx,8
	jle	NEAR $L$gcm_enc_avx512_final_reduce

6:
	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu8	ZMMWORD[64+rsi]{k2},zmm29
	vmovdqu64	r8,320(%r9), %zmm14 {%k5}{z}
	vmovdqu8	zmm29,zmm29{%k2}{z}
	vpshufb	zmm29,zmm29,zmm7
	vpclmulqdq	zmm4,zmm14,zmm29,0x01
	vpclmulqdq	zmm3,zmm14,zmm29,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm14,zmm29,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm14,zmm29,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96

	sub	rcx,8
	jle	NEAR $L$gcm_enc_avx512_final_reduce

	add	r8,64

	vmovdqa64	zmm29,zmm30
	vmovdqa64	zmm30,zmm31
	kmovq	k2,k3
	kmovq	k3,k4
	lea	rsi,[64+rsi]

	jmp	NEAR 6b

$L$gcm_enc_avx512_final_reduce:
	vpsrldq	zmm3,zmm2,8
	vpslldq	zmm2,zmm2,8

	vpxorq	zmm5,zmm5,zmm2
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpshufd	zmm5,zmm5,0x4e
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpshufd	zmm1,zmm1,0x4e
	vpxorq	zmm5,zmm5,zmm1

	vshufi64x2	zmm3,zmm5,zmm5,0xe
	vpxorq	zmm5,zmm5,zmm3
	vshufi64x2	ymm3,ymm5,ymm5,0x1
	vpxorq	ymm5,ymm5,ymm3

	vpshufb	xmm5,xmm5,xmm7

	mov	r10,QWORD[8+rsp]
	vmovdqu	XMMWORD[r10],xmm5

	vzeroupper
$L$gcm_enc_avx512_bail:

	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	ret

$L$gcm_enc_avx512_128B_block:

	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,64
	shrx	r8,r10,r8
	cmova	r8,r10
	kmovq	k1,r8
	vmovdqu8	zmm28,ZMMWORD[rdi]{%k1}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,128
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,64
	cmovbe	r8,r10
	kmovq	k2,r8
	vmovdqu8	zmm29,ZMMWORD[64+rdi]{%k2}{z}
	vpxorq	zmm10,zmm10,zmm18
	vpxorq	zmm11,zmm11,zmm18
	vaesenc	zmm10,zmm10,zmm19
	vaesenc	zmm11,zmm11,zmm19
	vaesenc	zmm10,zmm10,zmm20
	vaesenc	zmm11,zmm11,zmm20
	vaesenc	zmm10,zmm10,zmm21
	vaesenc	zmm11,zmm11,zmm21
	vaesenc	zmm10,zmm10,zmm22
	vaesenc	zmm11,zmm11,zmm22
	vaesenc	zmm10,zmm10,zmm23
	vaesenc	zmm11,zmm11,zmm23
	vaesenc	zmm10,zmm10,zmm24
	vaesenc	zmm11,zmm11,zmm24
	vaesenc	zmm10,zmm10,zmm25
	vaesenc	zmm11,zmm11,zmm25
	vaesenc	zmm10,zmm10,zmm26
	vaesenc	zmm11,zmm11,zmm26
	xor	r10,r10
1:
	vbroadcasti64x2	r10,144(%rdx), %zmm3
	add	r10,16
	vaesenc	zmm10,zmm10,zmm3
	vaesenc	zmm11,zmm11,zmm3

	cmp	r11,r10
	jnz	NEAR 1b

	vaesenclast	zmm10,zmm10,zmm27
	vaesenclast	zmm11,zmm11,zmm27

	vpxorq	zmm28,zmm10,zmm28
	vpxorq	zmm29,zmm11,zmm29
	jmp	NEAR $L$gcm_enc_avx512_hash_tail


$L$SEH_end_gcm_enc_avx512:
ALIGN	64
global	gcm_dec_avx512

gcm_dec_avx512:
	mov	QWORD[8+rsp],rdi	;WIN64 prologue
	mov	QWORD[16+rsp],rsi
	mov	rax,rsp
$L$SEH_begin_gcm_dec_avx512:
	mov	rdi,rcx
	mov	rsi,rdx
	mov	rdx,r8
	mov	rcx,r9
	mov	r8,QWORD[40+rsp]
	mov	r9,QWORD[48+rsp]




	mov	rax,rcx

	cmp	rcx,0
	je	NEAR $L$gcm_dec_avx512_bail

	vzeroupper

	vbroadcasti64x2	zmm7,ZMMWORD[$L$bswap]
	vbroadcasti64x2	zmm6,ZMMWORD[$L$poly]
	vbroadcasti64x2	zmm8,ZMMWORD[$L$inc]


	mov	r10,QWORD[8+rsp]
	vmovdqu64	xmm5,XMMWORD[r10]

	vbroadcasti64x2	zmm9,ZMMWORD[r8]
	mov	r11d,DWORD[240+rdx]

	vpshufb	xmm5,xmm5,xmm7
	vpshufb	zmm9,zmm9,zmm7


	vbroadcasti64x2	zmm18,ZMMWORD[rdx]
	vbroadcasti64x2	zmm19,ZMMWORD[16+rdx]
	vbroadcasti64x2	zmm20,ZMMWORD[32+rdx]
	vbroadcasti64x2	zmm21,ZMMWORD[48+rdx]
	vbroadcasti64x2	zmm22,ZMMWORD[64+rdx]
	vbroadcasti64x2	zmm23,ZMMWORD[80+rdx]
	vbroadcasti64x2	zmm24,ZMMWORD[96+rdx]
	vbroadcasti64x2	zmm25,ZMMWORD[112+rdx]
	vbroadcasti64x2	zmm26,ZMMWORD[128+rdx]
	sub	r11,8
	shl	r11,4
	vbroadcasti64x2	r11,144(%rdx), %zmm27



	mov	r10,rcx
	add	r10,15
	shr	r10,4

	vpxor	xmm3,xmm3,xmm3
	vpinsrd	xmm3,xmm3,r10d,2

	vpaddd	xmm3,xmm9,xmm3
	vpshufb	xmm3,xmm3,xmm7
	vmovdqu	XMMWORD[r8],xmm3


	vpaddd	zmm9,zmm9,ZMMWORD[$L$inc_init]

	mov	r10,-1
	kmovq	k1,r10
	kmovq	k2,r10
	kmovq	k3,r10
	kmovq	k4,r10

	cmp	rcx,256
	jb	NEAR $L$gcm_dec_avx512_last_block


	vmovdqu64	zmm14,ZMMWORD[r9]
	vmovdqu64	zmm15,ZMMWORD[64+r9]
	vmovdqu64	zmm16,ZMMWORD[128+r9]
	vmovdqu64	zmm17,ZMMWORD[192+r9]

ALIGN	16
$L$gcm_dec_avx512_main_loop:
	sub	rcx,256

	vmovdqu64	zmm28,ZMMWORD[rdi]

	vmovdqa64	zmm10,zmm9
	vpaddd	zmm11,zmm10,zmm8
	vpaddd	zmm12,zmm11,zmm8
	vpaddd	zmm13,zmm12,zmm8
	vpaddd	zmm9,zmm13,zmm8

	vpshufb	zmm10,zmm10,zmm7
	vpshufb	zmm11,zmm11,zmm7
	vpshufb	zmm12,zmm12,zmm7
	vpshufb	zmm13,zmm13,zmm7
	vpxorq	zmm10,zmm10,zmm18
	vpxorq	zmm11,zmm11,zmm18
	vpxorq	zmm12,zmm12,zmm18
	vpxorq	zmm13,zmm13,zmm18
	vmovdqu64	zmm29,ZMMWORD[64+rdi]

	vpshufb	zmm0,zmm28,zmm7
	vpxorq	zmm0,zmm0,zmm5
	vpclmulqdq	zmm2,zmm14,zmm0,0x01
	vpclmulqdq	zmm3,zmm14,zmm0,0x10
	vpclmulqdq	zmm1,zmm14,zmm0,0x00
	vpclmulqdq	zmm5,zmm14,zmm0,0x11
	vpxorq	zmm2,zmm2,zmm3
	vaesenc	zmm10,zmm10,zmm19
	vaesenc	zmm11,zmm11,zmm19
	vaesenc	zmm12,zmm12,zmm19
	vaesenc	zmm13,zmm13,zmm19
	vaesenc	zmm10,zmm10,zmm20
	vaesenc	zmm11,zmm11,zmm20
	vaesenc	zmm12,zmm12,zmm20
	vaesenc	zmm13,zmm13,zmm20

	vmovdqu64	zmm30,ZMMWORD[128+rdi]
	vpshufb	zmm0,zmm29,zmm7
	vpclmulqdq	zmm4,zmm15,zmm0,0x01
	vpclmulqdq	zmm3,zmm15,zmm0,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm15,zmm0,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm15,zmm0,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
	vaesenc	zmm10,zmm10,zmm21
	vaesenc	zmm11,zmm11,zmm21
	vaesenc	zmm12,zmm12,zmm21
	vaesenc	zmm13,zmm13,zmm21
	vaesenc	zmm10,zmm10,zmm22
	vaesenc	zmm11,zmm11,zmm22
	vaesenc	zmm12,zmm12,zmm22
	vaesenc	zmm13,zmm13,zmm22
	vmovdqu64	zmm31,ZMMWORD[192+rdi]
	vpshufb	zmm0,zmm30,zmm7
	vpclmulqdq	zmm4,zmm16,zmm0,0x01
	vpclmulqdq	zmm3,zmm16,zmm0,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm16,zmm0,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm16,zmm0,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
	vaesenc	zmm10,zmm10,zmm23
	vaesenc	zmm11,zmm11,zmm23
	vaesenc	zmm12,zmm12,zmm23
	vaesenc	zmm13,zmm13,zmm23
	vaesenc	zmm10,zmm10,zmm24
	vaesenc	zmm11,zmm11,zmm24
	vaesenc	zmm12,zmm12,zmm24
	vaesenc	zmm13,zmm13,zmm24

	vpshufb	zmm0,zmm31,zmm7
	vpclmulqdq	zmm4,zmm17,zmm0,0x01
	vpclmulqdq	zmm3,zmm17,zmm0,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm17,zmm0,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm17,zmm0,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96

	lea	rdi,[256+rdi]
	vaesenc	zmm10,zmm10,zmm25
	vaesenc	zmm11,zmm11,zmm25
	vaesenc	zmm12,zmm12,zmm25
	vaesenc	zmm13,zmm13,zmm25
	vaesenc	zmm10,zmm10,zmm26
	vaesenc	zmm11,zmm11,zmm26
	vaesenc	zmm12,zmm12,zmm26
	vaesenc	zmm13,zmm13,zmm26
	vpsrldq	zmm3,zmm2,8
	vpslldq	zmm2,zmm2,8

	vpxorq	zmm5,zmm5,zmm2
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpshufd	zmm5,zmm5,0x4e
	vpxorq	zmm5,zmm5,zmm3
	xor	r10,r10
ALIGN	16
1:
	vbroadcasti64x2	r10,144(%rdx), %zmm3
	add	r10,16
	vaesenc	zmm10,zmm10,zmm3
	vaesenc	zmm11,zmm11,zmm3
	vaesenc	zmm12,zmm12,zmm3
	vaesenc	zmm13,zmm13,zmm3
	cmp	r11,r10
	jnz	NEAR 1b
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpshufd	zmm1,zmm1,0x4e
	vpxorq	zmm5,zmm5,zmm1

	vshufi64x2	zmm3,zmm5,zmm5,0xe
	vpxorq	zmm5,zmm5,zmm3
	vaesenclast	zmm10,zmm10,zmm27
	vaesenclast	zmm11,zmm11,zmm27
	vaesenclast	zmm12,zmm12,zmm27
	vaesenclast	zmm13,zmm13,zmm27

	vshufi64x2	ymm3,ymm5,ymm5,0x1
	vpxorq	ymm5,ymm5,ymm3

	vmovdqa	xmm5,xmm5

	vpxorq	zmm28,zmm28,zmm10
	vpxorq	zmm29,zmm29,zmm11
	vpxorq	zmm30,zmm30,zmm12
	vpxorq	zmm31,zmm31,zmm13

	vmovdqu64	ZMMWORD[rsi],zmm28
	vmovdqu64	ZMMWORD[64+rsi],zmm29
	vmovdqu64	ZMMWORD[128+rsi],zmm30
	vmovdqu64	ZMMWORD[192+rsi],zmm31
	lea	rsi,[256+rsi]

	cmp	rcx,256
	jge	NEAR $L$gcm_dec_avx512_main_loop

$L$gcm_dec_avx512_last_block:
	cmp	rcx,0
	jz	NEAR $L$gcm_dec_avx512_finish

	vmovdqa64	zmm10,zmm9
	vpaddd	zmm11,zmm10,zmm8
	vpaddd	zmm12,zmm11,zmm8
	vpaddd	zmm13,zmm12,zmm8
	vpaddd	zmm9,zmm13,zmm8

	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,64
	shrx	r8,r10,r8
	cmova	r8,r10
	kmovq	k1,r8
	vmovdqu8	zmm28,ZMMWORD[rdi]{%k1}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,128
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,64
	cmovbe	r8,r10
	kmovq	k2,r8
	vmovdqu8	zmm29,ZMMWORD[64+rdi]{%k2}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,192
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,128
	cmovbe	r8,r10
	kmovq	k3,r8
	vmovdqu8	zmm30,ZMMWORD[128+rdi]{%k3}{z}
	mov	r8,rcx
	mov	r10,-1
	neg	r8
	cmp	rcx,256
	shrx	r8,r10,r8
	cmova	r8,r10
	xor	r10,r10
	cmp	rcx,192
	cmovbe	r8,r10
	kmovq	k4,r8
	vmovdqu8	zmm31,ZMMWORD[192+rdi]{%k4}{z}

	add	rcx,15
	and	rcx,0x1f0
	mov	r8,rcx
	neg	r8

	mov	r10,-1
	shr	rcx,3
	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu64	r8,256(%r9), %zmm14 {%k5}{z}
	vpshufb	zmm15,zmm28,zmm7
	vpxorq	zmm15,zmm15,zmm5
	vpclmulqdq	zmm2,zmm14,zmm15,0x01
	vpclmulqdq	zmm3,zmm14,zmm15,0x10
	vpclmulqdq	zmm1,zmm14,zmm15,0x00
	vpclmulqdq	zmm5,zmm14,zmm15,0x11
	vpxorq	zmm2,zmm2,zmm3
	vpshufb	zmm10,zmm10,zmm7
	vpshufb	zmm11,zmm11,zmm7
	vpshufb	zmm12,zmm12,zmm7
	vpshufb	zmm13,zmm13,zmm7
	vpxorq	zmm10,zmm10,zmm18
	vpxorq	zmm11,zmm11,zmm18
	vpxorq	zmm12,zmm12,zmm18
	vpxorq	zmm13,zmm13,zmm18
	vaesenc	zmm10,zmm10,zmm19
	vaesenc	zmm11,zmm11,zmm19
	vaesenc	zmm12,zmm12,zmm19
	vaesenc	zmm13,zmm13,zmm19
	vaesenc	zmm10,zmm10,zmm20
	vaesenc	zmm11,zmm11,zmm20
	vaesenc	zmm12,zmm12,zmm20
	vaesenc	zmm13,zmm13,zmm20

	sub	rcx,8
	jle	NEAR 3f
	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu64	r8,320(%r9), %zmm14 {%k5}{z}
	vpshufb	zmm15,zmm29,zmm7
	vpclmulqdq	zmm4,zmm14,zmm15,0x01
	vpclmulqdq	zmm3,zmm14,zmm15,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
3:
	vaesenc	zmm10,zmm10,zmm21
	vaesenc	zmm11,zmm11,zmm21
	vaesenc	zmm12,zmm12,zmm21
	vaesenc	zmm13,zmm13,zmm21
	vaesenc	zmm10,zmm10,zmm22
	vaesenc	zmm11,zmm11,zmm22
	vaesenc	zmm12,zmm12,zmm22
	vaesenc	zmm13,zmm13,zmm22

	sub	rcx,8
	jle	NEAR 3f

	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu64	r8,384(%r9), %zmm14 {%k5}{z}
	vpshufb	zmm15,zmm30,zmm7
	vpclmulqdq	zmm4,zmm14,zmm15,0x01
	vpclmulqdq	zmm3,zmm14,zmm15,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
3:
	vaesenc	zmm10,zmm10,zmm23
	vaesenc	zmm11,zmm11,zmm23
	vaesenc	zmm12,zmm12,zmm23
	vaesenc	zmm13,zmm13,zmm23
	vaesenc	zmm10,zmm10,zmm24
	vaesenc	zmm11,zmm11,zmm24
	vaesenc	zmm12,zmm12,zmm24
	vaesenc	zmm13,zmm13,zmm24

	sub	rcx,8
	jle	NEAR 3f

	bzhi	r10,r10,rcx
	kmovq	k5,r10

	vmovdqu64	r8,448(%r9), %zmm14 {%k5}{z}
	vpshufb	zmm15,zmm31,zmm7
	vpclmulqdq	zmm4,zmm14,zmm15,0x01
	vpclmulqdq	zmm3,zmm14,zmm15,0x11
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm14,zmm15,0x10
	vpternlogq	zmm2,zmm4,zmm3,0x96
3:
	vaesenc	zmm10,zmm10,zmm25
	vaesenc	zmm11,zmm11,zmm25
	vaesenc	zmm12,zmm12,zmm25
	vaesenc	zmm13,zmm13,zmm25
	vaesenc	zmm10,zmm10,zmm26
	vaesenc	zmm11,zmm11,zmm26
	vaesenc	zmm12,zmm12,zmm26
	vaesenc	zmm13,zmm13,zmm26
	xor	r10,r10
ALIGN	16
1:
	vbroadcasti64x2	r10,144(%rdx), %zmm3
	add	r10,16
	vaesenc	zmm10,zmm10,zmm3
	vaesenc	zmm11,zmm11,zmm3
	vaesenc	zmm12,zmm12,zmm3
	vaesenc	zmm13,zmm13,zmm3
	cmp	r11,r10
	jnz	NEAR 1b
	vaesenclast	zmm10,zmm10,zmm27
	vaesenclast	zmm11,zmm11,zmm27
	vaesenclast	zmm12,zmm12,zmm27
	vaesenclast	zmm13,zmm13,zmm27
	vpxorq	zmm28,zmm28,zmm10
	vpxorq	zmm29,zmm29,zmm11
	vpxorq	zmm30,zmm30,zmm12
	vpxorq	zmm31,zmm31,zmm13

	vmovdqu8	ZMMWORD[rsi]{k1},zmm28
	vmovdqu8	ZMMWORD[64+rsi]{k2},zmm29
	vmovdqu8	ZMMWORD[128+rsi]{k3},zmm30
	vmovdqu8	ZMMWORD[192+rsi]{k4},zmm31
	vpsrldq	zmm3,zmm2,8
	vpslldq	zmm2,zmm2,8

	vpxorq	zmm5,zmm5,zmm2
	vpxorq	zmm1,zmm1,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpshufd	zmm5,zmm5,0x4e
	vpxorq	zmm5,zmm5,zmm3
	vpclmulqdq	zmm3,zmm5,zmm6,0x00
	vpxorq	zmm1,zmm1,zmm3
	vpshufd	zmm1,zmm1,0x4e
	vpxorq	zmm5,zmm5,zmm1

	vshufi64x2	zmm3,zmm5,zmm5,0xe
	vpxorq	zmm5,zmm5,zmm3
	vshufi64x2	ymm3,ymm5,ymm5,0x1
	vpxorq	ymm5,ymm5,ymm3

$L$gcm_dec_avx512_finish:

	vpshufb	xmm5,xmm5,xmm7

	mov	r10,QWORD[8+rsp]
	vmovdqu	XMMWORD[r10],xmm5

	vzeroupper
$L$gcm_dec_avx512_bail:
	mov	rdi,QWORD[8+rsp]	;WIN64 epilogue
	mov	rsi,QWORD[16+rsp]
	ret

$L$SEH_end_gcm_dec_avx512:
%else
; Work around https://bugzilla.nasm.us/show_bug.cgi?id=3392738
ret
%endif
