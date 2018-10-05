	.text
	.syntax unified
	.eabi_attribute	67, "2.09"	@ Tag_conformance
	.eabi_attribute	6, 10	@ Tag_CPU_arch
	.eabi_attribute	7, 65	@ Tag_CPU_arch_profile
	.eabi_attribute	8, 1	@ Tag_ARM_ISA_use
	.eabi_attribute	9, 2	@ Tag_THUMB_ISA_use
	.fpu	neon
	.eabi_attribute	34, 1	@ Tag_CPU_unaligned_access
	.eabi_attribute	15, 1	@ Tag_ABI_PCS_RW_data
	.eabi_attribute	16, 1	@ Tag_ABI_PCS_RO_data
	.eabi_attribute	17, 2	@ Tag_ABI_PCS_GOT_use
	.eabi_attribute	20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute	21, 1	@ Tag_ABI_FP_exceptions
	.eabi_attribute	23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute	24, 1	@ Tag_ABI_align_needed
	.eabi_attribute	25, 1	@ Tag_ABI_align_preserved
	.eabi_attribute	38, 1	@ Tag_ABI_FP_16bit_format
	.eabi_attribute	18, 4	@ Tag_ABI_PCS_wchar_t
	.eabi_attribute	26, 2	@ Tag_ABI_enum_size
	.eabi_attribute	14, 0	@ Tag_ABI_PCS_R9_use
	.file	"hrss.c"
	.section	.text.poly_Rq_mul,"ax",%progbits
	.hidden	poly_Rq_mul          @ -- Begin function poly_Rq_mul
	.globl	poly_Rq_mul
	.p2align	2
	.type	poly_Rq_mul,%function
	.code	16                      @ @poly_Rq_mul
	.thumb_func
poly_Rq_mul:
.Lfunc_begin0:
	.file	1 "/home/agl/devel/boringssl/build-android" "../crypto/hrss/hrss.c"
	.loc	1 705 0                 @ ../crypto/hrss/hrss.c:705:0
	.fnstart
	.cfi_sections .debug_frame
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.cfi_def_cfa r7, 8
	.save	{r8, r9, r11}
	push.w	{r8, r9, r11}
	.cfi_offset r11, -24
	.cfi_offset r9, -28
	.cfi_offset r8, -32
	.pad	#7072
	sub.w	sp, sp, #7072
	mov	r4, sp
	bfc	r4, #0, #4
	mov	sp, r4
	mov	r4, r0
	ldr	r0, .LCPI0_0
	add.w	lr, sp, #16
	add.w	r8, sp, #12
.LPC0_0:
	add	r0, pc
	movs	r6, #0
	add.w	r5, lr, #4224
	mov	r3, r2
	ldr.w	r9, [r0]
	mov	r2, r1
	ldr.w	r0, [r9]
	str.w	r0, [r8]
.Ltmp0:
	.loc	1 715 3 prologue_end    @ ../crypto/hrss/hrss.c:715:3
	movs	r0, #88
.Ltmp1:
	.file	2 "/home/agl/devel/boringssl/build-android" "../crypto/hrss/../internal.h"
	.loc	2 713 10                @ ../crypto/hrss/../internal.h:713:10
	strh.w	r6, [r1, #1406]
	str.w	r6, [r1, #1402]
	add	r1, sp, #16
.Ltmp2:
	.loc	2 713 10 is_stmt 0      @ ../crypto/hrss/../internal.h:713:10
	strh.w	r6, [r3, #1406]
	str.w	r6, [r3, #1402]
.Ltmp3:
	.loc	1 715 3 is_stmt 1       @ ../crypto/hrss/hrss.c:715:3
	str	r0, [sp]
	mov	r0, r5
	bl	poly_Rq_mul_aarch64_aux
	add.w	r0, r5, #1392
	.loc	1 725 9                 @ ../crypto/hrss/hrss.c:725:9
	vld1.64	{d16, d17}, [r0:128]
	mov.w	r0, #1408
.LBB0_1:                                @ =>This Inner Loop Header: Depth=1
	adds	r1, r5, r6
	.loc	1 726 19                @ ../crypto/hrss/hrss.c:726:19
	vld1.16	{d18, d19}, [r1:128], r0
	.loc	1 725 9                 @ ../crypto/hrss/hrss.c:725:9
	vld1.64	{d20, d21}, [r1:128]
	.loc	1 726 17                @ ../crypto/hrss/hrss.c:726:17
	adds	r1, r4, r6
	.loc	1 723 24                @ ../crypto/hrss/hrss.c:723:24
	adds	r6, #16
	.loc	1 725 9                 @ ../crypto/hrss/hrss.c:725:9
	vext.16	q8, q8, q10, #5
	.loc	1 723 3                 @ ../crypto/hrss/hrss.c:723:3
	cmp.w	r6, #1408
	.loc	1 726 27                @ ../crypto/hrss/hrss.c:726:27
	vadd.i16	q8, q9, q8
	.loc	1 726 17 is_stmt 0      @ ../crypto/hrss/hrss.c:726:17
	vst1.64	{d16, d17}, [r1:128]
	.loc	1 725 9 is_stmt 1       @ ../crypto/hrss/hrss.c:725:9
	vorr	q8, q10, q10
	.loc	1 723 3                 @ ../crypto/hrss/hrss.c:723:3
	bne	.LBB0_1
@ %bb.2:
.Ltmp4:
	.loc	2 713 10                @ ../crypto/hrss/../internal.h:713:10
	movs	r0, #0
	strh.w	r0, [r4, #1406]
	str.w	r0, [r4, #1402]
	ldr.w	r0, [r8]
	ldr.w	r1, [r9]
	subs	r0, r1, r0
.Ltmp5:
	.loc	1 730 1                 @ ../crypto/hrss/hrss.c:730:1
	itttt	eq
	subeq.w	r4, r7, #24
	moveq	sp, r4
	popeq.w	{r8, r9, r11}
	popeq	{r4, r5, r6, r7, pc}
	bl	__stack_chk_fail
.Ltmp6:
	.p2align	2
@ %bb.3:
	.loc	1 0 1 is_stmt 0         @ ../crypto/hrss/hrss.c:0:1
.LCPI0_0:
.Ltmp7:
	.long	__stack_chk_guard(GOT_PREL)-((.LPC0_0+4)-.Ltmp7)
.Lfunc_end0:
	.size	poly_Rq_mul, .Lfunc_end0-poly_Rq_mul
	.cfi_endproc
	.fnend
                                        @ -- End function
	.section	.text.poly_Rq_mul_aarch64_aux,"ax",%progbits
	.p2align	1               @ -- Begin function poly_Rq_mul_aarch64_aux
	.type	poly_Rq_mul_aarch64_aux,%function
	.code	16                      @ @poly_Rq_mul_aarch64_aux
	.thumb_func
poly_Rq_mul_aarch64_aux:
.Lfunc_begin1:
	.loc	1 490 0 is_stmt 1       @ ../crypto/hrss/hrss.c:490:0
	.fnstart
	.cfi_startproc
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.cfi_def_cfa_offset 20
	.cfi_offset lr, -4
	.cfi_offset r7, -8
	.cfi_offset r6, -12
	.cfi_offset r5, -16
	.cfi_offset r4, -20
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.cfi_def_cfa r7, 8
	.save	{r8, r9, r10, r11}
	push.w	{r8, r9, r10, r11}
	.cfi_offset r11, -24
	.cfi_offset r10, -28
	.cfi_offset r9, -32
	.cfi_offset r8, -36
	.pad	#4
	sub	sp, #4
	.vsave	{d8, d9, d10, d11, d12, d13, d14, d15}
	vpush	{d8, d9, d10, d11, d12, d13, d14, d15}
	.cfi_offset d15, -48
	.cfi_offset d14, -56
	.cfi_offset d13, -64
	.cfi_offset d12, -72
	.cfi_offset d11, -80
	.cfi_offset d10, -88
	.cfi_offset d9, -96
	.cfi_offset d8, -104
	.pad	#856
	sub.w	sp, sp, #856
	mov	r4, sp
	bfc	r4, #0, #4
	mov	sp, r4
	mov	r9, r1
	ldr	r1, [r7, #8]
	mov	r8, r3
	mov	r10, r2
	mov	lr, r0
.Ltmp8:
	.loc	1 493 7 prologue_end    @ ../crypto/hrss/hrss.c:493:7
	cmp	r1, #3
	beq.w	.LBB1_3
@ %bb.1:
	cmp	r1, #2
	bne.w	.LBB1_4
@ %bb.2:
	.loc	1 497 16                @ ../crypto/hrss/hrss.c:497:16
	vld1.16	{d20, d21}, [r10:128]!
	.loc	1 498 16                @ ../crypto/hrss/hrss.c:498:16
	add	r0, sp, #816
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vmov.i32	q8, #0x0
	.loc	1 556 5                 @ ../crypto/hrss/hrss.c:556:5
	movs	r1, #30
	.loc	1 498 16                @ ../crypto/hrss/hrss.c:498:16
	vld1.64	{d22, d23}, [r10:128]
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vmov.i32	q9, #0x0
	.loc	1 498 16                @ ../crypto/hrss/hrss.c:498:16
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	add	r0, sp, #768
	vext.16	q13, q11, q8, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #640
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	add.w	r0, r8, #2
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #784
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	vmul.i16	q8, q8, q13
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	add.w	r0, r8, #16
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vext.16	q4, q10, q11, #7
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	vld1.16	{d24[], d25[]}, [r0:16]
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	add	r0, sp, #736
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	vmla.i16	q8, q12, q11
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 526 5                 @ ../crypto/hrss/hrss.c:526:5
	add.w	r0, r8, #18
	vld1.16	{d22[], d23[]}, [r0:16]
	.loc	1 528 5                 @ ../crypto/hrss/hrss.c:528:5
	add	r0, sp, #832
	.loc	1 526 5                 @ ../crypto/hrss/hrss.c:526:5
	vmla.i16	q8, q11, q4
	.loc	1 528 5                 @ ../crypto/hrss/hrss.c:528:5
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	.loc	1 530 5                 @ ../crypto/hrss/hrss.c:530:5
	add.w	r0, r8, #4
	vld1.16	{d22[], d23[]}, [r0:16]
	add	r0, sp, #752
	.loc	1 528 5                 @ ../crypto/hrss/hrss.c:528:5
	vext.16	q13, q4, q13, #7
	.loc	1 530 5                 @ ../crypto/hrss/hrss.c:530:5
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q11, q13
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	add	r0, sp, #672
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vext.16	q11, q9, q10, #7
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #20
	.loc	1 528 5                 @ ../crypto/hrss/hrss.c:528:5
	vext.16	q1, q11, q4, #7
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vld1.16	{d6[], d7[]}, [r0:16]
	.loc	1 535 5                 @ ../crypto/hrss/hrss.c:535:5
	add.w	r0, r8, #6
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vmla.i16	q8, q3, q1
	.loc	1 535 5                 @ ../crypto/hrss/hrss.c:535:5
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #704
	.loc	1 533 5                 @ ../crypto/hrss/hrss.c:533:5
	vext.16	q0, q1, q13, #7
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vmul.i16	q13, q3, q13
	.loc	1 535 5                 @ ../crypto/hrss/hrss.c:535:5
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	vmla.i16	q8, q10, q0
	.loc	1 536 5                 @ ../crypto/hrss/hrss.c:536:5
	add	r0, sp, #624
	.loc	1 528 5                 @ ../crypto/hrss/hrss.c:528:5
	vext.16	q10, q9, q11, #7
	vorr	q12, q10, q10
	.loc	1 533 5                 @ ../crypto/hrss/hrss.c:533:5
	vext.16	q15, q10, q1, #7
	.loc	1 536 5                 @ ../crypto/hrss/hrss.c:536:5
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #22
	vld1.16	{d14[], d15[]}, [r0:16]
	.loc	1 540 5                 @ ../crypto/hrss/hrss.c:540:5
	add.w	r0, r8, #8
	.loc	1 536 5                 @ ../crypto/hrss/hrss.c:536:5
	vmla.i16	q8, q7, q15
	.loc	1 540 5                 @ ../crypto/hrss/hrss.c:540:5
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #656
	.loc	1 538 5                 @ ../crypto/hrss/hrss.c:538:5
	vext.16	q11, q15, q0, #7
	.loc	1 533 5                 @ ../crypto/hrss/hrss.c:533:5
	vext.16	q2, q9, q12, #7
	.loc	1 540 5                 @ ../crypto/hrss/hrss.c:540:5
	vmla.i16	q8, q10, q11
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 541 5                 @ ../crypto/hrss/hrss.c:541:5
	add	r0, sp, #576
	.loc	1 538 5                 @ ../crypto/hrss/hrss.c:538:5
	vext.16	q10, q2, q15, #7
	.loc	1 541 5                 @ ../crypto/hrss/hrss.c:541:5
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
	add.w	r0, r8, #24
	vld1.16	{d24[], d25[]}, [r0:16]
	.loc	1 545 5                 @ ../crypto/hrss/hrss.c:545:5
	add	r0, sp, #688
	.loc	1 541 5                 @ ../crypto/hrss/hrss.c:541:5
	vmla.i16	q8, q12, q10
	.loc	1 543 5                 @ ../crypto/hrss/hrss.c:543:5
	vext.16	q5, q10, q11, #7
	.loc	1 538 5                 @ ../crypto/hrss/hrss.c:538:5
	vext.16	q6, q9, q2, #7
	.loc	1 545 5                 @ ../crypto/hrss/hrss.c:545:5
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #10
	vld1.16	{d28[], d29[]}, [r0:16]
	add	r0, sp, #608
	vmla.i16	q8, q14, q5
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	add.w	r0, r8, #26
	.loc	1 543 5                 @ ../crypto/hrss/hrss.c:543:5
	vext.16	q9, q6, q10, #7
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	vld1.16	{d28[], d29[]}, [r0:16]
	add	r0, sp, #592
	vmla.i16	q8, q14, q9
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #720
	.loc	1 548 5                 @ ../crypto/hrss/hrss.c:548:5
	vext.16	q14, q9, q5, #7
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	add.w	r0, r8, #12
	vld1.16	{d4[], d5[]}, [r0:16]
	add	r0, sp, #800
	vmla.i16	q8, q2, q14
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	add	r0, sp, #832
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #640
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	add	r0, sp, #816
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vmla.i16	q13, q14, q2
	.loc	1 536 5                 @ ../crypto/hrss/hrss.c:536:5
	vmla.i16	q13, q7, q0
	.loc	1 541 5                 @ ../crypto/hrss/hrss.c:541:5
	vmla.i16	q13, q12, q11
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 502 17                @ ../crypto/hrss/hrss.c:502:17
	mov	r0, r8
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	vmul.i16	q0, q14, q11
	.loc	1 502 17                @ ../crypto/hrss/hrss.c:502:17
	vld1.16	{d28[], d29[]}, [r0:16], r1
	.loc	1 509 5                 @ ../crypto/hrss/hrss.c:509:5
	add	r1, sp, #736
	vst1.64	{d28, d29}, [r1:128]    @ 16-byte Spill
	add	r1, sp, #768
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #784
	vmla.i16	q0, q14, q11
	vld1.64	{d10, d11}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #672
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	.loc	1 526 5                 @ ../crypto/hrss/hrss.c:526:5
	add	r1, sp, #832
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	vmla.i16	q0, q5, q4
	.loc	1 526 5                 @ ../crypto/hrss/hrss.c:526:5
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #752
	vld1.64	{d8, d9}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #624
	vld1.64	{d4, d5}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #704
	vmla.i16	q0, q14, q11
	.loc	1 530 5                 @ ../crypto/hrss/hrss.c:530:5
	vmla.i16	q0, q4, q1
	vld1.64	{d2, d3}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #576
	.loc	1 531 5                 @ ../crypto/hrss/hrss.c:531:5
	vmla.i16	q0, q3, q2
	.loc	1 535 5                 @ ../crypto/hrss/hrss.c:535:5
	vmla.i16	q0, q1, q15
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #656
	.loc	1 536 5                 @ ../crypto/hrss/hrss.c:536:5
	vmla.i16	q0, q7, q15
	vld1.64	{d14, d15}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #608
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
	add	r1, sp, #592
	vld1.64	{d28, d29}, [r1:128]    @ 16-byte Reload
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	add	r1, sp, #800
	.loc	1 540 5                 @ ../crypto/hrss/hrss.c:540:5
	vmla.i16	q0, q7, q10
	.loc	1 543 5                 @ ../crypto/hrss/hrss.c:543:5
	vmov.i32	q10, #0x0
	.loc	1 541 5                 @ ../crypto/hrss/hrss.c:541:5
	vmla.i16	q0, q12, q6
	.loc	1 543 5                 @ ../crypto/hrss/hrss.c:543:5
	vext.16	q10, q10, q6, #7
	.loc	1 548 5                 @ ../crypto/hrss/hrss.c:548:5
	vext.16	q12, q10, q9, #7
	.loc	1 545 5                 @ ../crypto/hrss/hrss.c:545:5
	vmla.i16	q0, q3, q9
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	vld1.64	{d18, d19}, [r1:128]    @ 16-byte Reload
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	add	r1, sp, #816
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	vmla.i16	q0, q14, q10
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	vmla.i16	q0, q9, q12
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	vmul.i16	q9, q5, q11
	vld1.64	{d22, d23}, [r1:128]    @ 16-byte Reload
	add	r1, sp, #736
	vld1.64	{d10, d11}, [r1:128]    @ 16-byte Reload
	.loc	1 551 5                 @ ../crypto/hrss/hrss.c:551:5
	add.w	r1, r8, #28
	.loc	1 525 5                 @ ../crypto/hrss/hrss.c:525:5
	vmla.i16	q9, q5, q11
	.loc	1 551 5                 @ ../crypto/hrss/hrss.c:551:5
	vld1.16	{d22[], d23[]}, [r1:16]
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	add	r1, sp, #688
	.loc	1 551 5                 @ ../crypto/hrss/hrss.c:551:5
	vmla.i16	q8, q11, q12
	.loc	1 530 5                 @ ../crypto/hrss/hrss.c:530:5
	vmla.i16	q9, q4, q2
	.loc	1 535 5                 @ ../crypto/hrss/hrss.c:535:5
	vmla.i16	q9, q1, q15
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	vld1.64	{d30, d31}, [r1:128]    @ 16-byte Reload
	.loc	1 555 5                 @ ../crypto/hrss/hrss.c:555:5
	add.w	r1, r8, #14
	.loc	1 546 5                 @ ../crypto/hrss/hrss.c:546:5
	vmla.i16	q13, q14, q15
	.loc	1 548 5                 @ ../crypto/hrss/hrss.c:548:5
	vmov.i32	q14, #0x0
	.loc	1 540 5                 @ ../crypto/hrss/hrss.c:540:5
	vmla.i16	q9, q7, q6
	.loc	1 518 5                 @ ../crypto/hrss/hrss.c:518:5
	vmov.i32	q1, #0x0
	.loc	1 545 5                 @ ../crypto/hrss/hrss.c:545:5
	vmla.i16	q9, q3, q10
	.loc	1 548 5                 @ ../crypto/hrss/hrss.c:548:5
	vext.16	q10, q14, q10, #7
	.loc	1 555 5                 @ ../crypto/hrss/hrss.c:555:5
	vld1.16	{d28[], d29[]}, [r1:16]
	add	r1, sp, #720
	.loc	1 551 5                 @ ../crypto/hrss/hrss.c:551:5
	vmla.i16	q0, q11, q10
	vld1.64	{d6, d7}, [r1:128]      @ 16-byte Reload
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	add	r1, sp, #800
	.loc	1 551 5                 @ ../crypto/hrss/hrss.c:551:5
	vmla.i16	q13, q11, q3
	.loc	1 553 5                 @ ../crypto/hrss/hrss.c:553:5
	vext.16	q15, q12, q3, #7
	vext.16	q11, q10, q12, #7
	.loc	1 555 5                 @ ../crypto/hrss/hrss.c:555:5
	vmla.i16	q8, q14, q15
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	vld1.64	{d24, d25}, [r1:128]    @ 16-byte Reload
	.loc	1 555 5                 @ ../crypto/hrss/hrss.c:555:5
	vmla.i16	q0, q14, q11
	.loc	1 562 5                 @ ../crypto/hrss/hrss.c:562:5
	mov	r1, lr
	.loc	1 550 5                 @ ../crypto/hrss/hrss.c:550:5
	vmla.i16	q9, q12, q10
	.loc	1 556 5                 @ ../crypto/hrss/hrss.c:556:5
	vld1.16	{d24[], d25[]}, [r0:16]
	.loc	1 562 5                 @ ../crypto/hrss/hrss.c:562:5
	movs	r0, #48
	.loc	1 556 5                 @ ../crypto/hrss/hrss.c:556:5
	vmla.i16	q13, q12, q15
	.loc	1 553 5                 @ ../crypto/hrss/hrss.c:553:5
	vext.16	q10, q1, q10, #7
	.loc	1 556 5                 @ ../crypto/hrss/hrss.c:556:5
	vmla.i16	q8, q12, q11
	vmla.i16	q0, q12, q10
	.loc	1 555 5                 @ ../crypto/hrss/hrss.c:555:5
	vmla.i16	q9, q14, q10
	.loc	1 562 5                 @ ../crypto/hrss/hrss.c:562:5
	vst1.16	{d18, d19}, [r1:128], r0
	add.w	r0, lr, #32
	vst1.64	{d26, d27}, [r1:128]
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	b.w	.LBB1_17
.LBB1_3:
	.loc	1 0 5 is_stmt 0         @ ../crypto/hrss/hrss.c:0:5
	movs	r0, #32
	.loc	1 572 16 is_stmt 1      @ ../crypto/hrss/hrss.c:572:16
	add.w	r1, r10, #16
	.loc	1 571 16                @ ../crypto/hrss/hrss.c:571:16
	vld1.16	{d22, d23}, [r10:128], r0
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vmov.i32	q8, #0x0
	.loc	1 573 16                @ ../crypto/hrss/hrss.c:573:16
	add	r0, sp, #752
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vmov.i32	q10, #0x0
	.loc	1 572 16                @ ../crypto/hrss/hrss.c:572:16
	vld1.64	{d18, d19}, [r1:128]
	.loc	1 577 17                @ ../crypto/hrss/hrss.c:577:17
	mov	r1, r8
	vorr	q14, q9, q9
	.loc	1 573 16                @ ../crypto/hrss/hrss.c:573:16
	vld1.64	{d6, d7}, [r10:128]
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vext.16	q1, q3, q8, #7
	vext.16	q15, q9, q3, #7
	.loc	1 573 16                @ ../crypto/hrss/hrss.c:573:16
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	.loc	1 609 5                 @ ../crypto/hrss/hrss.c:609:5
	vext.16	q8, q15, q1, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	add	r0, sp, #624
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #36
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #832
	vmul.i16	q2, q12, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	add.w	r0, r8, #34
	vld1.16	{d24[], d25[]}, [r0:16]
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	add	r0, sp, #256
	vmla.i16	q2, q12, q1
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #64
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vext.16	q13, q11, q9, #7
	vst1.64	{d2, d3}, [r0:128]      @ 16-byte Spill
	.loc	1 609 5                 @ ../crypto/hrss/hrss.c:609:5
	add	r0, sp, #704
	vext.16	q6, q13, q15, #7
	vorr	q15, q13, q13
	vst1.64	{d28, d29}, [r0:128]    @ 16-byte Spill
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	add.w	r0, r8, #38
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vext.16	q12, q10, q11, #7
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	vld1.16	{d18[], d19[]}, [r0:16]
	add	r0, sp, #320
	.loc	1 615 5                 @ ../crypto/hrss/hrss.c:615:5
	vext.16	q8, q6, q8, #7
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	vmla.i16	q2, q9, q8
	.loc	1 609 5                 @ ../crypto/hrss/hrss.c:609:5
	add	r0, sp, #160
	vext.16	q9, q12, q13, #7
	vorr	q7, q8, q8
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	.loc	1 615 5                 @ ../crypto/hrss/hrss.c:615:5
	add	r0, sp, #672
	vorr	q4, q9, q9
	vext.16	q13, q9, q6, #7
	vst1.64	{d30, d31}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	add	r0, sp, #416
	vst1.64	{d12, d13}, [r0:128]    @ 16-byte Spill
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	add	r0, sp, #48
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #40
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	vext.16	q0, q13, q8, #7
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vld1.16	{d22[], d23[]}, [r0:16]
	add	r0, sp, #352
	vorr	q8, q0, q0
	vmla.i16	q2, q11, q0
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
	.loc	1 609 5                 @ ../crypto/hrss/hrss.c:609:5
	vext.16	q11, q10, q12, #7
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 615 5                 @ ../crypto/hrss/hrss.c:615:5
	add	r0, sp, #736
	vext.16	q12, q11, q9, #7
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	add	r0, sp, #640
	vorr	q5, q12, q12
	vext.16	q0, q12, q13, #7
	vst1.64	{d8, d9}, [r0:128]      @ 16-byte Spill
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	add	r0, sp, #272
	.loc	1 615 5                 @ ../crypto/hrss/hrss.c:615:5
	vext.16	q9, q10, q11, #7
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vst1.64	{d0, d1}, [r0:128]      @ 16-byte Spill
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	add.w	r0, r8, #42
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vext.16	q13, q0, q8, #7
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #384
	vmla.i16	q2, q8, q13
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	vext.16	q11, q9, q12, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	add	r0, sp, #496
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vext.16	q12, q11, q0, #7
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vst1.64	{d26, d27}, [r0:128]    @ 16-byte Spill
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	add	r0, sp, #720
	vorr	q0, q12, q12
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	add	r0, sp, #656
	.loc	1 633 5                 @ ../crypto/hrss/hrss.c:633:5
	vext.16	q12, q12, q13, #7
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vst1.64	{d10, d11}, [r0:128]    @ 16-byte Spill
	.loc	1 637 5                 @ ../crypto/hrss/hrss.c:637:5
	add	r0, sp, #464
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add.w	r0, r8, #44
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #400
	vmla.i16	q2, q8, q12
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	add	r0, sp, #784
	.loc	1 621 5                 @ ../crypto/hrss/hrss.c:621:5
	vext.16	q8, q10, q9, #7
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vext.16	q9, q8, q11, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vorr	q8, q11, q11
	vst1.64	{d18, d19}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #592
	.loc	1 633 5                 @ ../crypto/hrss/hrss.c:633:5
	vext.16	q10, q9, q0, #7
	vorr	q9, q0, q0
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	movs	r0, #46
	.loc	1 577 17                @ ../crypto/hrss/hrss.c:577:17
	vld1.16	{d22[], d23[]}, [r1:16], r0
	.loc	1 639 5                 @ ../crypto/hrss/hrss.c:639:5
	add	r0, sp, #512
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #368
	vext.16	q11, q10, q12, #7
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	vld1.16	{d20[], d21[]}, [r1:16]
	.loc	1 649 5                 @ ../crypto/hrss/hrss.c:649:5
	mov	r1, lr
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	vmla.i16	q2, q10, q11
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #176
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #144
	vst1.64	{d4, d5}, [r0:128]      @ 16-byte Spill
	.loc	1 587 5                 @ ../crypto/hrss/hrss.c:587:5
	add.w	r0, r8, #32
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #480
	vmul.i16	q13, q10, q14
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	add.w	r0, r8, #16
	vorr	q14, q3, q3
	vld1.16	{d20[], d21[]}, [r0:16]
	.loc	1 587 5                 @ ../crypto/hrss/hrss.c:587:5
	add	r0, sp, #688
	vmla.i16	q13, q10, q3
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	add.w	r0, r8, #2
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #128
	vmla.i16	q13, q10, q1
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	add.w	r0, r8, #18
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #288
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #768
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #256
	vmla.i16	q13, q10, q11
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	add.w	r0, r8, #4
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #432
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	vmla.i16	q13, q11, q15
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	add.w	r0, r8, #20
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vmla.i16	q13, q12, q10
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vld1.16	{d20[], d21[]}, [r0:16]
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	add	r0, sp, #832
	vorr	q15, q10, q10
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vmla.i16	q13, q10, q6
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	add.w	r0, r8, #6
	vorr	q6, q14, q14
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	vmla.i16	q13, q10, q4
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #608
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	add.w	r0, r8, #22
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vmla.i16	q13, q10, q7
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #240
	vorr	q7, q9, q9
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #816
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #320
	vmla.i16	q13, q10, q12
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	add.w	r0, r8, #8
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #96
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	vmla.i16	q13, q2, q5
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #544
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	add.w	r0, r8, #24
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vmla.i16	q13, q12, q10
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	vld1.16	{d20[], d21[]}, [r0:16]
	add	r0, sp, #224
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #272
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vmla.i16	q13, q10, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	add.w	r0, r8, #10
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vmla.i16	q13, q0, q8
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #576
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #496
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	add.w	r0, r8, #26
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vmla.i16	q13, q8, q10
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #208
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #16
	vmla.i16	q13, q8, q9
	vst1.64	{d14, d15}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #800
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #384
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	add.w	r0, r8, #12
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vmla.i16	q13, q4, q9
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #528
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #464
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	add.w	r0, r8, #28
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vmla.i16	q13, q8, q10
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #192
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #304
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	add	r0, sp, #784
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vmla.i16	q13, q8, q3
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 633 5                 @ ../crypto/hrss/hrss.c:633:5
	add	r0, sp, #336
	.loc	1 627 5                 @ ../crypto/hrss/hrss.c:627:5
	vmov.i32	q8, #0x0
	vext.16	q8, q8, q10, #7
	.loc	1 633 5                 @ ../crypto/hrss/hrss.c:633:5
	vext.16	q10, q8, q9, #7
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #448
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #400
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	add.w	r0, r8, #14
	.loc	1 637 5                 @ ../crypto/hrss/hrss.c:637:5
	vmla.i16	q13, q9, q10
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	vld1.16	{d16[], d17[]}, [r0:16]
	add	r0, sp, #80
	vst1.64	{d16, d17}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #368
	.loc	1 639 5                 @ ../crypto/hrss/hrss.c:639:5
	vext.16	q10, q10, q3, #7
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #560
	vmla.i16	q13, q8, q12
	vst1.64	{d20, d21}, [r0:128]    @ 16-byte Spill
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	add.w	r0, r8, #30
	vld1.16	{d24[], d25[]}, [r0:16]
	add	r0, sp, #112
	vmla.i16	q13, q12, q10
	vst1.64	{d24, d25}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #288
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	add	r0, sp, #64
	vld1.64	{d16, d17}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #480
	vmul.i16	q8, q10, q8
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	add	r0, sp, #768
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	vmla.i16	q8, q14, q6
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	add	r0, sp, #32
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	vmla.i16	q8, q11, q14
	vorr	q11, q15, q15
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vst1.64	{d22, d23}, [r0:128]    @ 16-byte Spill
	add	r0, sp, #624
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	add	r0, sp, #416
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vmla.i16	q8, q15, q14
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #832
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #240
	vmla.i16	q8, q15, q14
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	add	r0, sp, #48
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	add	r0, sp, #816
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	vmla.i16	q8, q14, q15
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #224
	vmla.i16	q8, q2, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	add	r0, sp, #544
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #208
	vmla.i16	q8, q15, q2
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vmla.i16	q8, q0, q5
	vld1.64	{d0, d1}, [r0:128]      @ 16-byte Reload
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	add	r0, sp, #496
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #192
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	add	r0, sp, #464
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	vmla.i16	q8, q0, q2
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	add	r0, sp, #368
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vmla.i16	q8, q4, q7
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vmla.i16	q8, q1, q2
	.loc	1 637 5                 @ ../crypto/hrss/hrss.c:637:5
	vmla.i16	q8, q9, q3
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	add	r0, sp, #704
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	vmla.i16	q8, q12, q9
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #688
	vld1.64	{d24, d25}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vmul.i16	q12, q12, q9
	vld1.64	{d10, d11}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #752
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	.loc	1 587 5                 @ ../crypto/hrss/hrss.c:587:5
	add	r0, sp, #480
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	vmla.i16	q12, q5, q6
	.loc	1 587 5                 @ ../crypto/hrss/hrss.c:587:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #128
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	add	r0, sp, #768
	.loc	1 587 5                 @ ../crypto/hrss/hrss.c:587:5
	vmla.i16	q12, q9, q3
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	add	r0, sp, #672
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vmla.i16	q12, q4, q9
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #160
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	add	r0, sp, #256
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	vmla.i16	q12, q10, q9
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #432
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	add	r0, sp, #416
	.loc	1 607 5                 @ ../crypto/hrss/hrss.c:607:5
	vmla.i16	q12, q9, q6
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	add	r0, sp, #640
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vmla.i16	q12, q2, q9
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	add	r0, sp, #832
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vmla.i16	q12, q11, q9
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	add	r0, sp, #608
	.loc	1 613 5                 @ ../crypto/hrss/hrss.c:613:5
	vmla.i16	q12, q9, q10
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #816
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	add	r0, sp, #656
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vmla.i16	q12, q9, q11
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #720
	vmla.i16	q12, q14, q9
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	add	r0, sp, #320
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #96
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	add	r0, sp, #272
	.loc	1 619 5                 @ ../crypto/hrss/hrss.c:619:5
	vmla.i16	q12, q9, q14
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	add	r0, sp, #592
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vmla.i16	q12, q7, q9
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	add	r0, sp, #784
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	vmla.i16	q12, q15, q9
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #352
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	add	r0, sp, #576
	.loc	1 625 5                 @ ../crypto/hrss/hrss.c:625:5
	vmla.i16	q12, q11, q9
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #16
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	add	r0, sp, #800
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vmla.i16	q12, q9, q11
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	add	r0, sp, #384
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	vmla.i16	q12, q0, q9
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	add	r0, sp, #528
	.loc	1 631 5                 @ ../crypto/hrss/hrss.c:631:5
	vmla.i16	q12, q9, q11
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #304
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	add	r0, sp, #448
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vmla.i16	q12, q9, q15
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 637 5                 @ ../crypto/hrss/hrss.c:637:5
	add	r0, sp, #400
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vmla.i16	q12, q1, q9
	.loc	1 597 5                 @ ../crypto/hrss/hrss.c:597:5
	vmov.i32	q9, #0x0
	.loc	1 633 5                 @ ../crypto/hrss/hrss.c:633:5
	vext.16	q1, q9, q11, #7
	.loc	1 637 5                 @ ../crypto/hrss/hrss.c:637:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #80
	vmla.i16	q12, q9, q1
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	add	r0, sp, #560
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	add	r0, sp, #688
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	vmla.i16	q12, q9, q11
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #704
	vmul.i16	q0, q11, q3
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	add	r0, sp, #672
	vorr	q3, q4, q4
	.loc	1 586 5                 @ ../crypto/hrss/hrss.c:586:5
	vmla.i16	q0, q5, q11
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	add	r0, sp, #288
	vorr	q5, q7, q7
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vmla.i16	q0, q4, q11
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	add	r0, sp, #640
	.loc	1 606 5                 @ ../crypto/hrss/hrss.c:606:5
	vmla.i16	q0, q11, q6
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	add	r0, sp, #32
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vmla.i16	q0, q2, q11
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #608
	vld1.64	{d4, d5}, [r0:128]      @ 16-byte Reload
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	add	r0, sp, #656
	.loc	1 612 5                 @ ../crypto/hrss/hrss.c:612:5
	vmla.i16	q0, q11, q10
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	add	r0, sp, #240
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vmla.i16	q0, q2, q10
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	add	r0, sp, #592
	.loc	1 618 5                 @ ../crypto/hrss/hrss.c:618:5
	vmla.i16	q0, q10, q14
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #784
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	add	r0, sp, #224
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vmla.i16	q0, q7, q10
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #576
	vld1.64	{d14, d15}, [r0:128]    @ 16-byte Reload
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	add	r0, sp, #800
	.loc	1 624 5                 @ ../crypto/hrss/hrss.c:624:5
	vmla.i16	q0, q10, q15
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #336
	vld1.64	{d22, d23}, [r0:128]    @ 16-byte Reload
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	add	r0, sp, #208
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vmla.i16	q0, q7, q10
	.loc	1 630 5                 @ ../crypto/hrss/hrss.c:630:5
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #528
	vld1.64	{d8, d9}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #448
	vmla.i16	q0, q10, q11
	vld1.64	{d20, d21}, [r0:128]    @ 16-byte Reload
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	add	r0, sp, #192
	vld1.64	{d28, d29}, [r0:128]    @ 16-byte Reload
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	add	r0, sp, #752
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vmla.i16	q0, q4, q10
	.loc	1 639 5                 @ ../crypto/hrss/hrss.c:639:5
	vext.16	q10, q1, q10, #7
	.loc	1 636 5                 @ ../crypto/hrss/hrss.c:636:5
	vmla.i16	q0, q14, q1
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vmul.i16	q14, q3, q6
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	add	r0, sp, #512
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	add	r0, sp, #432
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	vmla.i16	q0, q9, q10
	.loc	1 605 5                 @ ../crypto/hrss/hrss.c:605:5
	vmla.i16	q14, q3, q6
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #736
	vld1.64	{d12, d13}, [r0:128]    @ 16-byte Reload
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	add	r0, sp, #720
	.loc	1 611 5                 @ ../crypto/hrss/hrss.c:611:5
	vmla.i16	q14, q3, q6
	.loc	1 617 5                 @ ../crypto/hrss/hrss.c:617:5
	vld1.64	{d6, d7}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #176
	vmla.i16	q14, q2, q3
	.loc	1 623 5                 @ ../crypto/hrss/hrss.c:623:5
	vmla.i16	q14, q5, q15
	vld1.64	{d30, d31}, [r0:128]    @ 16-byte Reload
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	add	r0, sp, #560
	vmla.i16	q13, q15, q10
	.loc	1 629 5                 @ ../crypto/hrss/hrss.c:629:5
	vmla.i16	q14, q7, q11
	.loc	1 639 5                 @ ../crypto/hrss/hrss.c:639:5
	vmov.i32	q11, #0x0
	.loc	1 635 5                 @ ../crypto/hrss/hrss.c:635:5
	vmla.i16	q14, q4, q1
	.loc	1 639 5                 @ ../crypto/hrss/hrss.c:639:5
	vext.16	q11, q11, q1, #7
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	vld1.64	{d2, d3}, [r0:128]      @ 16-byte Reload
	add	r0, sp, #112
	vmla.i16	q8, q15, q1
	.loc	1 641 5                 @ ../crypto/hrss/hrss.c:641:5
	vmla.i16	q14, q9, q11
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	.loc	1 649 5                 @ ../crypto/hrss/hrss.c:649:5
	movs	r0, #80
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	vmla.i16	q12, q9, q10
	.loc	1 649 5                 @ ../crypto/hrss/hrss.c:649:5
	vst1.16	{d28, d29}, [r1:128], r0
	add	r0, sp, #144
	.loc	1 642 5                 @ ../crypto/hrss/hrss.c:642:5
	vmla.i16	q0, q9, q11
	.loc	1 649 5                 @ ../crypto/hrss/hrss.c:649:5
	vld1.64	{d18, d19}, [r0:128]    @ 16-byte Reload
	add.w	r0, lr, #64
	vst1.64	{d18, d19}, [r1:128]
	.loc	1 643 5                 @ ../crypto/hrss/hrss.c:643:5
	vmla.i16	q12, q15, q11
	.loc	1 649 5                 @ ../crypto/hrss/hrss.c:649:5
	vst1.64	{d16, d17}, [r0:128]
	add.w	r0, lr, #16
	vst1.64	{d0, d1}, [r0:128]
	add.w	r0, lr, #48
	vst1.64	{d26, d27}, [r0:128]
	add.w	r0, lr, #32
	vst1.64	{d24, d25}, [r0:128]
	b	.LBB1_17
.LBB1_4:
	.loc	1 659 28                @ ../crypto/hrss/hrss.c:659:28
	lsr.w	r11, r1, #1
	.loc	1 662 31                @ ../crypto/hrss/hrss.c:662:31
	add.w	r0, r8, r11, lsl #4
	.loc	1 661 31                @ ../crypto/hrss/hrss.c:661:31
	str	r0, [sp, #816]          @ 4-byte Spill
	add.w	r0, r10, r11, lsl #4
	.loc	1 660 29                @ ../crypto/hrss/hrss.c:660:29
	str	r0, [sp, #800]          @ 4-byte Spill
	sub.w	r0, r1, r1, lsr #1
	str	r0, [sp, #832]          @ 4-byte Spill
	movs	r0, #0
	.loc	1 666 3                 @ ../crypto/hrss/hrss.c:666:3
	cmp.w	r0, r1, lsr #1
	beq	.LBB1_7
@ %bb.5:
	.loc	1 667 14                @ ../crypto/hrss/hrss.c:667:14
	ldr	r0, [r7, #8]
	lsl.w	r1, r11, #4
	mov	r2, r11
	mov	r3, r8
	mov	r4, lr
	mov	r5, r10
	lsls	r0, r0, #4
	sub.w	r12, r0, r11, lsl #4
.LBB1_6:                                @ =>This Inner Loop Header: Depth=1
	adds	r0, r5, r1
	.loc	1 667 26 is_stmt 0      @ ../crypto/hrss/hrss.c:667:26
	vld1.16	{d16, d17}, [r5:128]!
	.loc	1 668 25 is_stmt 1      @ ../crypto/hrss/hrss.c:668:25
	adds	r6, r3, r1
	.loc	1 666 24                @ ../crypto/hrss/hrss.c:666:24
	subs	r2, #1
	.loc	1 667 14                @ ../crypto/hrss/hrss.c:667:14
	vld1.64	{d18, d19}, [r0:128]
	.loc	1 668 23                @ ../crypto/hrss/hrss.c:668:23
	add.w	r0, r4, r12
	.loc	1 667 24                @ ../crypto/hrss/hrss.c:667:24
	vadd.i16	q8, q8, q9
	.loc	1 667 12 is_stmt 0      @ ../crypto/hrss/hrss.c:667:12
	vst1.16	{d16, d17}, [r4:128]!
	.loc	1 668 37 is_stmt 1      @ ../crypto/hrss/hrss.c:668:37
	vld1.16	{d18, d19}, [r3:128]!
	.loc	1 668 25 is_stmt 0      @ ../crypto/hrss/hrss.c:668:25
	vld1.64	{d16, d17}, [r6:128]
	.loc	1 668 35                @ ../crypto/hrss/hrss.c:668:35
	vadd.i16	q8, q9, q8
	.loc	1 668 23                @ ../crypto/hrss/hrss.c:668:23
	vst1.64	{d16, d17}, [r0:128]
	.loc	1 666 3 is_stmt 1       @ ../crypto/hrss/hrss.c:666:3
	bne	.LBB1_6
.LBB1_7:
	.loc	1 670 7                 @ ../crypto/hrss/hrss.c:670:7
	ldr	r0, [sp, #832]          @ 4-byte Reload
	ldr	r4, [r7, #8]
	cmp	r0, r11
	beq	.LBB1_9
@ %bb.8:
	.loc	1 671 20                @ ../crypto/hrss/hrss.c:671:20
	ldr	r0, [sp, #800]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	.loc	1 671 5 is_stmt 0       @ ../crypto/hrss/hrss.c:671:5
	add.w	r0, lr, r11, lsl #4
	.loc	1 671 18                @ ../crypto/hrss/hrss.c:671:18
	vst1.64	{d16, d17}, [r0:128]
	.loc	1 672 31 is_stmt 1      @ ../crypto/hrss/hrss.c:672:31
	ldr	r0, [sp, #816]          @ 4-byte Reload
	add.w	r0, r0, r11, lsl #4
	vld1.64	{d16, d17}, [r0:128]
	.loc	1 672 5 is_stmt 0       @ ../crypto/hrss/hrss.c:672:5
	add.w	r0, lr, r4, lsl #4
	.loc	1 672 29                @ ../crypto/hrss/hrss.c:672:29
	vst1.64	{d16, d17}, [r0:128]
.LBB1_9:
	.loc	1 0 29                  @ ../crypto/hrss/hrss.c:0:29
	ldr	r4, [sp, #832]          @ 4-byte Reload
	mov	r6, r11
	.loc	1 677 3 is_stmt 1       @ ../crypto/hrss/hrss.c:677:3
	mov	r0, r9
	mov	r2, lr
	str	r4, [sp]
	mov	r5, lr
	.loc	1 675 38                @ ../crypto/hrss/hrss.c:675:38
	add.w	r11, r9, r4, lsl #5
	.loc	1 677 60                @ ../crypto/hrss/hrss.c:677:60
	add.w	r3, lr, r4, lsl #4
	.loc	1 677 3 is_stmt 0       @ ../crypto/hrss/hrss.c:677:3
	mov	r1, r11
	bl	poly_Rq_mul_aarch64_aux
	.loc	1 680 43 is_stmt 1      @ ../crypto/hrss/hrss.c:680:43
	ldr	r0, [r7, #8]
	.loc	1 680 3 is_stmt 0       @ ../crypto/hrss/hrss.c:680:3
	mov	r1, r11
	str	r4, [sp]
	.loc	1 680 43                @ ../crypto/hrss/hrss.c:680:43
	bic	r4, r0, #1
	.loc	1 680 3                 @ ../crypto/hrss/hrss.c:680:3
	ldr	r2, [sp, #800]          @ 4-byte Reload
	ldr	r3, [sp, #816]          @ 4-byte Reload
	.loc	1 680 31                @ ../crypto/hrss/hrss.c:680:31
	add.w	r0, r5, r4, lsl #4
	.loc	1 680 3                 @ ../crypto/hrss/hrss.c:680:3
	bl	poly_Rq_mul_aarch64_aux
	.loc	1 683 3 is_stmt 1       @ ../crypto/hrss/hrss.c:683:3
	mov	r1, r11
	mov	r0, r5
	mov	r2, r10
	mov	r3, r8
	str	r6, [sp]
	mov	r11, r6
	bl	poly_Rq_mul_aarch64_aux
	.loc	1 686 3                 @ ../crypto/hrss/hrss.c:686:3
	cbz	r4, .LBB1_12
@ %bb.10:
	.loc	1 687 19                @ ../crypto/hrss/hrss.c:687:19
	lsl.w	r0, r11, #5
	mov	r1, r4
	mov	r2, r9
	mov	r3, r5
.LBB1_11:                               @ =>This Inner Loop Header: Depth=1
	.loc	1 687 28 is_stmt 0      @ ../crypto/hrss/hrss.c:687:28
	adds	r6, r3, r0
	.loc	1 687 19                @ ../crypto/hrss/hrss.c:687:19
	vld1.16	{d16, d17}, [r3:128]!
	.loc	1 686 24 is_stmt 1      @ ../crypto/hrss/hrss.c:686:24
	subs	r1, #1
	.loc	1 687 28                @ ../crypto/hrss/hrss.c:687:28
	vld1.64	{d18, d19}, [r6:128]
	.loc	1 687 26 is_stmt 0      @ ../crypto/hrss/hrss.c:687:26
	vadd.i16	q8, q9, q8
	.loc	1 687 16                @ ../crypto/hrss/hrss.c:687:16
	vld1.64	{d18, d19}, [r2:128]
	vsub.i16	q8, q9, q8
	vst1.16	{d16, d17}, [r2:128]!
	.loc	1 686 3 is_stmt 1       @ ../crypto/hrss/hrss.c:686:3
	bne	.LBB1_11
.LBB1_12:
	.loc	1 0 3 is_stmt 0         @ ../crypto/hrss/hrss.c:0:3
	ldr	r1, [sp, #832]          @ 4-byte Reload
	.loc	1 689 7 is_stmt 1       @ ../crypto/hrss/hrss.c:689:7
	cmp	r1, r11
	lsl.w	r0, r1, #1
	beq	.LBB1_14
@ %bb.13:
	.loc	1 690 29                @ ../crypto/hrss/hrss.c:690:29
	add.w	r1, r5, r11, lsl #6
	vld1.64	{d16, d17}, [r1:128]
	.loc	1 690 5 is_stmt 0       @ ../crypto/hrss/hrss.c:690:5
	add.w	r1, r9, r4, lsl #4
	.loc	1 690 26                @ ../crypto/hrss/hrss.c:690:26
	vld1.64	{d18, d19}, [r1:128]
	vsub.i16	q8, q9, q8
	vst1.64	{d16, d17}, [r1:128]
	movs	r1, #16
	.loc	1 691 33 is_stmt 1      @ ../crypto/hrss/hrss.c:691:33
	orr.w	r1, r1, r11, lsl #6
	add	r1, r5
	vld1.64	{d16, d17}, [r1:128]
	.loc	1 691 5 is_stmt 0       @ ../crypto/hrss/hrss.c:691:5
	ldr	r1, [r7, #8]
	orr	r1, r1, #1
	add.w	r1, r9, r1, lsl #4
	.loc	1 691 30                @ ../crypto/hrss/hrss.c:691:30
	vld1.64	{d18, d19}, [r1:128]
	vsub.i16	q8, q9, q8
	vst1.64	{d16, d17}, [r1:128]
.LBB1_14:
	.loc	1 695 3 is_stmt 1       @ ../crypto/hrss/hrss.c:695:3
	cbz	r0, .LBB1_17
@ %bb.15:
	.loc	1 696 25                @ ../crypto/hrss/hrss.c:696:25
	add.w	r1, r5, r11, lsl #4
.LBB1_16:                               @ =>This Inner Loop Header: Depth=1
	vld1.16	{d16, d17}, [r9:128]!
	.loc	1 695 24                @ ../crypto/hrss/hrss.c:695:24
	subs	r0, #1
	.loc	1 696 22                @ ../crypto/hrss/hrss.c:696:22
	vld1.64	{d18, d19}, [r1:128]
	vadd.i16	q8, q9, q8
	vst1.16	{d16, d17}, [r1:128]!
	.loc	1 695 3                 @ ../crypto/hrss/hrss.c:695:3
	bne	.LBB1_16
.LBB1_17:
	.loc	1 698 1                 @ ../crypto/hrss/hrss.c:698:1
	sub.w	r4, r7, #96
	mov	sp, r4
	vpop	{d8, d9, d10, d11, d12, d13, d14, d15}
	add	sp, #4
	pop.w	{r8, r9, r10, r11}
	pop	{r4, r5, r6, r7, pc}
.Ltmp9:
.Lfunc_end1:
	.size	poly_Rq_mul_aarch64_aux, .Lfunc_end1-poly_Rq_mul_aarch64_aux
	.cfi_endproc
	.fnend
