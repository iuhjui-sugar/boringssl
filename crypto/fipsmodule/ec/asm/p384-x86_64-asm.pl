#! /usr/bin/env perl
#
# The code in this file was adapted from the same code in p256-x86_64-asm.pl

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code.=<<___;
.text
.extern OPENSSL_ia32cap_P

# The polynomial
.align 64
.LOne:
.long 1,1,1,1,1,1,1,1
.LTwo:
.long 2,2,2,2,2,2,2,2
___

my ($val,$in_t,$index)=$win64?("%rcx","%rdx","%r8d"):("%rdi","%rsi","%edx");
my ($ONE,$INDEX,$Ra,$Rb,$Rc,$Rd,$Re,$Rf)=map("%xmm$_",(0..7));
my ($M0,$T0a,$T0b,$T0c,$T0d,$T0e,$T0f,$TMP0)=map("%xmm$_",(8..15));

$code.=<<___;
################################################################################
# void ecp_nistp384_select_w7(uint64_t *val, uint64_t *in_t, int index);
.globl	ecp_nistp384_select_w7
.type	ecp_nistp384_select_w7,\@abi-omnipotent
.align	32
ecp_nistp384_select_w7:
.cfi_startproc
	leaq	OPENSSL_ia32cap_P(%rip), %rax
	mov	8(%rax), %rax
	test	\$`1<<5`, %eax
	jz	.Lavx2_select_w7_p384
___
$code.=<<___	if ($win64);
	lea	-0x88(%rsp), %rax
.LSEH_begin_ecp_nistp384_select_w7:
	.byte	0x48,0x8d,0x60,0xe0		#lea	-0x20(%rax), %rsp
	.byte	0x0f,0x29,0x70,0xe0		#movaps	%xmm6, -0x20(%rax)
	.byte	0x0f,0x29,0x78,0xf0		#movaps	%xmm7, -0x10(%rax)
	.byte	0x44,0x0f,0x29,0x00		#movaps	%xmm8, 0(%rax)
	.byte	0x44,0x0f,0x29,0x48,0x10	#movaps	%xmm9, 0x10(%rax)
	.byte	0x44,0x0f,0x29,0x50,0x20	#movaps	%xmm10, 0x20(%rax)
	.byte	0x44,0x0f,0x29,0x58,0x30	#movaps	%xmm11, 0x30(%rax)
	.byte	0x44,0x0f,0x29,0x60,0x40	#movaps	%xmm12, 0x40(%rax)
	.byte	0x44,0x0f,0x29,0x68,0x50	#movaps	%xmm13, 0x50(%rax)
	.byte	0x44,0x0f,0x29,0x70,0x60	#movaps	%xmm14, 0x60(%rax)
	.byte	0x44,0x0f,0x29,0x78,0x70	#movaps	%xmm15, 0x70(%rax)
___
$code.=<<___;
	movdqa	.LOne(%rip), $M0
	movd	$index, $INDEX

	pxor	$Ra, $Ra
	pxor	$Rb, $Rb
	pxor	$Rc, $Rc
	pxor	$Rd, $Rd
	pxor	$Re, $Re
	pxor	$Rf, $Rf

	movdqa	$M0, $ONE
	pshufd	\$0, $INDEX, $INDEX
	mov	\$64, %rax

.Lselect_loop_sse_w7_p384:
	movdqa	$M0, $TMP0
	paddd	$ONE, $M0
	movdqa	16*0($in_t), $T0a
	movdqa	16*1($in_t), $T0b
	pcmpeqd	$INDEX, $TMP0
	movdqa	16*2($in_t), $T0c
	movdqa	16*3($in_t), $T0d
	movdqa	16*4($in_t), $T0e
	movdqa	16*5($in_t), $T0f
	lea	16*6($in_t), $in_t

	pand	$TMP0, $T0a
	pand	$TMP0, $T0b
	pand	$TMP0, $T0c
	pand	$TMP0, $T0d
	pand	$TMP0, $T0e
	pand	$TMP0, $T0f
	por	$T0a, $Ra
	por	$T0b, $Rb
	por	$T0c, $Rc
	por	$T0d, $Rd
	por	$T0e, $Re
	por	$T0f, $Rf

	dec	%rax
	jnz	.Lselect_loop_sse_w7_p384

	movdqu	$Ra, 16*0($val)
	movdqu	$Rb, 16*1($val)
	movdqu	$Rc, 16*2($val)
	movdqu	$Rd, 16*3($val)
	movdqu	$Re, 16*4($val)
	movdqu	$Rf, 16*5($val)
___
$code.=<<___	if ($win64);
	movaps	(%rsp), %xmm6
	movaps	0x10(%rsp), %xmm7
	movaps	0x20(%rsp), %xmm8
	movaps	0x30(%rsp), %xmm9
	movaps	0x40(%rsp), %xmm10
	movaps	0x50(%rsp), %xmm11
	movaps	0x60(%rsp), %xmm12
	movaps	0x70(%rsp), %xmm13
	movaps	0x80(%rsp), %xmm14
	movaps	0x90(%rsp), %xmm15
	lea	0xa8(%rsp), %rsp
___
$code.=<<___;
	ret
.cfi_endproc
.LSEH_end_ecp_nistp384_select_w7:
.size	ecp_nistp384_select_w7,.-ecp_nistp384_select_w7
___

my ($val,$in_t,$index)=$win64?("%rcx","%rdx","%r8d"):("%rdi","%rsi","%edx");
my ($TWO,$INDEX,$Ra,$Rb,$Rc)=map("%ymm$_",(0..4));
my ($M0,$T0a,$T0b,$T0c,$TMP0)=map("%ymm$_",(5..9));
my ($M1,$T1a,$T1b,$T1c,$TMP1)=map("%ymm$_",(10..14));

$code.=<<___;

################################################################################
# void ecp_nistp384_avx2_select_w7(uint64_t *val, uint64_t *in_t, int index);
.globl	ecp_nistp384_avx2_select_w7
.type	ecp_nistp384_avx2_select_w7,\@abi-omnipotent
.align	32
ecp_nistp384_avx2_select_w7:
.cfi_startproc
.Lavx2_select_w7_p384:
	vzeroupper
___
$code.=<<___	if ($win64);
	mov	%rsp,%r11
	lea	-0x88(%rsp), %rax
.LSEH_begin_ecp_nistp384_avx2_select_w7:
	.byte	0x48,0x8d,0x60,0xe0		# lea	-0x20(%rax), %rsp
	.byte	0xc5,0xf8,0x29,0x70,0xe0	# vmovaps %xmm6, -0x20(%rax)
	.byte	0xc5,0xf8,0x29,0x78,0xf0	# vmovaps %xmm7, -0x10(%rax)
	.byte	0xc5,0x78,0x29,0x40,0x00	# vmovaps %xmm8, 8(%rax)
	.byte	0xc5,0x78,0x29,0x48,0x10	# vmovaps %xmm9, 0x10(%rax)
	.byte	0xc5,0x78,0x29,0x50,0x20	# vmovaps %xmm10, 0x20(%rax)
	.byte	0xc5,0x78,0x29,0x58,0x30	# vmovaps %xmm11, 0x30(%rax)
	.byte	0xc5,0x78,0x29,0x60,0x40	# vmovaps %xmm12, 0x40(%rax)
	.byte	0xc5,0x78,0x29,0x68,0x50	# vmovaps %xmm13, 0x50(%rax)
	.byte	0xc5,0x78,0x29,0x70,0x60	# vmovaps %xmm14, 0x60(%rax)
	.byte	0xc5,0x78,0x29,0x78,0x70	# vmovaps %xmm15, 0x70(%rax)
___
$code.=<<___;
	vmovdqa	.LTwo(%rip), $TWO

	vpxor	$Ra, $Ra, $Ra
	vpxor	$Rb, $Rb, $Rb
	vpxor	$Rc, $Rc, $Rc

	vmovdqa .LOne(%rip), $M0
	vmovdqa .LTwo(%rip), $M1

	vmovd	$index, %xmm1
	vpermd	$INDEX, $Ra, $INDEX
	# Skip index = 0, because it is implicitly the point at infinity

	mov	\$32, %rax
.Lselect_loop_avx2_w7_p384:

	vmovdqa	32*0($in_t), $T0a
	vmovdqa	32*1($in_t), $T0b
	vmovdqa	32*2($in_t), $T0c

	vmovdqa	32*3($in_t), $T1a
	vmovdqa	32*4($in_t), $T1b
	vmovdqa	32*5($in_t), $T1c

	vpcmpeqd	$INDEX, $M0, $TMP0
	vpcmpeqd	$INDEX, $M1, $TMP1

	vpaddd	$TWO, $M0, $M0
	vpaddd	$TWO, $M1, $M1
	lea	32*6($in_t), $in_t

	vpand	$TMP0, $T0a, $T0a
	vpand	$TMP0, $T0b, $T0b
	vpand	$TMP0, $T0c, $T0c
	vpand	$TMP1, $T1a, $T1a
	vpand	$TMP1, $T1b, $T1b
	vpand	$TMP1, $T1c, $T1c

	vpxor	$T0a, $Ra, $Ra
	vpxor	$T0b, $Rb, $Rb
	vpxor	$T0c, $Rc, $Rc
	vpxor	$T1a, $Ra, $Ra
	vpxor	$T1b, $Rb, $Rb
	vpxor	$T1c, $Rc, $Rc

	dec %rax
	jnz .Lselect_loop_avx2_w7_p384

	vmovdqu $Ra, 32*0($val)
	vmovdqu $Rb, 32*1($val)
	vmovdqu $Rc, 32*2($val)
	vzeroupper
___
$code.=<<___	if ($win64);
	movaps	(%rsp), %xmm6
	movaps	0x10(%rsp), %xmm7
	movaps	0x20(%rsp), %xmm8
	movaps	0x30(%rsp), %xmm9
	movaps	0x40(%rsp), %xmm10
	movaps	0x50(%rsp), %xmm11
	movaps	0x60(%rsp), %xmm12
	movaps	0x70(%rsp), %xmm13
	movaps	0x80(%rsp), %xmm14
	movaps	0x90(%rsp), %xmm15
	lea	(%r11), %rsp
___
$code.=<<___;
	ret
.cfi_endproc
.LSEH_end_ecp_nistp384_avx2_select_w7:
.size	ecp_nistp384_avx2_select_w7,.-ecp_nistp384_avx2_select_w7
___

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT";
