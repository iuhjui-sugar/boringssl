#!/usr/bin/env perl

# Copyright (c) 2016, Shay Gueron.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code.=<<___;
.data

.align 16
one:
.quad 1,0
two:
.quad 2,0
three:
.quad 3,0
four:
.quad 4,0
five:
.quad 5,0
six:
.quad 6,0
seven:
.quad 7,0
eight:
.quad 8,0

OR_MASK:
.long 0x00000000,0x00000000,0x00000000,0x80000000
.Lbswap_mask:
.byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
shuff_mask:
.quad 0x0f0f0f0f0f0f0f0f, 0x0f0f0f0f0f0f0f0f
poly:
.quad 0x1, 0xc200000000000000
mask:
.long 0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
con1:
.long 1,1,1,1
con2:
.long 0x1b,0x1b,0x1b,0x1b
con3:
.byte -1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7
CONST_Vector:
.long 0,0,0,0, 0x80000000,0,0,0, 0x80000000,0x80000000,0,0, 0x80000000,0x80000000,0x80000000,0
and_mask:
.long 0,0xffffffff, 0xffffffff, 0xffffffff
___

$code.=<<___;
.text
___


#########################
# a = T
# b = TMP0 - remains unchanged
# res = T
# uses also TMP1,TMP2,TMP3,TMP4
# __m128i GFMUL(__m128i A, __m128i B);

$T = "%xmm0";
$TMP0 = "%xmm1";
$TMP1 = "%xmm2";
$TMP2 = "%xmm3";
$TMP3 = "%xmm4";
$TMP4 = "%xmm5";

$code.=<<___;
.type GFMUL,\@function,2
.align 16
GFMUL:
    vpclmulqdq  \$0x00, $TMP0, $T, $TMP1
    vpclmulqdq  \$0x11, $TMP0, $T, $TMP4
    vpclmulqdq  \$0x10, $TMP0, $T, $TMP2
    vpclmulqdq  \$0x01, $TMP0, $T, $TMP3
    vpxor       $TMP3, $TMP2, $TMP2
    vpslldq     \$8, $TMP2, $TMP3
    vpsrldq     \$8, $TMP2, $TMP2
    vpxor       $TMP3, $TMP1, $TMP1
    vpxor       $TMP2, $TMP4, $TMP4

    vpclmulqdq  \$0x10, poly(%rip), $TMP1, $TMP2
    vpshufd     \$78, $TMP1, $TMP3
    vpxor       $TMP3, $TMP2, $TMP1

    vpclmulqdq  \$0x10, poly(%rip), $TMP1, $TMP2
    vpshufd     \$78, $TMP1, $TMP3
    vpxor       $TMP3, $TMP2, $TMP1

    vpxor       $TMP4, $TMP1, $T
    ret
.size GFMUL, .-GFMUL
___

# Generates the H table
# void aes128gcmsiv_htable_init(uint8_t Htbl[16*8], uint8_t *H);

$Htbl = "%rdi";
$H = "%rsi";
$T = "%xmm0";
$TMP0 = "%xmm1";

$code.=<<___;
.globl	aes128gcmsiv_htable_init
.type	aes128gcmsiv_htable_init,\@function,2
.align	16
aes128gcmsiv_htable_init:
    vmovdqu  ($H), $T
    vmovdqu   $T, $TMP0
    vmovdqu   $T, ($Htbl)     # H
    call  GFMUL
    vmovdqu  $T, 16($Htbl)    # H^2
    call  GFMUL
    vmovdqu  $T, 32($Htbl)    # H^3
    call  GFMUL
    vmovdqu  $T, 48($Htbl)    # H^4
    call  GFMUL
    vmovdqu  $T, 64($Htbl)    # H^5
    call  GFMUL
    vmovdqu  $T, 80($Htbl)    # H^6
    call  GFMUL
    vmovdqu  $T, 96($Htbl)    # H^7
    call  GFMUL
    vmovdqu  $T, 112($Htbl)   # H^8
    ret
.size aes128gcmsiv_htable_init, .-aes128gcmsiv_htable_init
___


# Generates the H table
# void aes128gcmsiv_htable6_init(uint8_t Htbl[16*6], uint8_t *H);
$code.=<<___;
.globl	aes128gcmsiv_htable6_init
.type	aes128gcmsiv_htable6_init,\@function,2
.align	16
aes128gcmsiv_htable6_init:
    vmovdqu  ($H), $T
    vmovdqu   $T, $TMP0
    vmovdqu   $T, ($Htbl)     # H
    call  GFMUL
    vmovdqu  $T, 16($Htbl)    # H^2
    call  GFMUL
    vmovdqu  $T, 32($Htbl)    # H^3
    call  GFMUL
    vmovdqu  $T, 48($Htbl)    # H^4
    call  GFMUL
    vmovdqu  $T, 64($Htbl)    # H^5
    call  GFMUL
    vmovdqu  $T, 80($Htbl)    # H^6
    ret
.size aes128gcmsiv_htable6_init, .-aes128gcmsiv_htable6_init
___

# void aes128gcmsiv_htable_polyval(uint8_t Htbl[16*8], uint8_t *MSG, uint64_t LEN, uint8_t *T);
# parameter 1: %rdi     Htable  - pointer to Htable
# parameter 2: %rsi     INp     - pointer to input
# parameter 3: %rdx     LEN     - length of BUFFER in bytes
# parameter 4: %rcx     T       - pointer to POLYVAL output

$DATA = "%xmm0";
$T = "%xmm1";
$TMP0 = "%xmm3";
$TMP1 = "%xmm4";
$TMP2 = "%xmm5";
$TMP3 = "%xmm6";
$TMP4 = "%xmm7";
$Xhi = "%xmm9";
$IV = "%xmm10";
$Htbl = "%rdi";
$inp = "%rsi";
$len = "%rdx";
$Tp = "%rcx";
$hlp0 = "%r11";

sub SCHOOLBOOK_AAD {
my ($i)=@_;
return <<___;
    vpclmulqdq  \$0x01, ${\eval(16*$i)}($Htbl), $DATA, $TMP3
    vpxor          $TMP3, $TMP2, $TMP2
    vpclmulqdq  \$0x00, ${\eval(16*$i)}($Htbl), $DATA, $TMP3
    vpxor          $TMP3, $TMP0, $TMP0
    vpclmulqdq  \$0x11, ${\eval(16*$i)}($Htbl), $DATA, $TMP3
    vpxor          $TMP3, $TMP1, $TMP1
    vpclmulqdq  \$0x10, ${\eval(16*$i)}($Htbl), $DATA, $TMP3
    vpxor          $TMP3, $TMP2, $TMP2
___
}

$Htbl = "%rdi";
$inp = "%rsi";
$len = "%rdx";
$Tp = "%rcx";
$gtmp0 = "%r10";
$gtmp1 = "%r12";
$gtmp2 = "%r14";
$gtmp3 = "%r15";
$buffer = "%r8";

$code.=<<___;
.globl	aes128gcmsiv_htable_polyval
.type	aes128gcmsiv_htable_polyval,\@function,2
.align	16
aes128gcmsiv_htable_polyval:
    test  $len, $len
    jnz   .LbeginAAD_
    ret

.LbeginAAD_:
    vzeroall
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11

    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq \$16, %rsp
    movq %rsp, $buffer
    movq \$0, 0($buffer)
    movq \$0, 8($buffer)
    vpxor $Xhi, $Xhi, $Xhi
    vmovdqu ($Tp),$T

# We hash 8 blocks each iteration. If the total number of blocks is not a
# multiple of 8, we first hash the leading n%8 blocks.
    movq $len, $hlp0
    andq \$~-128, $hlp0
    movq $len, %r9
    andq \$-16, $hlp0
    andq \$~-16, %r9

    subq \$0x80, $len
    jb .LRemainder_part
    movq \$112, %r10
    vmovdqu ($inp), $DATA
    vpxor    $T, $DATA, $DATA

    vpclmulqdq  \$0x01, ($Htbl, %r10), $DATA, $TMP2
    vpclmulqdq  \$0x00, ($Htbl, %r10), $DATA, $TMP0
    vpclmulqdq  \$0x11, ($Htbl, %r10), $DATA, $TMP1
    vpclmulqdq  \$0x10, ($Htbl, %r10), $DATA, $TMP3
    vpxor       $TMP3, $TMP2, $TMP2

    lea 16($inp), $inp

    # hash remaining prefix bocks (up to 7 total prefix blocks)
.align 64
.Lpre_loop_htable:

    subq \$16, %r10

    vmovdqu     ($inp), $DATA           # next data block

    vpclmulqdq  \$0x00, ($Htbl,%r10), $DATA, $TMP3
    vpxor       $TMP3, $TMP0, $TMP0
    vpclmulqdq  \$0x11, ($Htbl,%r10), $DATA, $TMP3
    vpxor       $TMP3, $TMP1, $TMP1
    vpclmulqdq  \$0x01, ($Htbl,%r10), $DATA, $TMP3
    vpxor       $TMP3, $TMP2, $TMP2
    vpclmulqdq  \$0x10, ($Htbl,%r10), $DATA, $TMP3
    vpxor       $TMP3, $TMP2, $TMP2

    test    %r10, %r10

    leaq 16($inp), $inp

    jnz .Lpre_loop_htable

.Lred1_pre_hash_table:
    vpsrldq \$8, $TMP2, $TMP3
    vpslldq \$8, $TMP2, $TMP2

    vpxor $TMP3, $TMP1, $Xhi
    vpxor $TMP2, $TMP0, $T
    subq \$0x80, $len
    jb .LPre_Remainder_part

.Lmod_loop_:
    jb  .LPre_Remainder_part

    vmovdqu     16*7($inp),$DATA      # Ii

    vpclmulqdq  \$0x01, ($Htbl), $DATA, $TMP2
    vpclmulqdq  \$0x00, ($Htbl), $DATA, $TMP0
    vpclmulqdq  \$0x11, ($Htbl), $DATA, $TMP1
    vpclmulqdq  \$0x10, ($Htbl), $DATA, $TMP3
    vpxor       $TMP3, $TMP2, $TMP2
    #########################################################
    vmovdqu     16*6($inp),$DATA
    ${\SCHOOLBOOK_AAD(1)}
    #########################################################
    vmovdqu     16*5($inp),$DATA

    vpclmulqdq  \$0x10, poly(%rip), $T, $TMP4         #reduction stage 1a
    vpalignr       \$8, $T, $T, $T

    ${\SCHOOLBOOK_AAD(2)}

    vpxor          $TMP4, $T, $T                 #reduction stage 1b
    #########################################################
    vmovdqu     16*4($inp),$DATA

    ${\SCHOOLBOOK_AAD(3)}
    #########################################################
    vmovdqu     16*3($inp),$DATA

    vpclmulqdq  \$0x10, poly(%rip), $T, $TMP4         #reduction stage 2a
    vpalignr       \$8, $T, $T, $T

    ${\SCHOOLBOOK_AAD(4)}

    vpxor          $TMP4, $T, $T                 #reduction stage 2b
    #########################################################
    vmovdqu     16*2($inp),$DATA

    ${\SCHOOLBOOK_AAD(5)}

    vpxor          $Xhi, $T, $T                  #reduction finalize
    #########################################################
    vmovdqu     16*1($inp),$DATA

    ${\SCHOOLBOOK_AAD(6)}
    #########################################################
    vmovdqu     16*0($inp),$DATA
    vpxor          $T,$DATA,$DATA

    ${\SCHOOLBOOK_AAD(7)}
    #########################################################
    vpsrldq \$8, $TMP2, $TMP3
    vpslldq \$8, $TMP2, $TMP2

    vpxor       $TMP3, $TMP1, $Xhi
    vpxor       $TMP2, $TMP0, $T

    lea 16*8($inp), $inp
    subq \$0x80, $len
    jmp .Lmod_loop_

.LPre_Remainder_part:
    vpclmulqdq \$0x10, poly(%rip), $T, $TMP4
    vpalignr \$8, $T, $T, $T
    vpxor $TMP4, $T, $T
    vpxor $TMP0, $TMP0, $TMP0
    vpxor $TMP1, $TMP1, $TMP1
    vpclmulqdq \$0x10, poly(%rip), $T, $TMP4  # reduction stage 2a
    vpalignr \$8, $T, $T, $T
    vpxor $TMP4, $T, $T
    vpxor $TMP2, $TMP2, $TMP2
    vpxor $TMP3, $TMP3, $TMP3
    vpxor $Xhi, $T, $T
    cmp \$-0x80, $len
    je .Lsave_
    addq \$0x80, $len
    jmp .LRemainder_check

.LRemainder_part:
    addq \$0x80, $len
    cmp \$0, $len
    je .Ldone_

.LRemainder_check:
    cmp \$0, %r9
    jne .LRemainder_with_semi_block
    # Remainder has no semi blocks.
    vmovdqu ($inp), $DATA
    vpxor $T, $DATA, $DATA
    subq \$16, $hlp0
    vpclmulqdq \$0x00, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    leaq 16($inp), $inp
    cmpq \$0, $hlp0
    je .Lred1_

.align 64
.Lpre_loop_:
    subq \$16, $hlp0
    vmovdqu ($inp), $DATA  # next data block

    vpclmulqdq \$0x00, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    leaq 16($inp), $inp
    cmpq \$0, $hlp0
    jne .Lpre_loop_
    jmp .Lred1_

.LRemainder_with_semi_block:
    addq \$16, $Htbl
    cmp \$0, $hlp0
    je .Lsemi_block_first
    vmovdqu ($inp), $DATA
    vpxor $T, $DATA, $DATA
    subq \$16, $hlp0
    vpclmulqdq \$0x00, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2

    leaq 16($inp), $inp
    cmp \$0, $hlp0
    je .Lsemiblock

.align 64
.Lpre_loop_semi_block:
    subq \$16, $hlp0
    vmovdqu ($inp), $DATA  # next data block

    vpclmulqdq \$0x00, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl,$hlp0), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    leaq 16($inp), $inp
    cmpq \$0, $hlp0

    jne .Lpre_loop_semi_block

.Lsemiblock:
    subq \$16, $Htbl

    movq %r9, $gtmp0
    shrq \$2, $gtmp0
    movq $gtmp0, $gtmp1
    shlq \$4, $gtmp0
    andq \$~-4, %r9
    leaq CONST_Vector(%rip), $gtmp2
    vmovdqu ($gtmp2, $gtmp0), %xmm10
    vpmaskmovd ($inp), %xmm10, $DATA
    cmp \$0, %r9
    je .NoAddedBytes
    shlq \$2, $gtmp1
    addq $gtmp1, $inp
    movl ($inp), %r13d
    movl %r13d, ($buffer,$gtmp1)
    vpxor ($buffer), $DATA, $DATA

.NoAddedBytes:
    vpclmulqdq \$0x00, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    jmp .Lred1_

.Lsemi_block_first:
    subq \$16, $Htbl
    subq $hlp0, $len
    movq $len, $gtmp0
    shrq \$2, $gtmp0
    movq $gtmp0, $gtmp1
    shlq \$4, $gtmp0
    andq \$~-4, $len
    leaq CONST_Vector(%rip), $gtmp2
    vmovdqu ($gtmp2, $gtmp0), %xmm10
    vpmaskmovd ($inp), %xmm10, $DATA
    cmp \$0, $len
    je .NoAddedBytesSemiBlock
    shlq \$2, $gtmp1
    addq $gtmp1, $inp
    movl ($inp), %r13d
    movl %r13d, ($buffer, $gtmp1)
    vpxor ($buffer), $DATA, $DATA

.NoAddedBytesSemiBlock:
    vpxor $T, $DATA, $DATA
    vpclmulqdq \$0x00, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x01, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, ($Htbl), $DATA, $TMP3
    vpxor $TMP3, $TMP2, $TMP2

########################################################
.Lred1_:
    vpsrldq \$8, $TMP2, $TMP3
    vpslldq \$8, $TMP2, $TMP2

    vpxor $TMP3, $TMP1, $Xhi
    vpxor $TMP2, $TMP0, $T

.Ldone_:
    vpclmulqdq  \$0x10, poly(%rip), $T, $TMP3
    vpalignr    \$8, $T, $T, $T
    vpxor       $TMP3, $T, $T

    vpclmulqdq  \$0x10, poly(%rip), $T, $TMP3
    vpalignr    \$8, $T, $T, $T
    vpxor       $TMP3, $T, $T
    vpxor       $Xhi, $T, $T

.Lsave_:
    vmovdqu     $T,($Tp)
    vzeroall
    addq \$16, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
.size aes128gcmsiv_htable_polyval,.-aes128gcmsiv_htable_polyval
___


$T = "%rdi";
$Hp = "%rsi";
$INp = "%rdx";
$L = "%rcx";
$LOC = "%r10";
$LEN = "%eax";
$H = "%xmm1";
$RES = "%xmm0";

#void aes128gcmsiv_polyval_horner(unsigned char T[16],		// output
#				  const unsigned char* H,	// H
#				  unsigned char* BUF,		// Buffer
#				  unsigned int blocks);		// Len2
#
# parameter 1: %rdi	T	- pointers to POLYVAL output
# parameter 2: %rsi	Hp	- pointer to H (user key)
# parameter 3: %rdx	INp	- pointer to input
# parameter 4: %rcx	L	- total number of blocks in input BUFFER
$code.=<<___;
.globl	aes128gcmsiv_polyval_horner
.type	aes128gcmsiv_polyval_horner,\@function,2
.align	16
aes128gcmsiv_polyval_horner:
    test  $L, $L
    jnz   .LbeginPoly
    ret

.LbeginPoly:
    # We will start with L GFMULS for POLYVAL(BIG_BUFFER)
    # RES = GFMUL(RES, H)

    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r12
    pushq %r13
    pushq %rax
    xor $LOC, $LOC

    movq $L, %r8
    vmovdqu ($Hp), $H
    vmovdqu ($T), $RES

    cmp \$16, %r8
    jb .Lrem
.Lloop:
    vpxor ($INp, $LOC), $RES, $RES  # RES = RES + Xi
    call GFMUL  # RES = RES * H

    add \$16, $LOC
    subq \$16, %r8
    cmp \$16, %r8
    jae .Lloop

.Lrem:
    cmp \$0, %r8
    je .polyend
    movq %r8, $L
    subq \$16, %rsp
    movq \$0, (%rsp)
    movq \$0, 8(%rsp)
    shr \$2, %r8
    movq %r8, %r9
    shlq \$4, %r8
    leaq CONST_Vector(%rip), %r12
    vmovdqu (%r12, %r8), %xmm10
    vpmaskmovd ($INp, $LOC), %xmm10, %xmm10
    andq \$~-4, $L
    cmp \$0, $L
    je .noExtraBytes
    shlq \$2, %r9
    addq %r9, $LOC

.byteloop:
    addq $LOC, $INp
    movl ($INp), %eax
    movl %eax, (%rsp, %r9)
    vpxor (%rsp), %xmm10, %xmm10

.noExtraBytes:
    vpxor %xmm10, $RES, $RES
    call GFMUL

    # calculation of T is over here. RES=T

    addq \$16, %rsp
.polyend:
    vmovdqu $RES, ($T)
    popq %rax
    popq %r13
    popq %r12
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
ret
.size aes128gcmsiv_polyval_horner,.-aes128gcmsiv_polyval_horner
___

$aadINp = "%rdx";
$aadLen = "%rcx";
$msgINp = "%r8";
$msgLen = "%r9";
$aadLoc = "%r11";
$msgLoc = "%r12";
$TMP = "%r13";
$pLENBLK = "%r14";
$TMP1 = "%rsi";
$buffer = "%r15";

#void aes128gcmsiv_polyval_horner_aad_msg_lenblock(
#	uint8_t inout[16],
#	const uint8_t key[16],   // POLYVAL key
#	const uint8_t *ad,
#	size_t ad_len,
#	const uint8_t *plaintext,
#	size_t plaintext_len,
#	const uint8_t lenblock[16]);
# parameter 1: %rdi	T		pointers to POLYVAL output
# parameter 2: %rsi	Hp		pointer to H (user key)
# parameter 3: %rdx	aadINp		pointer to AAD input
# parameter 4: %rcx	aadLen		aad Length
# parameter 5: %r8	msgINp		pointer to MSG input
# parameter 6: %r9	msgLen		msg Length
# parameter 7: 8(%rsp)	lenBlk		lenBLK
$code.=<<___;
.globl	aes128gcmsiv_polyval_horner_aad_msg_lenblock
.type	aes128gcmsiv_polyval_horner_aad_msg_lenblock,\@function,2
.align	16
aes128gcmsiv_polyval_horner_aad_msg_lenblock:
    # We will start with L _GFMULS for POLYVAL(BIG_BUFFER)
    # RES = GFMUL(RES, H)

    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq 12*8+8(%rsp), $pLENBLK
    subq \$16, %rsp
    movq %rsp, $buffer
    movq \$0, 0($buffer)
    movq \$0, 8($buffer)
    xorq $LOC, $LOC
    movq $aadLen, $aadLoc
    movq $msgLen, $msgLoc
    shlq \$60, $aadLen
    shrq \$60, $aadLen
    vmovdqu ($Hp), $H
    vmovdqu ($T), $RES
    cmp \$16, $aadLoc
    jb .LaadRemainder
    subq \$16, $aadLoc

.Lloop1:
    vpxor ($aadINp,$LOC), $RES, $RES  # RES = RES + Xi
    call GFMUL  # RES = RES * H

    addq \$16, $LOC
    cmpq $LOC, $aadLoc
    jae .Lloop1

.LaadRemainder:
    cmp \$0, $aadLen
    je .MsgPart

    # Handle remaining AAD.
    movq $aadLen, $TMP
    shrq \$2, $TMP
    movq $TMP, $TMP1
    shlq \$4, $TMP
    shlq \$62, $aadLen
    shrq \$62, $aadLen
    leaq CONST_Vector(%rip), $aadLoc
    vmovdqu ($aadLoc,$TMP), %xmm10
    vpmaskmovd ($aadINp,$LOC), %xmm10, %xmm10
    cmp \$0, $aadLen
    je .noAddedBytes
    shlq \$2, $TMP1
    addq $TMP1, $LOC
    addq $LOC, $aadINp
    movl ($aadINp), %r13d
    movl %r13d, ($buffer,$TMP1)
    vpxor ($buffer), %xmm10, %xmm10

.noAddedBytes:
    vpxor %xmm10, $RES, $RES
    call GFMUL
    movl \$0, ($buffer,$TMP1)

.MsgPart:
    xorq $LOC, $LOC
    cmp \$16, $msgLoc
    jb .LMsgRemaining
    subq \$16, $msgLoc

.MsgLoop:
    vpxor ($msgINp, $LOC), $RES, $RES
    call GFMUL  # RES = RES * H
    addq \$16, $LOC
    cmp $LOC, $msgLoc
    jae .MsgLoop

.LMsgRemaining:
    shlq \$60, $msgLen
    shrq \$60, $msgLen
    cmp \$0, $msgLen
    je .LenBlkPart

    # Handle remaining msg.
    movq $msgLen, $TMP
    shrq \$2, $TMP
    movq $TMP, $TMP1
    shlq \$4, $TMP
    shlq \$62, $msgLen
    shrq \$62, $msgLen
    leaq CONST_Vector(%rip), $aadLoc
    vmovdqu ($aadLoc,$TMP), %xmm10
    vpmaskmovd ($msgINp,$LOC), %xmm10, %xmm10
    cmp \$0, $msgLen
    je .NoMsgBytesAdd
    shlq \$2, $TMP1
    addq $TMP1, $LOC
    movl ($msgINp,$LOC), %r13d
    movl %r13d, ($buffer,$TMP1)
    vpxor ($buffer), %xmm10, %xmm10

.NoMsgBytesAdd:
    vpxor %xmm10, $RES, $RES
    call GFMUL

.LenBlkPart:
    # calculation of T is over here. RES=T
    vpxor ($pLENBLK), $RES, $RES
    call GFMUL
    vmovdqu $RES, (%rdi)

    addq \$16, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
ret
.size aes128gcmsiv_polyval_horner_aad_msg_lenblock, .-aes128gcmsiv_polyval_horner_aad_msg_lenblock
___

# void aes128gcmsiv_aes_ks(const uint8_t *key, uint8_t *out_expanded_key);
# parameter 1: %rdi
# parameter 2: %rsi
$code.=<<___;
.globl	aes128gcmsiv_aes_ks
.type	aes128gcmsiv_aes_ks,\@function,2
.align	16
aes128gcmsiv_aes_ks:
    pushq %rdi
    pushq %rsi
    pushq %rax
    vmovdqu (%rdi), %xmm1           # xmm1 = user key
    vmovdqu %xmm1, (%rsi)           # rsi points to output

    vmovdqu con1(%rip), %xmm0
    vmovdqu mask(%rip), %xmm15

    mov \$8, %rax

.LOOP1_AVX:
    add \$16, %rsi                  # rsi points for next key
    dec %rax
    vpshufb %xmm15, %xmm1, %xmm2    # xmm2 = shuffled user key
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld \$1, %xmm0, %xmm0
    vpslldq \$4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, (%rsi)
    jne .LOOP1_AVX

    vmovdqu con2(%rip), %xmm0
    vpshufb %xmm15, %xmm1, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld \$1, %xmm0, %xmm0
    vpslldq \$4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 16(%rsi)

    vpshufb %xmm15, %xmm1, %xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslldq \$4, %xmm1, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpslldq \$4, %xmm3, %xmm3
    vpxor %xmm3, %xmm1, %xmm1
    vpxor %xmm2, %xmm1, %xmm1
    vmovdqu %xmm1, 32(%rsi)
    popq %rax
    popq %rsi
    popq %rdi
    ret
.size aes128gcmsiv_aes_ks,.-aes128gcmsiv_aes_ks
___

$BLOCK1 = "%xmm4";
$AUXREG = "%xmm3";
$KS1_REGA = "%xmm1";
$KS1_REGB = "%xmm2";

sub KS_BLOCK {
my ($reg, $reg2, $auxReg) = @_;
return <<___;
    vpsllq \$32, $reg, $auxReg         #!!saving mov instruction to xmm3
    vpxor $auxReg, $reg, $reg
    vpshufb con3(%rip), $reg,  $auxReg
    vpxor $auxReg, $reg, $reg
    vpxor $reg2, $reg, $reg
___
}

sub round {
my ($i, $j) = @_;
return <<___;
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    vpslld \$1, %xmm0, %xmm0
    ${\KS_BLOCK($KS1_REGA, $KS1_REGB, $AUXREG)}
    vaesenc %xmm1, $BLOCK1, $BLOCK1
    vmovdqa %xmm1, ${\eval(16*$i)}($j)
___
}

sub roundlast {
my ($i, $j) = @_;
return <<___;
    vpshufb %xmm15, %xmm1, %xmm2      #!!saving mov instruction to xmm2
    vaesenclast %xmm0, %xmm2, %xmm2
    ${\KS_BLOCK($KS1_REGA, $KS1_REGB, $AUXREG)}
    vaesenclast %xmm1, $BLOCK1, $BLOCK1
    vmovdqa %xmm1, ${\eval(16*$i)}($j)
___
}

# parameter 1: %rdi                         Pointer to PT
# parameter 2: %rsi                         Pointer to CT
# parameter 3: %rdx                         buffer len
# parameter 4: %rcx                         Pointer to keys
# parameter 5: %r8                          Pointer to initial key
# parameter 5: %r9d                         key length (unused for now)
$code.=<<___;
.globl	aes128gcmsiv_aes_ks_enc_x1
.type	aes128gcmsiv_aes_ks_enc_x1,\@function,2
.align	16
aes128gcmsiv_aes_ks_enc_x1:
.cfi_startproc
    pushq %rdi
.cfi_def_cfa_offset 16
    pushq %rsi
.cfi_def_cfa_offset 24
    pushq %rdx
.cfi_def_cfa_offset 32
    pushq %rcx
.cfi_def_cfa_offset 40
    pushq %r8
.cfi_def_cfa_offset 48
    pushq %r9
.cfi_def_cfa_offset 56
    vmovdqu (%r8), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu 0*16(%rdi), $BLOCK1

    vmovdqa %xmm1, (%rcx)                 # KEY[0] = first 16 bytes of random key
    vpxor %xmm1, $BLOCK1, $BLOCK1

    vmovdqa con1(%rip), %xmm0                    # xmm0  = 1,1,1,1
    vmovdqa mask(%rip), %xmm15                   # xmm15 = mask

    ${\round(1, "%rcx")}
    ${\round(2, "%rcx")}
    ${\round(3, "%rcx")}
    ${\round(4, "%rcx")}
    ${\round(5, "%rcx")}
    ${\round(6, "%rcx")}
    ${\round(7, "%rcx")}
    ${\round(8, "%rcx")}

    vmovdqa con2(%rip), %xmm0

    ${\round(9, "%rcx")}
    ${\roundlast(10, "%rcx")}

    vmovdqu $BLOCK1, 0*16(%rsi)
    popq %r9
.cfi_def_cfa_offset 48
    popq %r8
.cfi_def_cfa_offset 40
    popq %rcx
.cfi_def_cfa_offset 32
    popq %rdx
.cfi_def_cfa_offset 24
    popq %rsi
.cfi_def_cfa_offset 16
    popq %rdi
.cfi_def_cfa_offset 8
    ret
.cfi_endproc
.size aes128gcmsiv_aes_ks_enc_x1,.-aes128gcmsiv_aes_ks_enc_x1
___


# Expand without storing and encrypt two blocks
$AUXREG = "%xmm3";
$KS1_REGA = "%xmm1";
$KS1_REGB = "%xmm2";
$BLOCK1 = "%xmm4";
$BLOCK2 = "%xmm5";

sub round_b {
my ($i) = @_;
return <<___;
    vpshufb %xmm15, $KS1_REGA, $KS1_REGB        #!!saving mov instruction to xmm2
    vaesenclast %xmm0, $KS1_REGB, $KS1_REGB
    ${\KS_BLOCK($KS1_REGA, $KS1_REGB, $AUXREG)}
    vpslld \$1, %xmm0, %xmm0
    vaesenc $KS1_REGA, $BLOCK1, $BLOCK1
    vaesenc $KS1_REGA, $BLOCK2, $BLOCK2
___
}

sub roundlast_b {
my ($i) = @_;
return <<___;
    vpshufb %xmm15, $KS1_REGA, $KS1_REGB        #!!saving mov instruction to xmm2
    vaesenclast %xmm0, $KS1_REGB, $KS1_REGB
    ${\KS_BLOCK($KS1_REGA, $KS1_REGB, $AUXREG)}
    vaesenclast $KS1_REGA, $BLOCK1, $BLOCK1
    vaesenclast $KS1_REGA, $BLOCK2, $BLOCK2
___
}

# parameter 1: %rdi                         Pointer to PT
# parameter 2: %rsi                         Pointer to CT1
# parameter 3: %rdx                         Pointer to CT2
# parameter 4: %rcx                         Pointer to keys
# parameter 5: %r8                          Pointer to initial key
# parameter 5: %r9d                         key length (unused for now)
$code.=<<___;
.globl	aes128gcmsiv_aes_ks_no_mem_enc_x2
.type	aes128gcmsiv_aes_ks_no_mem_enc_x2,\@function,2
.align	16
aes128gcmsiv_aes_ks_no_mem_enc_x2:
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9

    vmovdqu (%r8), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu 0*16(%rdi), $BLOCK1
    vmovdqu 1*16(%rdi), $BLOCK2

    vpxor $KS1_REGA, $BLOCK1, $BLOCK1
    vpxor $KS1_REGA, $BLOCK2, $BLOCK2

    vmovdqa con1(%rip), %xmm0                    # xmm0  = 1,1,1,1
    vmovdqa mask(%rip), %xmm15                   # xmm15 = mask

    ${\round_b(1)}
    ${\round_b(2)}
    ${\round_b(3)}
    ${\round_b(4)}
    ${\round_b(5)}
    ${\round_b(6)}
    ${\round_b(7)}
    ${\round_b(8)}

    vmovdqa con2(%rip), %xmm0

    ${\round_b(9)}
    ${\roundlast_b(10)}

    vmovdqu $BLOCK1, 0*16(%rsi)
    vmovdqu $BLOCK2, 0*16(%rdx)
    popq  %r9
    popq  %r8
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret
.size aes128gcmsiv_aes_ks_no_mem_enc_x2,.-aes128gcmsiv_aes_ks_no_mem_enc_x2
___

# void aes128gcmsiv_aes_ks_x1_init_x4(
#	const uint8_t nonce[12],
#	uint8_t *ciphertext,
#	uint8_t *out_ks,
#	uint8_t *first_key);
$BLOCK2 = "%xmm10";
$BLOCK3 = "%xmm11";
$BLOCK4 = "%xmm12";
$ONE = "%xmm13";
# parameter 1: %rdi   Pointer to NONCE
# parameter 2: %rsi   Pointer to CT
# parameter 4: %rdx   Pointer to keys
# parameter 5: %rcx   Pointer to initial key
$code.=<<___;
.global aes128gcmsiv_aes_ks_x1_init_x4
.type aes128gcmsiv_aes_ks_x1_init_x4,\@function,2
.align 16
aes128gcmsiv_aes_ks_x1_init_x4:
    movl \$10, 240(%rcx)  # key.rounds = 10
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    vmovdqu (%rcx), %xmm1  # xmm1 = first 16 bytes of random key
    vmovdqu (%rdi), $BLOCK1
    vmovdqu (%rip), $BLOCK4
    vmovdqu $one(%rip), $ONE
    vpshufd \$0x90, $BLOCK1, $BLOCK1
    vpand $BLOCK4, $BLOCK1, $BLOCK1
    vpaddd $ONE, $BLOCK1, $BLOCK2
    vpaddd $ONE, $BLOCK2, $BLOCK3
    vpaddd $ONE, $BLOCK3, $BLOCK4

    vmovdqa %xmm1, (%rcx)  # KEY[0] = first 16 bytes of random key
    vpxor %xmm1, $BLOCK1, $BLOCK1
    vpxor %xmm1, $BLOCK2, $BLOCK2
    vpxor %xmm1, $BLOCK3, $BLOCK3
    vpxor %xmm1, $BLOCK4, $BLOCK4

    vmovdqa con1(%rip), %xmm0  # xmm0  = 1,1,1,1
    vmovdqa mask(%rip), %xmm15 # xmm15 = mask

    ${\round(1, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(2, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(3, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(4, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(5, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(6, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(7, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\round(8, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    vmovdqa con2(%rip), %xmm0
    ${\round(9, "%rdx")}
    vaesenc %xmm1, $BLOCK2, $BLOCK2
    vaesenc %xmm1, $BLOCK3, $BLOCK3
    vaesenc %xmm1, $BLOCK4, $BLOCK4
    ${\roundlast(10, "%rdx")}
    vaesenclast %xmm1, $BLOCK2, $BLOCK2
    vaesenclast %xmm1, $BLOCK3, $BLOCK3
    vaesenclast %xmm1, $BLOCK4, $BLOCK4
    vmovdqu $BLOCK1, 0*16(%rsi)
    vmovdqu $BLOCK2, 1*16(%rsi)
    vmovdqu $BLOCK3, 2*16(%rsi)
    vmovdqu $BLOCK4, 3*16(%rsi)

    vpxor %xmm1, %xmm1, %xmm1
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    ret
___

$KSp = "%rdx";
$STATE_1 = "%xmm1";

sub enc_roundx4 {
my ($i, $j) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}(%rdx), $j
    vaesenc $j, $BLOCK1, $BLOCK1
    vaesenc $j, $BLOCK2, $BLOCK2
    vaesenc $j, $BLOCK3, $BLOCK3
    vaesenc $j, $BLOCK4, $BLOCK4
___
}

sub enc_roundlastx4 {
my ($i, $j) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}(%rdx), $j
    vaesenclast $j, $BLOCK1, $BLOCK1
    vaesenclast $j, $BLOCK2, $BLOCK2
    vaesenclast $j, $BLOCK3, $BLOCK3
    vaesenclast $j, $BLOCK4, $BLOCK4
___
}

# void aes128gcmsiv_enc_x4(const uint8_t nonce[12],
#                              uint8_t *out_key_material,
#                              const uint8_t *key_schedule);
$code.=<<___;
.globl aes128gcmsiv_enc_x4
.type aes128gcmsiv_enc_x4,\@function,2
.align 16
aes128gcmsiv_enc_x4:
# parameter 1: %rdi                         Pointer to NONCE
# parameter 2: %rsi                         Pointer to CT
# parameter 4: %rdx                         Pointer to keys
    pushq %rdi
    pushq %rsi
    pushq %rdx

    vmovdqu (%rdx), %xmm1                  # xmm1 = first 16 bytes of random key
    vmovdqu 0*16(%rdi), $BLOCK1
    vmovdqu and_mask(%rip), $BLOCK4
    vmovdqu one(%rip), $ONE
    vpshufd \$0x90, $BLOCK1, $BLOCK1
    vpand $BLOCK4, $BLOCK1, $BLOCK1
    vpaddd $ONE, $BLOCK1, $BLOCK2
    vpaddd $ONE, $BLOCK2, $BLOCK3
    vpaddd $ONE, $BLOCK3, $BLOCK4

    vpxor %xmm1, $BLOCK1, $BLOCK1
    vpxor %xmm1, $BLOCK2, $BLOCK2
    vpxor %xmm1, $BLOCK3, $BLOCK3
    vpxor %xmm1, $BLOCK4, $BLOCK4


    ${\enc_roundx4(1, "%xmm1")}
    ${\enc_roundx4(2, "%xmm2")}
    ${\enc_roundx4(3, "%xmm1")}
    ${\enc_roundx4(4, "%xmm2")}
    ${\enc_roundx4(5, "%xmm1")}
    ${\enc_roundx4(6, "%xmm2")}
    ${\enc_roundx4(7, "%xmm1")}
    ${\enc_roundx4(8, "%xmm2")}
    ${\enc_roundx4(9, "%xmm1")}
    ${\enc_roundlastx4(10, "%xmm2")}

    vmovdqu $BLOCK1, 0*16(%rsi)
    vmovdqu $BLOCK2, 1*16(%rsi)
    vmovdqu $BLOCK3, 2*16(%rsi)
    vmovdqu $BLOCK4, 3*16(%rsi)

    vpxor %xmm1, %xmm1, %xmm1
    vpxor %xmm2, %xmm2, %xmm2
    popq %rdx
    popq %rsi
    popq %rdi
    ret
.size aes128gcmsiv_enc_x4,.-aes128gcmsiv_enc_x4
___

# parameter 1: PT   %rdi    (pointer to 128 bit)
# parameter 2: CT   %rsi    (pointer to 128 bit)
# parameter 3: ks   %rdx    (pointer to ks)
# parameter 3: ks   %rcx    (pointer to tag)
$code.=<<___;
.globl aes128gcmsiv_finalize_tag
aes128gcmsiv_finalize_tag:
    pushq %rdx
    pushq %rdi
    pushq %rsi
    pushq %rbp                                # store rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    movq %rsp, %rbp
    subq \$16, %rsp
    movq \$0, %rax
    vmovdqu (%rdi), $STATE_1

    movq (%rcx), %r10
    movq 8(%rcx), %r11
    vpxor ($KSp), $STATE_1, $STATE_1
    vaesenc 1*16($KSp), $STATE_1, $STATE_1
    vaesenc 2*16($KSp), $STATE_1, $STATE_1
    vaesenc 3*16($KSp), $STATE_1, $STATE_1
    vaesenc 4*16($KSp), $STATE_1, $STATE_1
    vaesenc 5*16($KSp), $STATE_1, $STATE_1
    vaesenc 6*16($KSp), $STATE_1, $STATE_1
    vaesenc 7*16($KSp), $STATE_1, $STATE_1
    vaesenc 8*16($KSp), $STATE_1, $STATE_1
    vaesenc 9*16($KSp), $STATE_1, $STATE_1
    vaesenclast 10*16($KSp), $STATE_1, $STATE_1    # STATE_1 == IV

    vmovdqa $STATE_1, (%rsi)
    vmovdqu $STATE_1, (%rsp)
    movq (%rsp), %r8
    movq 8(%rsp), %r9
    xorq %r8, %r10
    xorq %r9, %r11
    addq %r10, %r11
    movq %r11, %rax
    addq \$16, %rsp
    movq %rbp, %rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rsi
    popq %rdi
    popq %rdx
    ret
___

$CTR1 = "%xmm0";
$CTR2 = "%xmm1";
$CTR3 = "%xmm2";
$CTR4 = "%xmm3";
$ADDER = "%xmm4";

$STATE1 = "%xmm5";
$STATE2 = "%xmm6";
$STATE3 = "%xmm7";
$STATE4 = "%xmm8";

$TMP = "%xmm12";
$TMP2 = "%xmm13";
$TMP3 = "%xmm14";
$IV = "%xmm15";

$PT = "%rdi";
$CT = "%rsi";
$TAG = "%rdx";
$KS = "%rcx";
$LEN = "%r8";
$gTMP = "%r11";

sub aes_round {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $TMP
    vaesenc $TMP, $STATE1, $STATE1
    vaesenc $TMP, $STATE2, $STATE2
    vaesenc $TMP, $STATE3, $STATE3
    vaesenc $TMP, $STATE4, $STATE4
___
}

sub aes_lastround {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $TMP
    vaesenclast $TMP, $STATE1, $STATE1
    vaesenclast $TMP, $STATE2, $STATE2
    vaesenclast $TMP, $STATE3, $STATE3
    vaesenclast $TMP, $STATE4, $STATE4
___
}

# void aes128gcmsiv_enc_msg_x4(unsigned char* PT, unsigned char* CT,
#                              unsigned char* TAG, unsigned char* KS,
#                              size_t byte_len);
# parameter 1: %rdi     #PT
# parameter 2: %rsi     #CT
# parameter 3: %rdx     #TAG		[127 126 ... 0]  IV=[127...32]
# parameter 4: %rcx     #KS
# parameter 5: %r8      #LEN MSG_length in bytes
$code.=<<___;
.globl	aes128gcmsiv_enc_msg_x4
.type	aes128gcmsiv_enc_msg_x4,\@function,2
.align	16
aes128gcmsiv_enc_msg_x4:
    test $LEN, $LEN
    jnz  .Lbegin
    ret

.Lbegin:
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %rax
    xorq $gTMP, $gTMP

    movq $LEN, %r10
    shrq \$4, $LEN      # LEN = num of blocks
    shlq \$60, %r10
    je .NO_PARTS
    shrq \$60, %r10
    movq %r10, $gTMP

.NO_PARTS:
    movq $LEN, %r10
    shlq \$62, %r10
    shrq \$62, %r10

    # make IV from TAG
    vmovdqu ($TAG), $IV
    vpor OR_MASK(%rip), $IV, $IV  #IV = [1]TAG[126...32][00..00]

    vmovdqu four(%rip), $ADDER     # Register to increment counters
    vmovdqa $IV, $CTR1             # CTR1 = TAG[1][127...32][00..00]
    vpaddd one(%rip), $IV, $CTR2   # CTR2 = TAG[1][127...32][00..01]
    vpaddd two(%rip), $IV, $CTR3   # CTR3 = TAG[1][127...32][00..02]
    vpaddd three(%rip), $IV, $CTR4 # CTR4 = TAG[1][127...32][00..03]

    shrq \$2, $LEN
    je .REMAINDER

    subq \$64, $CT
    subq \$64, $PT

.LOOP:
    addq \$64, $CT
    addq \$64, $PT

    vmovdqa $CTR1, $STATE1
    vmovdqa $CTR2, $STATE2
    vmovdqa $CTR3, $STATE3
    vmovdqa $CTR4, $STATE4

    vpxor ($KS), $STATE1, $STATE1
    vpxor ($KS), $STATE2, $STATE2
    vpxor ($KS), $STATE3, $STATE3
    vpxor ($KS), $STATE4, $STATE4

    ${\aes_round(1)}
    vpaddd $ADDER, $CTR1, $CTR1
    ${\aes_round(2)}
    vpaddd $ADDER, $CTR2, $CTR2
    ${\aes_round(3)}
    vpaddd $ADDER, $CTR3, $CTR3
    ${\aes_round(4)}
    vpaddd $ADDER, $CTR4, $CTR4

    ${\aes_round(5)}
    ${\aes_round(6)}
    ${\aes_round(7)}
    ${\aes_round(8)}
    ${\aes_round(9)}
    ${\aes_lastround(10)}

    # XOR with Plaintext
    vpxor 0*16($PT), $STATE1, $STATE1
    vpxor 1*16($PT), $STATE2, $STATE2
    vpxor 2*16($PT), $STATE3, $STATE3
    vpxor 3*16($PT), $STATE4, $STATE4

    dec $LEN

    vmovdqu $STATE1, 0*16($CT)
    vmovdqu $STATE2, 1*16($CT)
    vmovdqu $STATE3, 2*16($CT)
    vmovdqu $STATE4, 3*16($CT)

    jne .LOOP

    addq \$64,$CT
    addq \$64,$PT

.REMAINDER:
    cmpq \$0, %r10
    je .END_BLOCK

.LOOP2:
    # enc each block separately
    # CTR1 is the highest counter (even if no LOOP done)
    vmovdqa $CTR1, $STATE1
    vpaddd one(%rip), $CTR1, $CTR1  # inc counter

    vpxor ($KS), $STATE1, $STATE1
    vaesenc 16($KS), $STATE1, $STATE1
    vaesenc 32($KS), $STATE1, $STATE1
    vaesenc 48($KS), $STATE1, $STATE1
    vaesenc 64($KS), $STATE1, $STATE1
    vaesenc 80($KS), $STATE1, $STATE1
    vaesenc 96($KS), $STATE1, $STATE1
    vaesenc 112($KS), $STATE1, $STATE1
    vaesenc 128($KS), $STATE1, $STATE1
    vaesenc 144($KS), $STATE1, $STATE1
    vaesenclast 160($KS), $STATE1, $STATE1

    # XOR with plaintext
    vpxor ($PT), $STATE1, $STATE1
    vmovdqu $STATE1, ($CT)

    addq \$16, $PT
    addq \$16, $CT

    decq %r10
    jne .LOOP2

.END_BLOCK:
    # gTMP holds the number of bytes left, <16
    cmp \$0, $gTMP
    je .END

    subq \$16, %rsp
    movq \$0, (%rsp)
    movq \$0, 8(%rsp)
    vpxor ($KS), $CTR1, $STATE1
    vaesenc 16($KS), $STATE1, $STATE1
    movq $gTMP, %r10  # r10 = len left
    movq $gTMP, %r8   # r8 = len left
    vaesenc 32($KS), $STATE1, $STATE1
    shr \$2, %r10      # number of double words possible
    andq \$~-4, %r8    # r8 = last 16 bytes %4
    movq %r10, %r13
    vaesenc 48($KS), $STATE1, $STATE1
    shlq \$4, %r10     # r10 = offset to mask of const
    vaesenc 64($KS), $STATE1, $STATE1
    vaesenc 80($KS), $STATE1, $STATE1
    leaq CONST_Vector(%rip), %r12
    vmovdqu (%r12, %r10), $CTR2
    vaesenc 96($KS), $STATE1, $STATE1
    vpmaskmovd ($PT), $CTR2, $CTR3
    vaesenc 112($KS), $STATE1, $STATE1
    shlq \$2, %r13
    vaesenc 128($KS), $STATE1, $STATE1
    addq %r13, $PT
    vaesenc 144($KS), $STATE1, $STATE1

    vaesenclast 160($KS), $STATE1, $STATE1
    cmp \$0, %r8
    je .NoAddedBytes_Enc_X4
    movl ($PT), %r10d
    movl %r10d, (%rsp, %r13)
    vpxor (%rsp), $CTR3, $CTR3

.NoAddedBytes_Enc_X4:
    vpxor $CTR3, $STATE1, $STATE1
    addq \$16, %rsp
    vpmaskmovd $STATE1, $CTR2, ($CT)
    cmp \$0, %r8
    je .END
    subq \$16, %rsp
    vmovdqu $STATE1, (%rsp)

    movl (%rsp, %r13), %eax
    addq \$16, %rsp
    addq %r13, $CT

.CTLOOP:
    movb %al, ($CT)
    addq \$1, $CT
    shrq \$8, %rax
    subq \$1, %r8
    jne .CTLOOP

.END:
    popq %rax
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
.size aes128gcmsiv_enc_msg_x4,.-aes128gcmsiv_enc_msg_x4
___

$STATE1 = "%xmm1";
$STATE2 = "%xmm2";
$STATE3 = "%xmm3";
$STATE4 = "%xmm4";
$STATE5 = "%xmm5";
$STATE6 = "%xmm6";
$STATE7 = "%xmm7";
$STATE8 = "%xmm8";

$CTR1 = "%xmm0";
$CTR2 = "%xmm9";
$CTR3 = "%xmm10";
$CTR4 = "%xmm11";
$CTR5 = "%xmm12";
$CTR6 = "%xmm13";
$CTR7 = "%xmm14";
$SCHED = "%xmm15";

$TMP1 = "%xmm1";
$TMP2 = "%xmm2";

sub aes_round8 {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $SCHED
    vaesenc $SCHED, $STATE1, $STATE1
    vaesenc $SCHED, $STATE2, $STATE2
    vaesenc $SCHED, $STATE3, $STATE3
    vaesenc $SCHED, $STATE4, $STATE4
    vaesenc $SCHED, $STATE5, $STATE5
    vaesenc $SCHED, $STATE6, $STATE6
    vaesenc $SCHED, $STATE7, $STATE7
    vaesenc $SCHED, $STATE8, $STATE8
___
}

sub aes_lastround8 {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $SCHED
    vaesenclast $SCHED, $STATE1, $STATE1
    vaesenclast $SCHED, $STATE2, $STATE2
    vaesenclast $SCHED, $STATE3, $STATE3
    vaesenclast $SCHED, $STATE4, $STATE4
    vaesenclast $SCHED, $STATE5, $STATE5
    vaesenclast $SCHED, $STATE6, $STATE6
    vaesenclast $SCHED, $STATE7, $STATE7
    vaesenclast $SCHED, $STATE8, $STATE8
___
}

# void ENC_MSG_x8(unsigned char* PT,
#                 unsigned char* CT,
#                 unsigned char* TAG,
#                 unsigned char* KS,
#                 size_t byte_len);
# parameter 1: %rdi     #PT
# parameter 2: %rsi     #CT
# parameter 3: %rdx     #TAG        [127 126 ... 0]  IV=[127...32]
# parameter 4: %rcx     #KS
# parameter 5: %r8      #LEN MSG_length in bytes
$code.=<<___;
.globl	aes128gcmsiv_enc_msg_x8
.type	aes128gcmsiv_enc_msg_x8,\@function,2
.align	16
aes128gcmsiv_enc_msg_x8:
    test $LEN, $LEN
    jnz .Lbegin_x8
    ret

.Lbegin_x8:
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %rax
    pushq %rbp
    movq %rsp, %rbp

    # Place in stack
    subq \$128, %rsp  # changed from 16 to 32 in order to save buffer for remaining bytes.
    andq \$-64, %rsp

    xorq $gTMP, $gTMP
    movq $LEN, %r10
    shrq \$4, $LEN  # LEN = num of blocks
    shlq \$60, %r10
    je .NO_PARTS_x8
    shrq \$60, %r10
    movq %r10, $gTMP

.NO_PARTS_x8:
    movq $LEN, %r10
    shlq \$61, %r10
    shrq \$61, %r10

    # make IV from TAG
    vmovdqu ($TAG), $TMP1
    vpor OR_MASK(%rip), $TMP1, $TMP1  # TMP1= IV = [1]TAG[126...32][00..00]

    # store counter8 in the stack
    vpaddd seven(%rip), $TMP1, $CTR1
    vmovdqu $CTR1, (%rsp)             # CTR8 = TAG[127...32][00..07]
    vpaddd one(%rip), $TMP1, $CTR2    # CTR2 = TAG[127...32][00..01]
    vpaddd two(%rip), $TMP1, $CTR3    # CTR3 = TAG[127...32][00..02]
    vpaddd three(%rip), $TMP1, $CTR4  # CTR4 = TAG[127...32][00..03]
    vpaddd four(%rip), $TMP1, $CTR5   # CTR5 = TAG[127...32][00..04]
    vpaddd five(%rip), $TMP1, $CTR6   # CTR6 = TAG[127...32][00..05]
    vpaddd six(%rip), $TMP1, $CTR7    # CTR7 = TAG[127...32][00..06]
    vmovdqa $TMP1, $CTR1              # CTR1 = TAG[127...32][00..00]

    shrq \$3, $LEN
    je .REMAINDER_x8

    subq \$128, $CT
    subq \$128, $PT

.LOOP_x8:
    addq \$128, $CT
    addq \$128, $PT

    vmovdqa $CTR1, $STATE1
    vmovdqa $CTR2, $STATE2
    vmovdqa $CTR3, $STATE3
    vmovdqa $CTR4, $STATE4
    vmovdqa $CTR5, $STATE5
    vmovdqa $CTR6, $STATE6
    vmovdqa $CTR7, $STATE7
    # move from stack
    vmovdqu (%rsp), $STATE8

    vpxor ($KS), $STATE1, $STATE1
    vpxor ($KS), $STATE2, $STATE2
    vpxor ($KS), $STATE3, $STATE3
    vpxor ($KS), $STATE4, $STATE4
    vpxor ($KS), $STATE5, $STATE5
    vpxor ($KS), $STATE6, $STATE6
    vpxor ($KS), $STATE7, $STATE7
    vpxor ($KS), $STATE8, $STATE8

    ${\aes_round8(1)}
    vmovdqu (%rsp), $CTR7  # deal with CTR8
    vpaddd eight(%rip), $CTR7, $CTR7
    vmovdqu $CTR7, (%rsp)
    ${\aes_round8(2)}
    vpsubd one(%rip), $CTR7, $CTR7
    ${\aes_round8(3)}
    vpaddd eight(%rip), $CTR1, $CTR1
    ${\aes_round8(4)}
    vpaddd eight(%rip), $CTR2, $CTR2
    ${\aes_round8(5)}
    vpaddd eight(%rip), $CTR3, $CTR3
    ${\aes_round8(6)}
    vpaddd eight(%rip), $CTR4, $CTR4
    ${\aes_round8(7)}
    vpaddd eight(%rip), $CTR5, $CTR5
    ${\aes_round8(8)}
    vpaddd eight(%rip), $CTR6, $CTR6
    ${\aes_round8(9)}
    ${\aes_lastround8(10)}

    # XOR with Plaintext
    vpxor 0*16($PT), $STATE1, $STATE1
    vpxor 1*16($PT), $STATE2, $STATE2
    vpxor 2*16($PT), $STATE3, $STATE3
    vpxor 3*16($PT), $STATE4, $STATE4
    vpxor 4*16($PT), $STATE5, $STATE5
    vpxor 5*16($PT), $STATE6, $STATE6
    vpxor 6*16($PT), $STATE7, $STATE7
    vpxor 7*16($PT), $STATE8, $STATE8

    dec $LEN

    vmovdqu $STATE1, 0*16($CT)
    vmovdqu $STATE2, 1*16($CT)
    vmovdqu $STATE3, 2*16($CT)
    vmovdqu $STATE4, 3*16($CT)
    vmovdqu $STATE5, 4*16($CT)
    vmovdqu $STATE6, 5*16($CT)
    vmovdqu $STATE7, 6*16($CT)
    vmovdqu $STATE8, 7*16($CT)

    jne .LOOP_x8

    addq \$128, $CT
    addq \$128, $PT

.REMAINDER_x8:
    cmpq \$0, %r10
    je .END_FULL_BLOCKS_x8

.LOOP2_x8:
    # enc each block separately
    # CTR1 is the highest counter (even if no LOOP done)
    vmovdqa $CTR1, $STATE1
    vpaddd one(%rip), $CTR1, $CTR1  # inc counter

    vpxor ($KS), $STATE1, $STATE1
    vaesenc 16($KS), $STATE1, $STATE1
    vaesenc 32($KS), $STATE1, $STATE1
    vaesenc 48($KS), $STATE1, $STATE1
    vaesenc 64($KS), $STATE1, $STATE1
    vaesenc 80($KS), $STATE1, $STATE1
    vaesenc 96($KS), $STATE1, $STATE1
    vaesenc 112($KS), $STATE1, $STATE1
    vaesenc 128($KS), $STATE1, $STATE1
    vaesenc 144($KS), $STATE1, $STATE1
    vaesenclast 160($KS), $STATE1, $STATE1

    # XOR with Plaintext
    vpxor ($PT), $STATE1, $STATE1

    vmovdqu $STATE1, ($CT)

    addq \$16, $PT
    addq \$16, $CT

    decq %r10
    jne .LOOP2_x8

.END_FULL_BLOCKS_x8:
    cmpq \$0, $gTMP
    je .END_x8
    movq \$0, (%rsp)
    movq \$0, 8(%rsp)
    vpxor ($KS), $CTR1, $STATE1
    vaesenc 16($KS), $STATE1, $STATE1
    movq $gTMP, %r10  # r10 = len left
    movq $gTMP, %r8   # r8 = len left
    vaesenc 32($KS), $STATE1, $STATE1
    shr \$2, %r10     # number of double words possible
    shlq \$62, %r8
    movq %r10, %r13
    vaesenc 48($KS), $STATE1, $STATE1
    shlq \$4, %r10    # r10 = offset to mask of const
    shrq \$62, %r8    # r8= last 16 bytes %4
    vaesenc 64($KS), $STATE1, $STATE1
    vaesenc 80($KS), $STATE1, $STATE1
    leaq CONST_Vector(%rip), %r12
    vmovdqu (%r12, %r10), $CTR3
    vaesenc 96($KS), $STATE1, $STATE1
    vpmaskmovd ($PT), $CTR3, $CTR2
    vaesenc 112($KS), $STATE1, $STATE1
    shlq \$2, %r13
    vaesenc 128($KS), $STATE1, $STATE1
    addq %r13, $PT
    vaesenc 144($KS), $STATE1, $STATE1
    movl ($PT), %r10d
    vaesenclast 160($KS), $STATE1, $STATE1
    cmp \$0, %r8
    je .NoAddedBytes_Enc_x8
    movl %r10d, (%rsp, %r13)
    vpxor (%rsp), $CTR2, $CTR2

.NoAddedBytes_Enc_x8:
    vpxor $CTR2, $STATE1, $STATE1
    vpmaskmovd $STATE1, $CTR3, ($CT)
    vmovdqu $STATE1, (%rsp)
    movl (%rsp,%r13), %eax
    cmp \$0, %r8
    je .END_x8

.bytesloop_x8:
    movb %al, ($CT, %r13)
    inc %r13
    dec %r8
    shrq \$8, %rax
    cmp \$0, %r8
    jne .bytesloop_x8

.END_x8:
    addq \$128, %rsp
    movq %rbp, %rsp
    popq %rbp
    popq %rax
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret
.size aes128gcmsiv_enc_msg_x8,.-aes128gcmsiv_enc_msg_x8
___


$T = "%xmm0";
$TMP0 = "%xmm1";
$TMP1 = "%xmm2";
$TMP2 = "%xmm3";
$TMP3 = "%xmm4";
$TMP4 = "%xmm5";
$TMP5 = "%xmm6";
$CTR1 = "%xmm7";
$CTR2 = "%xmm8";
$CTR3 = "%xmm9";
$CTR4 = "%xmm10";
$CTR5 = "%xmm11";
$CTR6 = "%xmm12";

$CTR = "%xmm15";

$HTABLE_ROUNDS = "%xmm13";
$S_BUF_ROUNDS = "%xmm14";

$CT = "%rdi";
$PT = "%rsi";
$POL = "%rdx";
$TAG = "%rcx";
$Htbl = "%r8";
$KS = "%r9";
$LEN = "%r10";
$secureBuffer = "%rax";

sub aes_round_dec {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $TMP3
    vaesenc $TMP3, $CTR1, $CTR1
    vaesenc $TMP3, $CTR2, $CTR2
    vaesenc $TMP3, $CTR3, $CTR3
    vaesenc $TMP3, $CTR4, $CTR4
    vaesenc $TMP3, $CTR5, $CTR5
    vaesenc $TMP3, $CTR6, $CTR6
___
}

sub aes_lastround_dec {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16)}($KS), $TMP3
    vaesenclast $TMP3, $CTR1, $CTR1
    vaesenclast $TMP3, $CTR2, $CTR2
    vaesenclast $TMP3, $CTR3, $CTR3
    vaesenclast $TMP3, $CTR4, $CTR4
    vaesenclast $TMP3, $CTR5, $CTR5
    vaesenclast $TMP3, $CTR6, $CTR6
___
}

sub schoolbook {
my ($i) = @_;
return <<___;
    vmovdqu ${\eval($i*16-32)}($secureBuffer), $TMP5
    vmovdqu ${\eval($i*16-32)}($Htbl), $HTABLE_ROUNDS

    vpclmulqdq \$0x10, $HTABLE_ROUNDS, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, $HTABLE_ROUNDS, $TMP5, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x00, $HTABLE_ROUNDS, $TMP5, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x01, $HTABLE_ROUNDS, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
___
}

###############################################################################
# void aes128gcmsiv_dec(
#                   unsigned char* CT,                //input
#                   unsigned char* PT,                  //output
#                   unsigned char POLYVAL_dec[16],      //input/output
#                   unsigned char TAG[16],
#                   unsigned char Htable[16*8],
#                   unsigned char* KS,                  //Key Schedule for decryption
#                   int byte_len,
#                   unsigned char secureBuffer[16*8]);
# parameter 1: %rdi     CT           # input
# parameter 2: %rsi     PT           # output
# parameter 3: %rdx     POL          # input/output
# parameter 4: %rcx     TAG          # TAG
# parameter 5: %r8      Htbl         # H
# parameter 6: %r9      KS           # KS
# parameter 7: %rsp+8   LEN          # LEN
# parameter 8: %rsp+16  secureBuffer # secureBuffer

$code.=<<___;
.globl	aes128gcmsiv_dec
.type	aes128gcmsiv_dec,\@function,2
.align	16
aes128gcmsiv_dec:
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r13
    pushq %rax


    movq 8+9*8(%rsp), $LEN
    movq \$0xffffffff, %r13
    andq %r13, $LEN
    test $LEN, $LEN
    jnz .Lbegin_dec
    jmp .Ldone_dec

.Lbegin_dec:
    vzeroupper
    mov 16+9*8(%rsp), $secureBuffer
    vmovdqu ($POL), $T

    leaq 32($secureBuffer), $secureBuffer
    leaq 32($Htbl), $Htbl

    # make CTRBLKs from TAG
    vmovdqu ($TAG), $CTR
    vpor OR_MASK(%rip), $CTR, $CTR  #CTR = [1]TAG[126...32][00..00]


    # If less then 6 blocks, make singles
    cmp \$96, $LEN
    jb .Ldata_dec_singles

    # Decrypt the first six blocks
    sub \$96, $LEN
    vmovdqa $CTR, $CTR1
    vpaddd one(%rip), $CTR1, $CTR2
    vpaddd two(%rip), $CTR1, $CTR3
    vpaddd one(%rip), $CTR3, $CTR4
    vpaddd two(%rip), $CTR3, $CTR5
    vpaddd one(%rip), $CTR5, $CTR6
    vpaddd two(%rip), $CTR5, $CTR

    vpxor ($KS), $CTR1, $CTR1
    vpxor ($KS), $CTR2, $CTR2
    vpxor ($KS), $CTR3, $CTR3
    vpxor ($KS), $CTR4, $CTR4
    vpxor ($KS), $CTR5, $CTR5
    vpxor ($KS), $CTR6, $CTR6

    ${\aes_round_dec(1)}
    ${\aes_round_dec(2)}
    ${\aes_round_dec(3)}
    ${\aes_round_dec(4)}
    ${\aes_round_dec(5)}
    ${\aes_round_dec(6)}
    ${\aes_round_dec(7)}
    ${\aes_round_dec(8)}
    ${\aes_round_dec(9)}
    ${\aes_lastround_dec(10)}

    # XOR with CT
    vpxor 0*16($CT), $CTR1, $CTR1
    vpxor 1*16($CT), $CTR2, $CTR2
    vpxor 2*16($CT), $CTR3, $CTR3
    vpxor 3*16($CT), $CTR4, $CTR4
    vpxor 4*16($CT), $CTR5, $CTR5
    vpxor 5*16($CT), $CTR6, $CTR6

    vmovdqu $CTR1, 0*16($PT)
    vmovdqu $CTR2, 1*16($PT)
    vmovdqu $CTR3, 2*16($PT)
    vmovdqu $CTR4, 3*16($PT)
    vmovdqu $CTR5, 4*16($PT)
    vmovdqu $CTR6, 5*16($PT)

    add \$96, $CT
    add \$96, $PT
    jmp .Ldata_octets_dec

# Decrypt 6 blocks each time while hashing previous 6 blocks
.align 64
.Ldata_octets_dec:
    cmp \$96, $LEN
    jb .Lend_octets_dec
    sub \$96, $LEN

    vmovdqu $CTR6, $TMP5
    vmovdqu $CTR5, 1*16-32($secureBuffer)
    vmovdqu $CTR4, 2*16-32($secureBuffer)
    vmovdqu $CTR3, 3*16-32($secureBuffer)
    vmovdqu $CTR2, 4*16-32($secureBuffer)
    vmovdqu $CTR1, 5*16-32($secureBuffer)

    vmovdqa $CTR, $CTR1
    vpaddd one(%rip), $CTR1, $CTR2
    vpaddd two(%rip), $CTR1, $CTR3
    vpaddd one(%rip), $CTR3, $CTR4
    vpaddd two(%rip), $CTR3, $CTR5
    vpaddd one(%rip), $CTR5, $CTR6
    vpaddd two(%rip), $CTR5, $CTR

    vmovdqu ($KS), $TMP3
    vpxor $TMP3, $CTR1, $CTR1
    vpxor $TMP3, $CTR2, $CTR2
    vpxor $TMP3, $CTR3, $CTR3
    vpxor $TMP3, $CTR4, $CTR4
    vpxor $TMP3, $CTR5, $CTR5
    vpxor $TMP3, $CTR6, $CTR6

    vmovdqu 0*16-32($Htbl), $TMP3
    vpclmulqdq \$0x11, $TMP3, $TMP5, $TMP1
    vpclmulqdq \$0x00, $TMP3, $TMP5, $TMP2
    vpclmulqdq \$0x01, $TMP3, $TMP5, $TMP0
    vpclmulqdq \$0x10, $TMP3, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0

    ${\aes_round_dec(1)}
    ${\schoolbook(1)}

    ${\aes_round_dec(2)}
    ${\schoolbook(2)}

    ${\aes_round_dec(3)}
    ${\schoolbook(3)}

    ${\aes_round_dec(4)}
    ${\schoolbook(4)}

    ${\aes_round_dec(5)}
    ${\aes_round_dec(6)}
    ${\aes_round_dec(7)}

    vmovdqu 5*16-32($secureBuffer), $TMP5
    vpxor $T, $TMP5, $TMP5
    vmovdqu 5*16-32($Htbl), $TMP4

    vpclmulqdq \$0x01, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x11, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x00, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0

    ${\aes_round_dec(8)}

    vpsrldq \$8, $TMP0, $TMP3
    vpxor $TMP3, $TMP1, $TMP4
    vpslldq \$8, $TMP0, $TMP3
    vpxor $TMP3, $TMP2, $T

    vmovdqa poly(%rip), $TMP2

    ${\aes_round_dec(9)}

    vmovdqu 10*16($KS), $TMP5

    vpalignr \$8, $T, $T, $TMP1
    vpclmulqdq \$0x10, $TMP2, $T, $T
    vpxor $T, $TMP1, $T

    vpxor 0*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR1, $CTR1
    vpxor 1*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR2, $CTR2
    vpxor 2*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR3, $CTR3
    vpxor 3*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR4, $CTR4
    vpxor 4*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR5, $CTR5
    vpxor 5*16($CT), $TMP5, $TMP3
    vaesenclast $TMP3, $CTR6, $CTR6

    vpalignr \$8, $T, $T, $TMP1
    vpclmulqdq \$0x10, $TMP2, $T, $T
    vpxor $T, $TMP1, $T

    vmovdqu $CTR1, 0*16($PT)
    vmovdqu $CTR2, 1*16($PT)
    vmovdqu $CTR3, 2*16($PT)
    vmovdqu $CTR4, 3*16($PT)
    vmovdqu $CTR5, 4*16($PT)
    vmovdqu $CTR6, 5*16($PT)

    vpxor $TMP4, $T, $T

    lea 96($CT), $CT
    lea 96($PT), $PT
    jmp .Ldata_octets_dec

.Lend_octets_dec:
    vmovdqu $CTR6, $TMP5
    vmovdqu $CTR5, 1*16-32($secureBuffer)
    vmovdqu $CTR4, 2*16-32($secureBuffer)
    vmovdqu $CTR3, 3*16-32($secureBuffer)
    vmovdqu $CTR2, 4*16-32($secureBuffer)
    vmovdqu $CTR1, 5*16-32($secureBuffer)

    vmovdqu   0*16-32($Htbl), $TMP3
    vpclmulqdq \$0x10, $TMP3, $TMP5, $TMP0
    vpclmulqdq \$0x11, $TMP3, $TMP5, $TMP1
    vpclmulqdq \$0x00, $TMP3, $TMP5, $TMP2
    vpclmulqdq \$0x01, $TMP3, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0

    ${\schoolbook(1)}
    ${\schoolbook(2)}
    ${\schoolbook(3)}
    ${\schoolbook(4)}

    vmovdqu 5*16-32($secureBuffer), $TMP5
    vpxor $T, $TMP5, $TMP5
    vmovdqu 5*16-32($Htbl), $TMP4
    vpclmulqdq \$0x11, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP1, $TMP1
    vpclmulqdq \$0x00, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP2, $TMP2
    vpclmulqdq \$0x10, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0
    vpclmulqdq \$0x01, $TMP4, $TMP5, $TMP3
    vpxor $TMP3, $TMP0, $TMP0

    vpsrldq \$8, $TMP0, $TMP3
    vpxor $TMP3, $TMP1, $TMP4
    vpslldq \$8, $TMP0, $TMP3
    vpxor $TMP3, $TMP2, $T

    vmovdqa poly(%rip), $TMP2

    vpalignr \$8, $T, $T, $TMP1
    vpclmulqdq \$0x10, $TMP2, $T, $T
    vpxor $T, $TMP1, $T

    vpalignr \$8, $T, $T, $TMP1
    vpclmulqdq \$0x10, $TMP2, $T, $T
    vpxor $T, $TMP1, $T

    vpxor $TMP4, $T, $T

# Here we encrypt any remaining whole block
.Ldata_dec_singles:
    # if there are no whole blocks
    cmp \$16, $LEN
    jb .Ldata_end_dec
    sub \$16, $LEN

    vmovdqa $CTR, $TMP1
    vpaddd one(%rip), $CTR, $CTR

    vpxor 0*16($KS), $TMP1, $TMP1
    vaesenc 1*16($KS), $TMP1, $TMP1
    vaesenc 2*16($KS), $TMP1, $TMP1
    vaesenc 3*16($KS), $TMP1, $TMP1
    vaesenc 4*16($KS), $TMP1, $TMP1
    vaesenc 5*16($KS), $TMP1, $TMP1
    vaesenc 6*16($KS), $TMP1, $TMP1
    vaesenc 7*16($KS), $TMP1, $TMP1
    vaesenc 8*16($KS), $TMP1, $TMP1
    vaesenc 9*16($KS), $TMP1, $TMP1
    vaesenclast 10*16($KS), $TMP1, $TMP1

    vpxor ($CT), $TMP1, $TMP1
    vmovdqu $TMP1, ($PT)
    addq \$16, $CT
    addq \$16, $PT

    vpxor $TMP1, $T, $T
    vmovdqu -32($Htbl), $TMP0
    call GFMUL

    jmp .Ldata_dec_singles

.Ldata_end_dec:
    vmovdqu $T, ($POL)

.Ldone_dec:
    popq %rax
    popq %r13
    popq %r10
    popq %r9
    popq %r8
    popq %rcx
    popq %rdx
    popq %rsi
    popq %rdi
    ret

.size aes128gcmsiv_dec, .-aes128gcmsiv_dec
___


print $code;

close STDOUT;
