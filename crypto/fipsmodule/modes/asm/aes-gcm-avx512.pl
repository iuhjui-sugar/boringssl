#!/usr/bin/env perl
# Copyright (c) 2024, Google Inc.
# Copyright (c) 2024, Cloudflare Inc.
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
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#
# Author: Vlad Krasnov
#
$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

$code=<<___;
.text

.section .rodata

.align 64

.Lpoly:
.quad 0xc200000000000000, 0x0000000000000001

.Lbswap:
.byte 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8

.Linc:
.long 0,0,4,0

.align 64

.Linc_init:
.long 0,0,0,0
.long 0,0,1,0
.long 0,0,2,0
.long 0,0,3,0

.text
___

my ($acc0,$acc1,$accm)=map("%xmm$_",(0..2));
my ($t0,$t1,$xi,$poly,$bswap)=map("%xmm$_",(3..7));
my ($h0,$b0)=map("%xmm$_",(8..9));

my ($acc1_z,$accm_z,$t0_z,$t1_z,$acc0_z,$poly_z,$bswap_z,$inc_z,$ctr)=map("%zmm$_",(1..9));
my ($ctr0,$ctr1,$ctr2,$ctr3)=map("%zmm$_",(10..13));
my ($h0_z,$h1_z,$h2_z,$h3_z)=map("%zmm$_",(14..17));
my ($k0,$k1,$k2,$k3,$k4,$k5,$k6,$k7,$k8,$klast)=map("%zmm$_",(18..27));
my ($m0,$m1,$m2,$m3)=map("%zmm$_",(28..31));

my $ctr_x=$ctr =~ s/zmm/xmm/r;
my $t0_y=$t0_z =~ s/zmm/ymm/r;

my $xi_z=$acc0_z;
my $xi_y=$xi_z =~ s/zmm/ymm/r;

{
my ($htbl_ptr,$h_ptr,$i)=("%rdi","%rsi","%rcx");

$code.=<<___;
.align 64
.globl gcm_init_avx512
.type gcm_init_avx512,\@function,2
gcm_init_avx512:
.cfi_startproc

    vzeroupper

    vmovdqu ($h_ptr), $xi
    vmovdqa .Lpoly(%rip), $poly
    vmovdqa .Lbswap(%rip), $bswap

    lea     16*15($htbl_ptr), $htbl_ptr

    # Multiply by 2 modulo P
    vmovq   $xi, $i
    sar     \$63, $i
    vmovq   $i, $t1
    vpshufd \$0x44, $t1, $t1
    vpand   $poly, $t1, $t1
    vpsrlq  \$63, $xi, $t0
    vpsrldq \$8, $t0, $t0
    vpsllq  \$1, $xi, $xi
    vpxor   $t1, $xi, $xi
    vpxor   $t0, $xi, $xi

    vmovdqu $xi, ($htbl_ptr)
    lea     -16($htbl_ptr), $htbl_ptr

    mov \$15, $i
    vmovdqa $xi, $t0

    # Now prepare powers of H, the powers are stored in reverse order
    # i.e. H^16 is stored a htbl[0] and H^1 is stored at htbl[15]
.align 16
.Laes_gcm_init_loop:
        vpclmulqdq \$0x01, $xi, $t0, $accm
        vpclmulqdq \$0x00, $xi, $t0, $acc0
        vpclmulqdq \$0x11, $xi, $t0, $acc1
        vpclmulqdq \$0x10, $xi, $t0, $t0
        vpxor $t0, $accm, $accm

        vpsrldq  \$8, $accm, $t0
        vpslldq  \$8, $accm, $accm
        vpxor    $accm, $acc1, $acc1
        vpxor    $t0, $acc0, $acc0

        vpclmulqdq \$0x00, $poly, $acc1, $accm
        vpshufd    \$0x4e, $acc1, $acc1
        vpxor      $accm, $acc1, $acc1

        vpclmulqdq \$0x00, $poly, $acc1, $accm
        vpshufd    \$0x4e, $acc1, $acc1
        vpxor      $accm, $acc1, $acc1

        vpxor   $acc0, $acc1, $t0
        vpshufd \$0x4e, $t0, $t0

        vmovdqu $t0, ($htbl_ptr)
        lea     -16($htbl_ptr), $htbl_ptr

    dec $i
    jne .Laes_gcm_init_loop

    vzeroupper

    ret

.cfi_endproc
.size gcm_init_avx512,.-gcm_init_avx512
___
}

{
my ($xi_ptr,$htbl_ptr)=("%rdi","%rsi");

$code.=<<___;
.align 64
.globl gcm_gmult_avx512
.type gcm_gmult_avx512,\@function,2
gcm_gmult_avx512:
.cfi_startproc
    vzeroupper

    vmovdqu ($xi_ptr), $xi
    vmovdqu 16*15($htbl_ptr), $h0

    vmovdqa .Lpoly(%rip), $poly
    vmovdqa .Lbswap(%rip), $bswap

    vpshufb  $bswap, $xi, $xi

    vpclmulqdq \$0x01, $xi, $h0, $accm
    vpclmulqdq \$0x10, $xi, $h0, $t1
    vpclmulqdq \$0x00, $xi, $h0, $acc1
    vpclmulqdq \$0x11, $xi, $h0, $acc0

    vpxor $t1, $accm, $accm

    vpsrldq \$8, $accm, $t0
    vpslldq \$8, $accm, $accm

    vpxor $accm, $acc0, $acc0
    vpxor $t0, $acc1, $acc1

    vpclmulqdq \$0x00, $poly, $acc0, $t0
    vpshufd    \$0x4e, $acc0, $acc0
    vpxor      $t0, $acc0, $acc0
    vpclmulqdq \$0x00, $poly, $acc0, $t0
    vpxor      $t0, $acc1, $acc1
    vpshufd    \$0x4e, $acc1, $acc1
    vpxor      $acc1, $acc0, $acc0

    vpshufb $bswap, $acc0, $xi
    vmovdqu $xi, ($xi_ptr)

    vzeroupper

    ret
.cfi_endproc
.size gcm_gmult_avx512,.-gcm_gmult_avx512
___
}

{
my ($xi_ptr,$htbl_ptr,$in_ptr,$in_len,$i)=("%rdi","%rsi","%rdx","%rcx","%r8");

$code.=<<___;
.align 64
.globl gcm_ghash_avx512
.type gcm_ghash_avx512,\@function,4
gcm_ghash_avx512:
.cfi_startproc
    # BoringSSL GHASH is only expected to hash whole blocks
    shr \$4, $in_len
    jz .Lgcm_ghash_avx512_bail

    # Despite its name the function does not utilize AVX512 to perform
    # GHASH, but rather it uses AVX and relies on the htbl layout generated
    # by gcm_init_avx512. The reason to avoid AVX512 here is due to GHASH
    # being rarely used for large chunks of AAD, and in the TLS use case it
    # is less than a block.
    vzeroupper

    vmovdqu ($xi_ptr), $xi

    vmovdqa .Lpoly(%rip), $poly
    vmovdqa .Lbswap(%rip), $bswap

    vpshufb  $bswap, $xi, $xi

    # Since the htbl is in reverse order, we can get the largest needed
    # power required for current block by taking offset from the end of
    # the table 
    lea 16*16($htbl_ptr), $htbl_ptr

.align 16
.Lgcm_ghash_avx512_loop:

        # compute i = max(16, in_len), because we want to process 16 blocks at most
        # except for the remainder where we want to process the last in_len blocks
        mov \$16, $i
        cmp \$16, $in_len
        cmovbe $in_len, $i 

        sub $i, $in_len

        shl \$4, $i        # could be avoided if lea could do * 16
        sub $i, $htbl_ptr  # for 16 blocks this will return to the beginning of the table
                           # and for the remainder it will point to the proper power

        vmovdqu 16*0($htbl_ptr), $h0
        vmovdqu 16*0($in_ptr), $b0
        vpshufb $bswap, $b0, $b0
        lea 16*1($htbl_ptr), $htbl_ptr
        lea 16*1($in_ptr), $in_ptr
        sub \$16, $i

        vpxor $xi, $b0, $b0

        vpclmulqdq \$0x01, $b0, $h0, $accm
        vpclmulqdq \$0x00, $b0, $h0, $acc1
        vpclmulqdq \$0x11, $b0, $h0, $acc0
        vpclmulqdq \$0x10, $b0, $h0, $t0
        vpxor $t0, $accm, $accm

        # If last block skip to reduce
        jz .Lgcm_ghash_avx512_loop_reduce

.align 16
.Lgcm_ghash_avx512_loop_inner:
            vmovdqu 16*0($htbl_ptr), $h0
            vmovdqu 16*0($in_ptr), $b0
            vpshufb $bswap, $b0, $b0

            vpclmulqdq \$0x00, $b0, $h0, $t0
            vpxor $t0, $acc1, $acc1
            vpclmulqdq \$0x01, $b0, $h0, $t0
            vpxor $t0, $accm, $accm
            vpclmulqdq \$0x11, $b0, $h0, $t0
            vpxor $t0, $acc0, $acc0
            vpclmulqdq \$0x10, $b0, $h0, $t0
            vpxor $t0, $accm, $accm

            lea 16*1($htbl_ptr), $htbl_ptr
            lea 16*1($in_ptr), $in_ptr
            sub \$16, $i

            jnz .Lgcm_ghash_avx512_loop_inner

.Lgcm_ghash_avx512_loop_reduce:
        vpsrldq \$8, $accm, $t0
        vpslldq \$8, $accm, $accm

        vpxor $accm, $acc0, $acc0
        vpxor $t0, $acc1, $acc1

        vpclmulqdq \$0x00, $poly, $acc0, $t0
        vpshufd    \$0x4e, $acc0, $acc0
        vpxor      $t0, $acc0, $acc0

        vpclmulqdq \$0x00, $poly, $acc0, $t0
        vpxor      $t0, $acc1, $acc1
        vpshufd    \$0x4e, $acc1, $acc1
        vpxor      $acc1, $acc0, $xi

        cmp \$0, $in_len
        jnz .Lgcm_ghash_avx512_loop

    vpshufb $bswap, $xi, $xi
    vmovdqu $xi, ($xi_ptr)

    vzeroupper

.Lgcm_ghash_avx512_bail:

    ret
.cfi_endproc
.size gcm_ghash_avx512,.-gcm_ghash_avx512
___
}

my ($in_ptr,$out_ptr,$aes_key,$in_len,$iv,$htbl_ptr)=("%rdi","%rsi","%rdx","%rcx","%r8","%r9");
my ($i,$rnds)=("%r10","%r11");
my ($i32,$rnds32)=("${i}d","${rnds}d");
my $t=$iv;

sub gen_load_mask {
my($len,$mask)=@_;
    # If the remaining length is greater than len, the mask should be set
    # to all 1's. Otherwise it the remaining length is smaller than (len-64)
    # it shoud be set to all 0's. In between those two, only the lower
    # (remaining % 64) bits need to be set.
$code.=<<___;
    mov     $in_len, $t
    mov     \$-1, $i
    neg     $t
    cmp     \$$len, $in_len
    shrx    $t, $i, $t
    cmova   $i, $t
___
if ($len>64) {
$code.=<<___;
    xor     $i, $i
    cmp     \$${\($len - 64)}, $in_len
    cmovbe  $i, $t
___
}
$code.=<<___;
    kmovq   $t, $mask
___
}

sub bswap_round {
my(@ctrs)=@_;
for my $ctr (@ctrs) {
$code.=<<___;
    vpshufb $bswap_z, $ctr, $ctr
___
}
}

sub xor_round {
my($key, @ctrs)=@_;
for my $ctr (@ctrs) {
$code.=<<___;
    vpxorq  $key, $ctr, $ctr
___
}
}

sub enc_round {
my($key, @ctrs)=@_;
for my $ctr (@ctrs) {
$code.=<<___;
    vaesenc $key, $ctr, $ctr
___
}
}

sub enclast_round {
my($key, @ctrs)=@_;
for my $ctr (@ctrs) {
$code.=<<___;
    vaesenclast $key, $ctr, $ctr
___
}
}

sub mul {
my($b,$h)=@_;
$code.=<<___;
    vpclmulqdq \$0x01, $b, $h, $accm_z
    vpclmulqdq \$0x10, $b, $h, $t0_z
    vpclmulqdq \$0x00, $b, $h, $acc1_z
    vpclmulqdq \$0x11, $b, $h, $acc0_z
    vpxorq $t0_z, $accm_z, $accm_z
___
}

sub mul_acc {
my($b,$h)=@_;
$code.=<<___;
    vpclmulqdq \$0x01, $b, $h, $t1_z
    vpclmulqdq \$0x11, $b, $h, $t0_z
    vpxorq $t0_z, $acc0_z, $acc0_z
    vpclmulqdq \$0x00, $b, $h, $t0_z
    vpxorq $t0_z, $acc1_z, $acc1_z
    vpclmulqdq \$0x10, $b, $h, $t0_z
    vpternlogq \$0x96, $t0_z, $t1_z, $accm_z
___
}

# Accumulate `accm` into `acc0` and `acc1`
sub pre_reduce {
$code.=<<___;
    vpsrldq \$8, $accm_z, $t0_z
    vpslldq \$8, $accm_z, $accm_z

    vpxorq $accm_z, $acc0_z, $acc0_z
    vpxorq $t0_z, $acc1_z, $acc1_z
___
}

sub reduce_step_1 {
$code.=<<___;
    vpclmulqdq \$0x00, $poly_z, $acc0_z, $t0_z
    vpshufd    \$0x4e, $acc0_z, $acc0_z
    vpxorq     $t0_z, $acc0_z, $acc0_z
___
}

sub reduce_step_2 {
$code.=<<___;
    vpclmulqdq \$0x00, $poly_z, $acc0_z, $t0_z
    vpxorq     $t0_z, $acc1_z, $acc1_z
    vpshufd    \$0x4e, $acc1_z, $acc1_z
    vpxorq     $acc1_z, $acc0_z, $xi_z
___
}

{
$code.=<<___;
.align 64
.globl gcm_enc_avx512
.type gcm_enc_avx512,\@function,7
gcm_enc_avx512:
.cfi_startproc

    mov $in_len, %rax

    cmp \$0, $in_len
    je .Lgcm_enc_avx512_bail

    vzeroupper

    vbroadcasti64x2 .Lbswap(%rip), $bswap_z
    vbroadcasti64x2 .Lpoly(%rip), $poly_z
    vbroadcasti64x2 .Linc(%rip), $inc_z

    # xi_ptr is on stack as the 7th parameter
    mov 8(%rsp), $i
    vmovdqu64 ($i), $xi # This zeroes out the top 3 lanes of xi_z

    vbroadcasti64x2 ($iv), $ctr
    mov 16*15($aes_key), $rnds32

    vpshufb $bswap, $xi, $xi
    vpshufb $bswap_z, $ctr, $ctr

    # Pre-load most of the AES key schedule
    vbroadcasti64x2 16*0($aes_key), $k0
    vbroadcasti64x2 16*1($aes_key), $k1
    vbroadcasti64x2 16*2($aes_key), $k2
    vbroadcasti64x2 16*3($aes_key), $k3
    vbroadcasti64x2 16*4($aes_key), $k4
    vbroadcasti64x2 16*5($aes_key), $k5
    vbroadcasti64x2 16*6($aes_key), $k6
    vbroadcasti64x2 16*7($aes_key), $k7
    vbroadcasti64x2 16*8($aes_key), $k8
    sub \$8, $rnds
    shl \$4, $rnds
    vbroadcasti64x2 ${\(16*9)}($aes_key, $rnds), $klast

    # Compute the value of the final `CTR` block and store as it
    # is expected to be updated when function is finished
    mov $in_len, $i
    add \$15, $i
    shr \$4, $i

    vpxor $t0, $t0, $t0
    vpinsrd \$2, $i32, $t0, $t0

    # Initialize 16 counter blocks (accross 4 zmm registers)
    vpaddd .Linc_init(%rip), $ctr, $ctr0
    vpaddd $t0, $ctr_x, $t0
    vpaddd $inc_z, $ctr0, $ctr1
    vpaddd $inc_z, $ctr1, $ctr2
    vpaddd $inc_z, $ctr2, $ctr3
    vpaddd $inc_z, $ctr3, $ctr
    vpshufb $bswap, $t0, $t0
    vmovdqu $t0, ($iv)

    vpshufb $bswap_z, $ctr0, $ctr0
    vpshufb $bswap_z, $ctr1, $ctr1
    vpshufb $bswap_z, $ctr2, $ctr2
    vpshufb $bswap_z, $ctr3, $ctr3

    mov \$-1, $i
    kmovq $i, %k1
    kmovq $i, %k2
    kmovq $i, %k3
    kmovq $i, %k4

    cmp \$16*16, $in_len
    jae 1f

    cmp \$8*16, $in_len
    jbe .Lgcm_enc_avx512_128B_block

    # When there are less than 256 bytes to encrypt we use masked loads
    # to avoid going past the end of data
    vmovdqu8 64*0($in_ptr), $m0
    vmovdqu8 64*1($in_ptr), $m1
___
    gen_load_mask(64*3, "%k3");
$code.=<<___;
    vmovdqu8 64*2($in_ptr), $m2 {%k3}{z}
___
    gen_load_mask(64*4, "%k4");
$code.=<<___;
    vmovdqu8 64*3($in_ptr), $m3 {%k4}{z}

    jmp 2f
1:
    vmovdqu64 64*0($in_ptr), $m0
    vmovdqu64 64*1($in_ptr), $m1
    vmovdqu64 64*2($in_ptr), $m2
    vmovdqu64 64*3($in_ptr), $m3
2:
    leaq 64*4($in_ptr), $in_ptr
___
    xor_round($k0, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k1, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k2, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k3, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k4, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k5, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k6, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k7, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k8, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
    xor $i, $i
1:
        vbroadcasti64x2 ${\(16*9)}($aes_key, $i), $t0_z
        add \$16, $i
___
        enc_round($t0_z, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

        cmp $i, $rnds
        jnz 1b
___
    enclast_round($klast, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

    vpxorq $m0, $ctr0, $m0
    vpxorq $m1, $ctr1, $m1
    vpxorq $m2, $ctr2, $m2
    vpxorq $m3, $ctr3, $m3

    # Pre-load the 16 powers of H
    vmovdqu64  16*0($htbl_ptr), $h0_z
    vmovdqu64  16*4($htbl_ptr), $h1_z
    vmovdqu64  16*8($htbl_ptr), $h2_z
    vmovdqu64 16*12($htbl_ptr), $h3_z

.align 16
.Lgcm_enc_avx512_main_loop:
        cmp \$256, $in_len
        jbe .Lgcm_enc_avx512_hash_tail

        # In this loop we prepare a 256B block of encrypted counters,
        # while hashing in the previously encrypted 256B.
        sub \$256, $in_len

        vmovdqa64 $ctr, $ctr0
        vmovdqu8 $m0, 64*0($out_ptr)
        vpaddd $inc_z, $ctr, $ctr1
        vmovdqu8 $m1, 64*1($out_ptr)
        vpaddd $inc_z, $ctr1, $ctr2
        vmovdqu8 $m2, 64*2($out_ptr)
        vpaddd $inc_z, $ctr2, $ctr3
        vmovdqu8 $m3, 64*3($out_ptr)
        vpaddd $inc_z, $ctr3, $ctr

        leaq 64*4($out_ptr), $out_ptr
        vpshufb $bswap_z, $m0, $m0
___
        bswap_round($ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vpxorq $xi_z, $m0, $m0
___
        xor_round($k0, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vpshufb  $bswap_z, $m1, $m1
___
        mul($m0, $h0_z);
        enc_round($k1, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k2, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vpshufb   $bswap_z, $m2, $m2
___
        mul_acc($m1, $h1_z);
        enc_round($k3, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k4, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vpshufb   $bswap_z, $m3, $m3
___
        mul_acc($m2, $h2_z);
        enc_round($k5, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k6, $ctr0, $ctr1, $ctr2, $ctr3);

        mul_acc($m3, $h3_z);
$code.=<<___;

        cmp \$256, $in_len
        jae 1f

        # When there are less than 256 bytes of input remaining, perform a
        # masked load instead of an uncoditional 256 byte load
___
        gen_load_mask(64*1, "%k1");
$code.=<<___;
        vmovdqu8 64*0($in_ptr), $m0 {%k1}{z}
___
        gen_load_mask(64*2, "%k2");
$code.=<<___;
        vmovdqu8 64*1($in_ptr), $m1 {%k2}{z}
___
        gen_load_mask(64*3, "%k3");
$code.=<<___;
        vmovdqu8 64*2($in_ptr), $m2 {%k3}{z}
___
        gen_load_mask(64*4, "%k4");
$code.=<<___;
        vmovdqu8 64*3($in_ptr), $m3 {%k4}{z}

        jmp 2f
    1:
        # Unmasked load of 256 bytes
        vmovdqu64 64*0($in_ptr), $m0
        vmovdqu64 64*1($in_ptr), $m1
        vmovdqu64 64*2($in_ptr), $m2
        vmovdqu64 64*3($in_ptr), $m3
    2:
        leaq 64*4($in_ptr), $in_ptr
___
        enc_round($k7, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k8, $ctr0, $ctr1, $ctr2, $ctr3);

        pre_reduce();
        reduce_step_1();
$code.=<<___;
        xor $i, $i
.align 16
1:
            vbroadcasti64x2 ${\(16*9)}($aes_key, $i), $t0_z
            add \$16, $i
___
            enc_round($t0_z, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

            cmp $i, $rnds
            jnz 1b
___
        reduce_step_2();
$code.=<<___;

        vshufi64x2 \$0xe, $xi_z, $xi_z, $t0_z
        vpxorq $t0_z, $xi_z, $xi_z
___
        enclast_round($klast, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vshufi64x2 \$0x1, $xi_y, $xi_y, $t0_y

        vpxorq $ctr0, $m0, $m0
        vpxorq $ctr1, $m1, $m1
        vpxorq $ctr2, $m2, $m2
        vpxorq $ctr3, $m3, $m3

        vpxorq $t0_y, $xi_y, $xi_y

        vmovdqa64 $xi, $xi

        jmp .Lgcm_enc_avx512_main_loop

.Lgcm_enc_avx512_hash_tail:
    # At this point `in_len` indicates how many bytes we have to hash.
    # In order to get the proper hash keys we have to round up the len
    # to the next multiple of 16.
    add \$15, $in_len
    and \$0x1f0, $in_len
    mov $in_len, $t
    neg $t

    mov \$-1, $i
    shr \$3, $in_len

    bzhi $in_len, $i, $i
    kmovq $i, %k5

    vmovdqu8  $m0, 64*0($out_ptr){%k1}
    vmovdqu64 256($htbl_ptr, $t), $h0_z {%k5}{z}
    vmovdqu8  $m0, $m0 {%k1}{z}
    vpshufb   $bswap_z, $m0, $m0
    vpxorq    $xi_z, $m0, $m0
___
    mul($m0, $h0_z);
$code.=<<___;

    sub \$8, $in_len
    jle .Lgcm_enc_avx512_final_reduce

6:
        bzhi $in_len, $i, $i
        kmovq $i, %k5

        vmovdqu8   $m1, 64*1($out_ptr){%k2}
        vmovdqu64  320($htbl_ptr, $t), $h0_z {%k5}{z}
        vmovdqu8   $m1, $m1 {%k2}{z}
        vpshufb    $bswap_z, $m1, $m1
___
        mul_acc($m1, $h0_z);
$code.=<<___;

        sub \$8, $in_len
        jle .Lgcm_enc_avx512_final_reduce

        add \$64, $t

        vmovdqa64 $m2, $m1
        vmovdqa64 $m3, $m2
        kmovq %k3, %k2
        kmovq %k4, %k3
        leaq 64($out_ptr), $out_ptr

    jmp 6b

.Lgcm_enc_avx512_final_reduce:
___
    pre_reduce();
    reduce_step_1();
    reduce_step_2();
$code.=<<___;

    vshufi64x2 \$0xe, $xi_z, $xi_z, $t0_z
    vpxorq $t0_z, $xi_z, $xi_z
    vshufi64x2 \$0x1, $xi_y, $xi_y, $t0_y
    vpxorq $t0_y, $xi_y, $xi_y

    vpshufb $bswap, $xi, $xi

    mov 8(%rsp), $i
    vmovdqu $xi, ($i)

    vzeroupper
.Lgcm_enc_avx512_bail:

    ret

.Lgcm_enc_avx512_128B_block:

___
    gen_load_mask(64*1, "%k1");
$code.=<<___;
    vmovdqu8 64*0($in_ptr), $m0 {%k1}{z}
___
    gen_load_mask(64*2, "%k2");
$code.=<<___;
    vmovdqu8 64*1($in_ptr), $m1 {%k2}{z}
___
    xor_round($k0, $ctr0, $ctr1);
    enc_round($k1, $ctr0, $ctr1);
    enc_round($k2, $ctr0, $ctr1);
    enc_round($k3, $ctr0, $ctr1);
    enc_round($k4, $ctr0, $ctr1);
    enc_round($k5, $ctr0, $ctr1);
    enc_round($k6, $ctr0, $ctr1);
    enc_round($k7, $ctr0, $ctr1);
    enc_round($k8, $ctr0, $ctr1);
$code.=<<___;
    xor $i, $i
1:
        vbroadcasti64x2 ${\(16*9)}($aes_key, $i), $t0_z
        add \$16, $i
___
        enc_round($t0_z, $ctr0, $ctr1);
$code.=<<___;

        cmp $i, $rnds
        jnz 1b

___
    enclast_round($klast, $ctr0, $ctr1);
$code.=<<___;

    vpxorq $m0, $ctr0, $m0
    vpxorq $m1, $ctr1, $m1
    jmp .Lgcm_enc_avx512_hash_tail

.cfi_endproc
.size gcm_enc_avx512,.-gcm_enc_avx512
___
}

my $mm="%zmm0";

{
$code.=<<___;
.align 64
.globl gcm_dec_avx512
.type gcm_dec_avx512,\@function,7
gcm_dec_avx512:
.cfi_startproc

    mov $in_len, %rax

    cmp \$0, $in_len
    je .Lgcm_dec_avx512_bail

    vzeroupper

    vbroadcasti64x2 .Lbswap(%rip), $bswap_z
    vbroadcasti64x2 .Lpoly(%rip), $poly_z
    vbroadcasti64x2 .Linc(%rip), $inc_z

    # xi_ptr is on stack as the 7th parameter
    mov 8(%rsp), $i
    vmovdqu64 ($i), $xi # This zeroes out the top 3 lanes of xi_z

    vbroadcasti64x2 ($iv), $ctr
    mov 16*15($aes_key), $rnds32

    vpshufb $bswap, $xi, $xi
    vpshufb $bswap_z, $ctr, $ctr

    # Pre-load most of the AES key schedule
    vbroadcasti64x2 16*0($aes_key), $k0
    vbroadcasti64x2 16*1($aes_key), $k1
    vbroadcasti64x2 16*2($aes_key), $k2
    vbroadcasti64x2 16*3($aes_key), $k3
    vbroadcasti64x2 16*4($aes_key), $k4
    vbroadcasti64x2 16*5($aes_key), $k5
    vbroadcasti64x2 16*6($aes_key), $k6
    vbroadcasti64x2 16*7($aes_key), $k7
    vbroadcasti64x2 16*8($aes_key), $k8
    sub \$8, $rnds
    shl \$4, $rnds
    vbroadcasti64x2 ${\(16*9)}($aes_key, $rnds), $klast

    # Compute the value of the final `CTR` block and store as it
    # is expected to be updated when function is finished
    mov $in_len, $i
    add \$15, $i
    shr \$4, $i

    vpxor $t0, $t0, $t0
    vpinsrd \$2, $i32, $t0, $t0

    vpaddd $t0, $ctr_x, $t0
    vpshufb $bswap, $t0, $t0
    vmovdqu $t0, ($iv)

    # Initial counter values
    vpaddd .Linc_init(%rip), $ctr, $ctr

    mov \$-1, $i
    kmovq $i, %k1
    kmovq $i, %k2
    kmovq $i, %k3
    kmovq $i, %k4

    cmp \$256, $in_len
    jb .Lgcm_dec_avx512_last_block

    # Pre-load the 16 powers of H
    vmovdqu64  16*0($htbl_ptr), $h0_z
    vmovdqu64  16*4($htbl_ptr), $h1_z
    vmovdqu64  16*8($htbl_ptr), $h2_z
    vmovdqu64 16*12($htbl_ptr), $h3_z

.align 16
.Lgcm_dec_avx512_main_loop:
        sub \$256, $in_len

        vmovdqu64 64*0($in_ptr), $m0

        vmovdqa64 $ctr, $ctr0
        vpaddd $inc_z, $ctr0, $ctr1
        vpaddd $inc_z, $ctr1, $ctr2
        vpaddd $inc_z, $ctr2, $ctr3
        vpaddd $inc_z, $ctr3, $ctr

        vpshufb $bswap_z, $ctr0, $ctr0
        vpshufb $bswap_z, $ctr1, $ctr1
        vpshufb $bswap_z, $ctr2, $ctr2
        vpshufb $bswap_z, $ctr3, $ctr3
___
        xor_round($k0, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vmovdqu64 64*1($in_ptr), $m1

        vpshufb $bswap_z, $m0, $mm
        vpxorq $xi_z, $mm, $mm
___
        mul($mm, $h0_z);
        enc_round($k1, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k2, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

        vmovdqu64 64*2($in_ptr), $m2
        vpshufb   $bswap_z, $m1, $mm
___
        mul_acc($mm, $h1_z);
        enc_round($k3, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k4, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        vmovdqu64 64*3($in_ptr), $m3
        vpshufb   $bswap_z, $m2, $mm
___
        mul_acc($mm, $h2_z);
        enc_round($k5, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k6, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

        vpshufb   $bswap_z, $m3, $mm
___
        mul_acc($mm, $h3_z);
$code.=<<___;

        lea 64*4($in_ptr), $in_ptr
___
        enc_round($k7, $ctr0, $ctr1, $ctr2, $ctr3);
        enc_round($k8, $ctr0, $ctr1, $ctr2, $ctr3);

        pre_reduce();
        reduce_step_1();
$code.=<<___;
        xor $i, $i
.align 16
1:
            vbroadcasti64x2 ${\(16*9)}($aes_key, $i), $t0_z
            add \$16, $i
___
            enc_round($t0_z, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
            cmp $i, $rnds
            jnz 1b
___
        reduce_step_2();
$code.=<<___;

        vshufi64x2 \$0xe, $xi_z, $xi_z, $t0_z
        vpxorq $t0_z, $xi_z, $xi_z
___
        enclast_round($klast, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

        vshufi64x2 \$0x1, $xi_y, $xi_y, $t0_y
        vpxorq $t0_y, $xi_y, $xi_y

        vmovdqa $xi, $xi

        vpxorq $ctr0, $m0, $m0
        vpxorq $ctr1, $m1, $m1
        vpxorq $ctr2, $m2, $m2
        vpxorq $ctr3, $m3, $m3

        vmovdqu64 $m0, 64*0($out_ptr)
        vmovdqu64 $m1, 64*1($out_ptr)
        vmovdqu64 $m2, 64*2($out_ptr)
        vmovdqu64 $m3, 64*3($out_ptr)
        lea 64*4($out_ptr), $out_ptr

        cmp \$256, $in_len
        jge .Lgcm_dec_avx512_main_loop

.Lgcm_dec_avx512_last_block:
    cmp \$0, $in_len
    jz .Lgcm_dec_avx512_finish

    vmovdqa64 $ctr, $ctr0
    vpaddd $inc_z, $ctr0, $ctr1
    vpaddd $inc_z, $ctr1, $ctr2
    vpaddd $inc_z, $ctr2, $ctr3
    vpaddd $inc_z, $ctr3, $ctr

___
    gen_load_mask(64*1, "%k1");
$code.=<<___;
    vmovdqu8 64*0($in_ptr), $m0 {%k1}{z}
___
    gen_load_mask(64*2, "%k2");
$code.=<<___;
    vmovdqu8 64*1($in_ptr), $m1 {%k2}{z}
___
    gen_load_mask(64*3, "%k3");
$code.=<<___;
    vmovdqu8 64*2($in_ptr), $m2 {%k3}{z}
___
    gen_load_mask(64*4, "%k4");
$code.=<<___;
    vmovdqu8 64*3($in_ptr), $m3 {%k4}{z}

    add \$15, $in_len
    and \$0x1f0, $in_len
    mov $in_len, $t
    neg $t

    mov \$-1, $i
    shr \$3, $in_len
    bzhi $in_len, $i, $i
    kmovq $i, %k5

    vmovdqu64   256($htbl_ptr, $t), $h0_z {%k5}{z}
    vpshufb     $bswap_z, $m0, $h1_z
    vpxorq      $xi_z, $h1_z, $h1_z
___
    mul($h1_z, $h0_z);
$code.=<<___;
    vpshufb $bswap_z, $ctr0, $ctr0
    vpshufb $bswap_z, $ctr1, $ctr1
    vpshufb $bswap_z, $ctr2, $ctr2
    vpshufb $bswap_z, $ctr3, $ctr3
___
    xor_round($k0, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k1, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k2, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

    sub \$8, $in_len
    jle 3f
    bzhi $in_len, $i, $i
    kmovq $i, %k5

    vmovdqu64   320($htbl_ptr, $t), $h0_z {%k5}{z}
    vpshufb     $bswap_z, $m1, $h1_z
___
    mul_acc($h1_z, $h0_z);
$code.=<<___;
3:
___
    enc_round($k3, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k4, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

    sub \$8, $in_len
    jle 3f

    bzhi $in_len, $i, $i
    kmovq $i, %k5

    vmovdqu64   384($htbl_ptr, $t), $h0_z {%k5}{z}
    vpshufb     $bswap_z, $m2, $h1_z
___
    mul_acc($h1_z, $h0_z);
$code.=<<___;
3:
___
    enc_round($k5, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k6, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;

    sub \$8, $in_len
    jle 3f

    bzhi    $in_len, $i, $i
    kmovq   $i, %k5

    vmovdqu64   448($htbl_ptr, $t), $h0_z {%k5}{z}
    vpshufb     $bswap_z, $m3, $h1_z
___
    mul_acc($h1_z, $h0_z);
$code.=<<___;
3:
___
    enc_round($k7, $ctr0, $ctr1, $ctr2, $ctr3);
    enc_round($k8, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
    xor $i, $i
.align 16
1:
        vbroadcasti64x2 ${\(16*9)}($aes_key, $i), $t0_z
        add \$16, $i
___
        enc_round($t0_z, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
        cmp $i, $rnds
        jnz 1b
___
    enclast_round($klast, $ctr0, $ctr1, $ctr2, $ctr3);
$code.=<<___;
    vpxorq $ctr0, $m0, $m0
    vpxorq $ctr1, $m1, $m1
    vpxorq $ctr2, $m2, $m2
    vpxorq $ctr3, $m3, $m3

    vmovdqu8 $m0, 64*0($out_ptr){%k1}
    vmovdqu8 $m1, 64*1($out_ptr){%k2}
    vmovdqu8 $m2, 64*2($out_ptr){%k3}
    vmovdqu8 $m3, 64*3($out_ptr){%k4}
___
    pre_reduce();
    reduce_step_1();
    reduce_step_2();
$code.=<<___;

    vshufi64x2 \$0xe, $xi_z, $xi_z, $t0_z
    vpxorq $t0_z, $xi_z, $xi_z
    vshufi64x2 \$0x1, $xi_y, $xi_y, $t0_y
    vpxorq $t0_y, $xi_y, $xi_y

.Lgcm_dec_avx512_finish:

    vpshufb $bswap, $xi, $xi

    mov 8(%rsp), $i
    vmovdqu $xi, ($i)

    vzeroupper
.Lgcm_dec_avx512_bail:
    ret
.cfi_endproc
.size gcm_dec_avx512,.-gcm_dec_avx512
___
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT or die "error closing STDOUT: $!";
