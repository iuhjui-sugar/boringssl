#!/usr/bin/env perl

# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This code was provided by Intel.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

$code=<<___;

.data
.align 16

.mask:
.long 0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d
.con1:
.long 1,1,1,1
.con2:
.long 0x1b,0x1b,0x1b,0x1b
.con3:
.byte -1,-1,-1,-1,-1,-1,-1,-1,4,5,6,7,4,5,6,7

.local .mask, .con1, .con2, .con3

.text
___

# Parameters to the functions.
$out_ciphertext="%rdi";
$out_zero_ciphertext="%rsi";
$out_key_schedule="%rdx";
$key="%rcx";
$plaintext="%r8";

# Named registers for local values.
$block1="%xmm4";
$block2="%xmm5";
$auxreg="%xmm3";
$ks1_rega="%xmm1";
$ks1_regb="%xmm2";
$con_mask="%xmm0";
$mask="%xmm15";


sub ks_block_128 {
  my ($reg, $reg2, $aux) = @_;
  $code.=<<___;
	vpsllq \$32, $reg, $aux
	vpxor $aux, $reg, $reg
	vpshufb .con3(%rip), $reg, $aux
	vpxor $aux, $reg, $reg
	vpxor $reg2, $reg, $reg
___
}

sub round_128 {
  my ($i)=@_;
  $code.=<<___;
	vpshufb %xmm15, %xmm1, %xmm2
	vaesenclast %xmm0, %xmm2, %xmm2
	vpslld \$1, %xmm0, %xmm0
___
  &ks_block_128($ks1_rega, $ks1_regb, $auxreg);
  $code.=<<___;
	vaesenc %xmm1, $block1, $block1
	vaesenc %xmm1, $block2, $block2
	vmovdqu %xmm1, $i*16($out_key_schedule)
___
}

sub round_last_128 {
  my ($i)=@_;
  $code.=<<___;
	vpshufb %xmm15, %xmm1, %xmm2
	vaesenclast %xmm0, %xmm2, %xmm2
___
  &ks_block_128($ks1_rega, $ks1_regb, $auxreg);
  $code.=<<___;
	vaesenclast %xmm1, $block1, $block1
	vaesenclast %xmm1, $block2, $block2
	vmovdqu %xmm1, $i*16($out_key_schedule)
___
}

$code.=<<___;
.align 16
.globl aesni_schedule_and_encrypt_128
aesni_schedule_and_encrypt_128:
	movl \$9, 240($out_key_schedule)
	vmovdqu ($key), %xmm1
	vmovdqu ($plaintext), $block1
	vpxor $block2, $block2, $block2
	vmovdqu %xmm1, ($out_key_schedule)
	vpxor %xmm1, $block1, $block1
	vpxor %xmm1, $block2, $block2
	vmovdqa .con1(%rip), $con_mask
	vmovdqa .mask(%rip), $mask
___
for (my $i = 1; $i < 9; $i++) {
  &round_128($i);
}
$code.=<<___;
	vmovdqa .con2(%rip), $con_mask
___
	&round_128(9);
	&round_last_128(10);
$code.=<<___;
	vmovdqu $block1, ($out_ciphertext)
	vmovdqu $block2, ($out_zero_ciphertext)

	ret
.size	aesni_schedule_and_encrypt_128,.-aesni_schedule_and_encrypt_128
___


$block1="%xmm8";
$block2="%xmm9";
$auxreg="%xmm14";
$key1="%xmm1";
$key2="%xmm3";

sub round_double_256 {
  my ($i, $j)=@_;

  $code.=<<___;
	vpshufb %xmm15, %xmm3, %xmm2
	vaesenclast %xmm0, %xmm2, %xmm2
	vpslld \$1, %xmm0, %xmm0
	vpslldq \$4, %xmm1, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpxor %xmm2, %xmm1, %xmm1
	vaesenc %xmm1, $block1, $block1
	vaesenc %xmm1, $block2, $block2
	vmovdqu %xmm1, $i*16($out_key_schedule)
	vpshufd \$0xff, %xmm1, %xmm2
	vaesenclast %xmm14, %xmm2, %xmm2
	vpslldq \$4, %xmm3, %xmm4
	vpxor %xmm4, %xmm3, %xmm3
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm3, %xmm3
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm3, %xmm3
	vpxor %xmm2, %xmm3, %xmm3
	vaesenc %xmm3, $block1, $block1
	vaesenc %xmm3, $block2, $block2
	vmovdqu %xmm3, $j*16($out_key_schedule)
___
}

sub round_last_256 {
  my ($i)=@_;

  $code.=<<___
	vpshufb %xmm15, %xmm3, %xmm2
	vaesenclast %xmm0, %xmm2, %xmm2
	vpslldq \$4, %xmm1, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpslldq \$4, %xmm4, %xmm4
	vpxor %xmm4, %xmm1, %xmm1
	vpxor %xmm2, %xmm1, %xmm1
	vaesenclast %xmm1, $block1, $block1
	vaesenclast %xmm1, $block2, $block2
	vmovdqu %xmm1, $i*16($out_key_schedule)
___
}

$code.=<<___;
.align 16
.globl aesni_schedule_and_encrypt_256
aesni_schedule_and_encrypt_256:
	movl \$13, 240($out_key_schedule)
	vmovdqa .con1(%rip), $con_mask
	vmovdqa .mask(%rip), $mask
	vmovdqu ($plaintext), $block1
	vpxor $block2, $block2, $block2
	vmovdqu ($key), $key1
	vmovdqu 16($key), $key2
	vpxor $key1, $block1, $block1
	vpxor $key1, $block2, $block2
	vaesenc $key2, $block1, $block1
	vaesenc $key2, $block2, $block2
	vmovdqu $key1, ($out_key_schedule)
	vmovdqu $key2, 16($out_key_schedule)
	vpxor $auxreg, $auxreg, $auxreg
___

&round_double_256(2, 3);
&round_double_256(4, 5);
&round_double_256(6, 7);
&round_double_256(8, 9);
&round_double_256(10, 11);
&round_double_256(12, 13);
&round_last_256(14);

$code.=<<___;
	vmovdqu $block1, ($out_ciphertext)
	vmovdqu $block2, ($out_zero_ciphertext)
	ret
.size	aesni_schedule_and_encrypt_256,.-aesni_schedule_and_encrypt_256
___

print $code;

close STDOUT;
