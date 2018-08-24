#! /usr/bin/env perl
#
# Written by Nir Drucker, and Shay Gueron
# AWS Cryptographic Algorithms Group
# (ndrucker@amazon.com, gueron@amazon.com)
# based on BN_mod_inverse_odd

while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

$code.=<<___;

.text

#############################################################################
# extern int beeu_mod_inverse_non_ctime(BN_ULONG out[P256_LIMBS], 
#                                       BN_ULONG   a[P256_LIMBS], BN_ULONG n[P256_LIMBS]);
#
# Assumption1: n is odd for the BEEU
# Assumption2: 1 < a < n < 2^256
# Setting the ABI parameters
#define out %rdi
#define a   %rsi
#define n   %rdx

# X/Y will hold the inverse parameter
# Assumption: X,Y<2^(256)
#define x0 %r8
#define x1 %r9
#define x2 %r10
#define x3 %r11
#borrow from out (out is needed only at the end)
#define x4 %rdi 

#define y0 %r12
#define y1 %r13
#define y2 %r14
#define y3 %r15
#define y4 %rbp

#define shift %rcx
#define t0    %rax
#define t1    %rbx
#define t2    %rsi
#borrow
#define t3    %rcx 

#define T0    %xmm0
#define T1    %xmm1

# Offsets on the stack
#define out_rsp          0x00
#define shift_rsp       (out_rsp  +0x8)
#define a_rsp0           (shift_rsp+0x8)
#define a_rsp1           (a_rsp0+0x8)
#define a_rsp2           (a_rsp1+0x8)
#define a_rsp3           (a_rsp2+0x8)
#define b_rsp0           (a_rsp3+0x8)
#define b_rsp1           (b_rsp0+0x8)
#define b_rsp2           (b_rsp1+0x8)
#define b_rsp3           (b_rsp2+0x8)

# Borrow when a_rsp/b_rsp are no longer needed.
#define y_rsp0           (a_rsp0)
#define y_rsp1           (y_rsp0+0x8)
#define y_rsp2           (y_rsp1+0x8)
#define y_rsp3           (y_rsp2+0x8)
#define y_rsp4           (y_rsp3+0x8)

#define last_rsp_offset  (b_rsp3+0x8)
___

$code.=<<___;

.macro STORE
    push %r12
    push %r13
    push %r14
    push %r15
    push %rbx
    push %rsi
    push %rbp
    sub \$last_rsp_offset, %rsp
    movq out, out_rsp(%rsp)
.endm

.macro RESTORE
    add \$last_rsp_offset, %rsp
    pop %rbp
    pop %rsi
    pop %rbx
    pop %r15
    pop %r14
    pop %r13
    pop %r12
.endm

.macro TEST_B_ZERO
    xor t1, t1
    orq b_rsp0(%rsp), t1
    orq b_rsp1(%rsp), t1
    orq b_rsp2(%rsp), t1
    orq b_rsp3(%rsp), t1
    jz .Lbeeu_loop_end
.endm

.macro SHIFT1 var0 var1 var2 var3 var4
    # Ensure X is even and divide by two.
    movq \$1, t1
    andq \\var0, t1
    jz .Lbeeu_shift_loop_after_add\\@
    add 0*8(n), \\var0
    adc 1*8(n), \\var1
    adc 2*8(n), \\var2
    adc 3*8(n), \\var3
    adc \$0, \\var4

.Lbeeu_shift_loop_after_add\\@ \:
    shrd \$1, \\var1, \\var0
    shrd \$1, \\var2, \\var1
    shrd \$1, \\var3, \\var2
    shrd \$1, \\var4, \\var3
    shr  \$1, \\var4
.endm

.macro SHIFT256 var

    # Copy shifted values.
    # Remember not to override t3=rcx
    movq 1*8+\\var(%rsp), t0
    movq 2*8+\\var(%rsp), t1
    movq 3*8+\\var(%rsp), t2

    shrd %cl, t0, 0*8+\\var(%rsp)
    shrd %cl, t1, 1*8+\\var(%rsp) 
    shrd %cl, t2, 2*8+\\var(%rsp)
    
    shr  %cl, t2
    mov t2, 3*8+\\var(%rsp)

.endm

.type beeu_mod_inverse_non_ctime,\@function
.hidden beeu_mod_inverse_non_ctime
.globl  beeu_mod_inverse_non_ctime
.align 32
beeu_mod_inverse_non_ctime:
    STORE

    # X=1, Y=0
    movq \$1, x0
    xorq x1, x1
    xorq x2, x2
    xorq x3, x3
    xorq x4, x4
    
    xorq y0, y0
    xorq y1, y1
    xorq y2, y2
    xorq y3, y3
    xorq y4, y4

    # Copy a/n into B/A on the stack.
    vmovdqu 0*8(a), T0
    vmovdqu 2*8(a), T1
    vmovdqu T0, b_rsp0(%rsp)
    vmovdqu T1, b_rsp2(%rsp)

    vmovdqu 0*8(n), T0
    vmovdqu 2*8(n), T1
    vmovdqu T0, a_rsp0(%rsp)
    vmovdqu T1, a_rsp2(%rsp)

.Lbeeu_loop:
    TEST_B_ZERO

    # 0 < B < |n|,
    # 0 < A <= |n|,
    # (1)      X*a  ==  B   (mod |n|),
    # (2) (-1)*Y*a  ==  A   (mod |n|)

    # Now divide B by the maximum possible power of two in the
    # integers, and divide X by the same value mod |n|. When we're
    # done, (1) still holds.
    movq \$1, shift

    # Note that B > 0
.Lbeeu_shift_loop_XB:
    movq shift, t1
    andq b_rsp0(%rsp), t1
    jnz .Lbeeu_shift_loop_end_XB
    
    SHIFT1 x0, x1, x2, x3, x4
    shl \$1, shift
    
    # Test wraparound of the shift parameter. The probability to have 32 zeroes in a row is small
    # Therefore having the value below equal \$0x8000000 or \$0x8000 
    # Does not affect the performance. We choose 0x8000000 because it is the 
    # maximal immediate value possible.
    cmp \$0x8000000, shift
    jne .Lbeeu_shift_loop_XB

.Lbeeu_shift_loop_end_XB:
    bsf shift, shift
    test shift, shift
    jz .Lbeeu_no_shift_XB

    SHIFT256 b_rsp0

.Lbeeu_no_shift_XB:

    # Same for A and Y.  Afterwards, (2) still holds.
    movq \$1, shift

    # Note that A > 0
.Lbeeu_shift_loop_YA:
    movq shift, t1
    andq a_rsp0(%rsp), t1
    jnz .Lbeeu_shift_loop_end_YA
    
    SHIFT1 y0, y1, y2, y3, y4
    shl \$1, shift
    
    # Test wraparound of the shift parameter. The probability to have 32 zeroes in a row is small
    # Therefore having the value below equal \$0x8000000 or \$0x8000 
    # Does not affect the performance. We choose 0x8000000 because it is the 
    # maximal immediate value possible.
    cmp \$0x8000000, shift
    jne .Lbeeu_shift_loop_YA

.Lbeeu_shift_loop_end_YA:
    bsf shift, shift
    test shift, shift
    jz .Lbeeu_no_shift_YA

    SHIFT256 a_rsp0

.Lbeeu_no_shift_YA:

    #T = B-A (A,B < 2^256)
    mov b_rsp0(%rsp), t0
    mov b_rsp1(%rsp), t1
    mov b_rsp2(%rsp), t2
    mov b_rsp3(%rsp), t3
    sub a_rsp0(%rsp), t0
    sbb a_rsp1(%rsp), t1
    sbb a_rsp2(%rsp), t2
    sbb a_rsp3(%rsp), t3  #borrow from shift
    jnc .Lbeeu_B_bigger_than_A

    #A = A - B
    mov a_rsp0(%rsp), t0
    mov a_rsp1(%rsp), t1
    mov a_rsp2(%rsp), t2
    mov a_rsp3(%rsp), t3
    sub b_rsp0(%rsp), t0
    sbb b_rsp1(%rsp), t1
    sbb b_rsp2(%rsp), t2
    sbb b_rsp3(%rsp), t3
    mov t0, a_rsp0(%rsp)
    mov t1, a_rsp1(%rsp)
    mov t2, a_rsp2(%rsp)
    mov t3, a_rsp3(%rsp)
    
    #Y = Y  X
    add x0, y0
    adc x1, y1
    adc x2, y2
    adc x3, y3
    adc x4, y4
    jmp .Lbeeu_loop
    
.Lbeeu_B_bigger_than_A:
    #B = T = B - A
    mov t0, b_rsp0(%rsp)
    mov t1, b_rsp1(%rsp)
    mov t2, b_rsp2(%rsp)
    mov t3, b_rsp3(%rsp)
    
    #X = Y  X
    add y0, x0
    adc y1, x1
    adc y2, x2
    adc y3, x3
    adc y4, x4

    jmp .Lbeeu_loop
            
.Lbeeu_loop_end:

    # The Euclid's algorithm loop ends when A == beeu(a,n);
    # Therefore (-1)*Y*a == A (mod |n|), Y>0

    # Verify that A = 1 ==> (-1)*Y*a = A = 1  (mod |n|) 
    mov a_rsp0(%rsp), t1
    dec t1
    or a_rsp1(%rsp), t1
    or a_rsp2(%rsp), t1
    or a_rsp3(%rsp), t1
    #. If not fail
    jnz .Lbeeu_err
    
    # From this point on, we no longer need X 
    # Therefore we use it as a temporary storage.
    # X = n 
    movq 0*8(n), x0
    movq 1*8(n), x1
    movq 2*8(n), x2
    movq 3*8(n), x3
    xorq x4, x4

.Lbeeu_redution_loop:
    movq y0, y_rsp0(%rsp)
    movq y1, y_rsp1(%rsp)
    movq y2, y_rsp2(%rsp)
    movq y3, y_rsp3(%rsp)
    movq y4, y_rsp4(%rsp)

    #. If Y>n ==> Y=Y-n
    sub x0, y0
    sbb x1, y1
    sbb x2, y2
    sbb x3, y3
    sbb \$0, y4

    # Choose old Y or new Y
    cmovc y_rsp0(%rsp), y0
    cmovc y_rsp1(%rsp), y1
    cmovc y_rsp2(%rsp), y2
    cmovc y_rsp3(%rsp), y3
    jnc .Lbeeu_redution_loop 

    # X = n - Y (n, Y < 2^256), (Cancel the (-1))
    sub y0, x0
    sbb y1, x1
    sbb y2, x2
    sbb y3, x3

.Lbeeu_save:
    # Save the inverse(<2^256) to out.
    mov out_rsp(%rsp), out

    movq x0, 0*8(out)
    movq x1, 1*8(out)
    movq x2, 2*8(out)
    movq x3, 3*8(out)
    
    # The function returns 1
    movq \$1, %rax
    jmp .Lbeeu_finish

.Lbeeu_err:
    # The function returns 0 
    xorq %rax, %rax

.Lbeeu_finish:
    RESTORE
    ret

.size beeu_mod_inverse_non_ctime, .-beeu_mod_inverse_non_ctime

#############################################################################
# extern int p256_fe_add_in_place(const BN_ULONG out[P256_LIMBS], const BN_ULONG in[P256_LIMBS])
#
# Setting the ABI parameters
#define out %rdi
#define in  %rsi

.type p256_fe_add_in_place,\@function
.hidden p256_fe_add_in_place
.globl  p256_fe_add_in_place
.align 32
p256_fe_add_in_place:

    mov 0*8(in), %r8
    mov 1*8(in), %r9
    mov 2*8(in), %r10
    mov 3*8(in), %r11
    add %r8,  0*8(out)
    adc %r9,  1*8(out)
    adc %r10, 2*8(out)
    adc %r11, 3*8(out)
    ret

.size p256_fe_add_in_place, .-p256_fe_add_in_place
___

print $code;
close STDOUT;
