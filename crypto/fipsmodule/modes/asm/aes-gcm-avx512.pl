# Copyright (C) 2021 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions
# and limitations under the License.
#
#
# This implementation is based on the AES-GCM code (AVX512VAES + VPCLMULQDQ)
# from Intel(R) Multi-Buffer Crypto for IPsec Library v1.0
# (https://github.com/intel/intel-ipsec-mb).
# Original author is Tomasz Kantecki <tomasz.kantecki@intel.com>.
#
# August 2021
#
# Initial release.
#
# GCM128_CONTEXT structure has storage for 16 hkeys only, but this
# implementation can use up to 48.  To avoid extending the context size,
# precompute and store in the context first 16 hkeys only, and compute the rest
# on demand keeping them in the local frame.
#
#======================================================================
# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output  = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop   : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.|          ? shift : undef;

$win64 = 0;
$win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx512vaes = 1;

$0 =~ m/(.*[\/\\])[^\/\\]+$/;
$dir = $1;
($xlate = "${dir}x86_64-xlate.pl" and -f $xlate)
  or ($xlate = "${dir}../../../perlasm/x86_64-xlate.pl" and -f $xlate)
  or die "can't locate x86_64-xlate.pl";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
  or die "can't call $xlate: $!";
*STDOUT = *OUT;

#======================================================================
# ; Mapping key length -> AES rounds number
my %aes_rounds = (
  128 => 9,
  192 => 11,
  256 => 13);

if ($avx512vaes > 0) { #<<<

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Code generation control switches
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

# ; ABI-aware zeroing of volatile registers in EPILOG().
my $CLEAR_SCRATCH_REGISTERS = 1;

# ; Zero HKeys storage from the stack if they are stored there
my $CLEAR_HKEYS_STORAGE_ON_EXIT = 1;

# ; Enable / disable check of function arguments for null pointer
# ; Currently disabled, as this check is handled outside.
my $CHECK_FUNCTION_ARGUMENTS = 0;

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Stack frame definition
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

# (1) -> +64(Win)/+48(Lin)-byte space for pushed GPRs
# (2) -> +8-byte space for 16-byte alignment of XMM storage
# (3) -> Frame pointer (%RBP)
# (4) -> +160-byte XMM storage (Windows only, zero on Linux)
# (5) -> +48-byte space for 64-byte alignment of %RSP from p.8
# (6) -> +768-byte LOCAL storage (optional, can be omitted in some functions)
# (7) -> +768-byte HKEYS storage
# (8) -> Stack pointer (%RSP) aligned on 64-byte boundary

my $GP_STORAGE  = $win64 ? 8 * 8     : 8 * 6;    # ; space for saved non-volatile GP registers (pushed on stack)
my $XMM_STORAGE = $win64 ? (10 * 16) : 0;        # ; space for saved XMM registers
my $HKEYS_STORAGE = (48 * 16);                   # ; space for HKeys^i, i=1..48
my $LOCAL_STORAGE = (48 * 16);                   # ; space for up to 48 AES blocks

my $STACK_HKEYS_OFFSET = 0;
my $STACK_LOCAL_OFFSET = ($STACK_HKEYS_OFFSET + $HKEYS_STORAGE);

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Function arguments abstraction
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
my ($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9, $arg10, $arg11);

# ; This implementation follows the convention: for non-leaf functions (they
# ; must call PROLOG) %rbp is used as a frame pointer, and has fixed offset from
# ; the function entry: $GP_STORAGE + [8 bytes alignment (Windows only)].  This
# ; helps to facilitate SEH handlers writing.
#
# ; Leaf functions here do not use more than 4 input arguments.
if ($win64) {
  $arg1  = "%rcx";
  $arg2  = "%rdx";
  $arg3  = "%r8";
  $arg4  = "%r9";
  $arg5  = "`$GP_STORAGE + 8 + 8*5`(%rbp)";    # +8 - alignment bytes
  $arg6  = "`$GP_STORAGE + 8 + 8*6`(%rbp)";
  $arg7  = "`$GP_STORAGE + 8 + 8*7`(%rbp)";
  $arg8  = "`$GP_STORAGE + 8 + 8*8`(%rbp)";
  $arg9  = "`$GP_STORAGE + 8 + 8*9`(%rbp)";
  $arg10 = "`$GP_STORAGE + 8 + 8*10`(%rbp)";
  $arg11 = "`$GP_STORAGE + 8 + 8*11`(%rbp)";
} else {
  $arg1  = "%rdi";
  $arg2  = "%rsi";
  $arg3  = "%rdx";
  $arg4  = "%rcx";
  $arg5  = "%r8";
  $arg6  = "%r9";
  $arg7  = "`$GP_STORAGE + 8*1`(%rbp)";
  $arg8  = "`$GP_STORAGE + 8*2`(%rbp)";
  $arg9  = "`$GP_STORAGE + 8*3`(%rbp)";
  $arg10 = "`$GP_STORAGE + 8*4`(%rbp)";
  $arg11 = "`$GP_STORAGE + 8*5`(%rbp)";
}

# ; Offsets in gcm128_context structure (see crypto/fipsmodule/modes/modes.h)
my $CTX_OFFSET_CurCount  = (16 * 0);          #  ; (Yi) Current counter for generation of encryption key
my $CTX_OFFSET_PEncBlock = (16 * 1);          #  ; (repurposed EKi field) Partial block buffer
my $CTX_OFFSET_EK0       = (16 * 2);          #  ; (EK0) Encrypted Y0 counter (see gcm spec notation)
my $CTX_OFFSET_AadLen    = (16 * 3);          #  ; (len.u[0]) Length of Hash which has been input
my $CTX_OFFSET_InLen     = ((16 * 3) + 8);    #  ; (len.u[1]) Length of input data which will be encrypted or decrypted
my $CTX_OFFSET_AadHash   = (16 * 4);          #  ; (Xi) Current hash
my $CTX_OFFSET_HTable    = (16 * 6);          #  ; (Htable) Precomputed table (allows 16 values)

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Helper functions
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

# ; Generates "random" local labels
sub random_string() {
  my @chars  = ('a' .. 'z', 'A' .. 'Z', '0' .. '9', '_');
  my $length = 15;
  my $str;
  map { $str .= $chars[rand(33)] } 1 .. $length;
  return $str;
}

sub BYTE {
  my ($reg) = @_;
  if ($reg =~ /%r[abcd]x/i) {
    $reg =~ s/%r([abcd])x/%${1}l/i;
  } elsif ($reg =~ /%r[sdb][ip]/i) {
    $reg =~ s/%r([sdb][ip])/%${1}l/i;
  } elsif ($reg =~ /%r[0-9]{1,2}/i) {
    $reg =~ s/%(r[0-9]{1,2})/%${1}b/i;
  } else {
    die "BYTE: unknown register: $reg\n";
  }
  return $reg;
}

sub WORD {
  my ($reg) = @_;
  if ($reg =~ /%r[abcdsdb][xip]/i) {
    $reg =~ s/%r([abcdsdb])([xip])/%${1}${2}/i;
  } elsif ($reg =~ /%r[0-9]{1,2}/) {
    $reg =~ s/%(r[0-9]{1,2})/%${1}w/i;
  } else {
    die "WORD: unknown register: $reg\n";
  }
  return $reg;
}

sub DWORD {
  my ($reg) = @_;
  if ($reg =~ /%r[abcdsdb][xip]/i) {
    $reg =~ s/%r([abcdsdb])([xip])/%e${1}${2}/i;
  } elsif ($reg =~ /%r[0-9]{1,2}/i) {
    $reg =~ s/%(r[0-9]{1,2})/%${1}d/i;
  } else {
    die "DWORD: unknown register: $reg\n";
  }
  return $reg;
}

sub XWORD {
  my ($reg) = @_;
  if ($reg =~ /%[xyz]mm/i) {
    $reg =~ s/%[xyz]mm/%xmm/i;
  } else {
    die "XWORD: unknown register: $reg\n";
  }
  return $reg;
}

sub YWORD {
  my ($reg) = @_;
  if ($reg =~ /%[xyz]mm/i) {
    $reg =~ s/%[xyz]mm/%ymm/i;
  } else {
    die "YWORD: unknown register: $reg\n";
  }
  return $reg;
}

sub ZWORD {
  my ($reg) = @_;
  if ($reg =~ /%[xyz]mm/i) {
    $reg =~ s/%[xyz]mm/%zmm/i;
  } else {
    die "ZWORD: unknown register: $reg\n";
  }
  return $reg;
}

# ; Provides memory location for the corresponding HashKey power
sub HashKeyByIdx {
  my ($idx, $base, $displacement) = @_;
  die "HashKeyOffset: idx out of bounds! idx = $idx\n" if ($idx > 48 || $idx < 1);
  $displacement = 0 if (!$displacement);

  my $offset_base;
  my $offset_i;
  if ($base eq "%rsp") {    # frame storage
    $offset_base = $STACK_HKEYS_OFFSET;
    $offset_i    = 16 * (48 - $idx);
  } else {                  # context storage
    die "HashKeyOffset: idx out of bounds for context storage! idx = $idx\n" if ($idx > 16);
    $offset_base = 0;
    $offset_i    = 16 * (16 - $idx);
  }
  return "`$offset_base + $offset_i + $displacement`($base)";
}

# ; Creates local frame and does back up of non-volatile registers.
# ; Holds stack unwinding directives.
sub PROLOG {
  my ($need_hkeys_stack_storage, $need_aes_stack_storage, $func_name) = @_;

  my $DYNAMIC_STACK_ALLOC_SIZE            = 0;
  my $DYNAMIC_STACK_ALLOC_ALIGNMENT_SPACE = $win64 ? 48 : 52;

  if ($need_hkeys_stack_storage) {
    $DYNAMIC_STACK_ALLOC_SIZE += $HKEYS_STORAGE;
  }

  if ($need_aes_stack_storage) {
    if (!$need_hkeys_stack_storage) {
      die "PROLOG: unsupported case - aes storage without hkeys one";
    }
    $DYNAMIC_STACK_ALLOC_SIZE += $LOCAL_STORAGE;
  }

  $code .= <<___;
    push    %rbx
.cfi_push   %rbx
.L${func_name}_seh_push_rbx:
    push    %rbp
.cfi_push   %rbp
.L${func_name}_seh_push_rbp:
    push    %r12
.cfi_push   %r12
.L${func_name}_seh_push_r12:
    push    %r13
.cfi_push   %r13
.L${func_name}_seh_push_r13:
    push    %r14
.cfi_push   %r14
.L${func_name}_seh_push_r14:
    push    %r15
.cfi_push   %r15
.L${func_name}_seh_push_r15:
___

  if ($win64) {
    $code .= <<___;
    push    %rdi
.L${func_name}_seh_push_rdi:
    push    %rsi
.L${func_name}_seh_push_rsi:

    sub     \$`$XMM_STORAGE+8`,%rsp   # +8 alignment
.L${func_name}_seh_allocstack_xmm:
___
  }
  $code .= <<___;
    # ; %rbp contains stack pointer right after GP regs pushed at stack + [8
    # ; bytes of alignment (Windows only)].  It serves as a frame pointer in SEH
    # ; handlers. The requirement for a frame pointer is that its offset from
    # ; RSP shall be multiple of 16, and not exceed 240 bytes. The frame pointer
    # ; itself seems to be reasonable to use here, because later we do 64-byte stack
    # ; alignment which gives us non-determinate offsets and complicates writing
    # ; SEH handlers.
    #
    # ; It also serves as an anchor for retrieving stack arguments on both Linux
    # ; and Windows.
    lea     `$XMM_STORAGE`(%rsp),%rbp
.cfi_def_cfa_register %rbp
.L${func_name}_seh_setfp:
___
  if ($win64) {

    # ; xmm6:xmm15 need to be preserved on Windows
    foreach my $reg_idx (6 .. 15) {
      my $xmm_reg_offset = ($reg_idx - 6) * 16;
      $code .= <<___;
        vmovdqu           %xmm${reg_idx},$xmm_reg_offset(%rsp)
.L${func_name}_seh_save_xmm${reg_idx}:
___
    }
  }

  $code .= <<___;
# Prolog ends here. Next stack allocation is treated as "dynamic".
.L${func_name}_seh_prolog_end:
___

  if ($DYNAMIC_STACK_ALLOC_SIZE) {
    $code .= <<___;
        sub               \$`$DYNAMIC_STACK_ALLOC_SIZE + $DYNAMIC_STACK_ALLOC_ALIGNMENT_SPACE`,%rsp
        and               \$(-64),%rsp
___
  }
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Restore register content for the caller.
# ;;; And cleanup stack.
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub EPILOG {
  my ($hkeys_storage_on_stack, $payload_len) = @_;

  my $rndsuffix = &random_string();

  if ($hkeys_storage_on_stack && $CLEAR_HKEYS_STORAGE_ON_EXIT) {

    # ; There is no need in hkeys cleanup if payload len was small, i.e. no hkeys
    # ; were stored in the local frame storage
    $code .= <<___;
        cmpq              \$`16*16`,$payload_len
        jbe               .Lskip_hkeys_cleanup_${rndsuffix}
        vpxor             %xmm0,%xmm0,%xmm0
___
    for (my $i = 0; $i < int($HKEYS_STORAGE / 64); $i++) {
      $code .= "vmovdqa64         %zmm0,`$STACK_HKEYS_OFFSET + 64*$i`(%rsp)\n";
    }
    $code .= ".Lskip_hkeys_cleanup_${rndsuffix}:\n";
  }

  if ($CLEAR_SCRATCH_REGISTERS) {
    &clear_scratch_gps_asm();
    &clear_scratch_zmms_asm();
  } else {
    $code .= "vzeroupper\n";
  }

  if ($win64) {

    # ; restore xmm15:xmm6
    for (my $reg_idx = 15; $reg_idx >= 6; $reg_idx--) {
      my $xmm_reg_offset = -$XMM_STORAGE + ($reg_idx - 6) * 16;
      $code .= <<___;
        vmovdqu           $xmm_reg_offset(%rbp),%xmm${reg_idx},
___
    }
  }

  if ($win64) {

    # Forming valid epilog for SEH with use of frame pointer.
    # https://docs.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-160#epilog-code
    $code .= "lea      8(%rbp),%rsp\n";
  } else {
    $code .= "lea      (%rbp),%rsp\n";
    $code .= ".cfi_def_cfa_register %rsp\n";
  }

  if ($win64) {
    $code .= <<___;
     pop     %rsi
.cfi_pop     %rsi
     pop     %rdi
.cfi_pop     %rdi
___
  }
  $code .= <<___;
     pop     %r15
.cfi_pop     %r15
     pop     %r14
.cfi_pop     %r14
     pop     %r13
.cfi_pop     %r13
     pop     %r12
.cfi_pop     %r12
     pop     %rbp
.cfi_pop     %rbp
     pop     %rbx
.cfi_pop     %rbx
___
}

# ; Clears all scratch ZMM registers
# ;
# ; It should be called before restoring the XMM registers
# ; for Windows (XMM6-XMM15).
# ;
sub clear_scratch_zmms_asm {

  # ; On Linux, all ZMM registers are scratch registers
  if (!$win64) {
    $code .= "vzeroall\n";
  } else {
    foreach my $i (0 .. 5) {
      $code .= "vpxorq  %xmm${i},%xmm${i},%xmm${i}\n";
    }
  }
  foreach my $i (16 .. 31) {
    $code .= "vpxorq  %xmm${i},%xmm${i},%xmm${i}\n";
  }
}

# Clears all scratch GP registers
sub clear_scratch_gps_asm {
  foreach my $reg ("%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11") {
    $code .= "xor $reg,$reg\n";
  }
  if (!$win64) {
    foreach my $reg ("%rsi", "%rdi") {
      $code .= "xor $reg,$reg\n";
    }
  }
}

sub precompute_hkeys_on_stack {
  my $HTABLE      = $_[0];
  my $HKEYS_READY = $_[1];
  my $ZTMP0       = $_[2];
  my $ZTMP1       = $_[3];
  my $ZTMP2       = $_[4];
  my $ZTMP3       = $_[5];
  my $ZTMP4       = $_[6];
  my $ZTMP5       = $_[7];
  my $ZTMP6       = $_[8];
  my $ZTMP7       = $_[9];

  my $rndsuffix = &random_string();

  # ; Fill the stack with the first 16 hkeys from the context
  $code .= <<___;
        test              $HKEYS_READY,$HKEYS_READY
        jnz              .L_skip_hkeys_precomputation_${rndsuffix}

        # ; Move 16 hkeys from the context to stack
        vmovdqu64         @{[HashKeyByIdx(4,$HTABLE)]},$ZTMP0
        vmovdqu64         $ZTMP0,@{[HashKeyByIdx(4,"%rsp")]}

        vmovdqu64         @{[HashKeyByIdx(8,$HTABLE)]},$ZTMP1
        vmovdqu64         $ZTMP1,@{[HashKeyByIdx(8,"%rsp")]}

        # ; broadcast HashKey^8
        vshufi64x2        \$0x00,$ZTMP1,$ZTMP1,$ZTMP1

        vmovdqu64         @{[HashKeyByIdx(12,$HTABLE)]},$ZTMP2
        vmovdqu64         $ZTMP2,@{[HashKeyByIdx(12,"%rsp")]}

        vmovdqu64         @{[HashKeyByIdx(16,$HTABLE)]},$ZTMP3
        vmovdqu64         $ZTMP3,@{[HashKeyByIdx(16,"%rsp")]}
___

  # ; Precompute hkeys^i, i=17..48
  my $i = 20;
  foreach (1 .. int((48 - 16) / 8)) {

    # ;; compute HashKey^(4 + n), HashKey^(3 + n), ... HashKey^(1 + n)
    &GHASH_MUL($ZTMP2, $ZTMP1, $ZTMP4, $ZTMP5, $ZTMP6, $ZTMP7, $ZTMP0);
    $code .= "vmovdqu64         $ZTMP2,@{[HashKeyByIdx($i,\"%rsp\")]}\n";
    $i += 4;

    # ;; compute HashKey^(8 + n), HashKey^(7 + n), ... HashKey^(5 + n)
    &GHASH_MUL($ZTMP3, $ZTMP1, $ZTMP4, $ZTMP5, $ZTMP6, $ZTMP7, $ZTMP0);
    $code .= "vmovdqu64         $ZTMP3,@{[HashKeyByIdx($i,\"%rsp\")]}\n";
    $i += 4;
  }
  $code .= "mov     \$1,$HKEYS_READY\n";
  $code .= ".L_skip_hkeys_precomputation_${rndsuffix}:\n";
}

# ;; =============================================================================
# ;; Generic macro to produce code that executes $OPCODE instruction
# ;; on selected number of AES blocks (16 bytes long) between 0 and 16.
# ;; All three operands of the instruction come from registers.
# ;; Note: if 3 blocks are left at the end instruction is produced to operate all
# ;;       4 blocks (full width of ZMM)
sub ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16 {
  my $NUM_BLOCKS = $_[0];    # [in] numerical value, number of AES blocks (0 to 16)
  my $OPCODE     = $_[1];    # [in] instruction name
  my @DST;
  $DST[0] = $_[2];           # [out] destination ZMM register
  $DST[1] = $_[3];           # [out] destination ZMM register
  $DST[2] = $_[4];           # [out] destination ZMM register
  $DST[3] = $_[5];           # [out] destination ZMM register
  my @SRC1;
  $SRC1[0] = $_[6];          # [in] source 1 ZMM register
  $SRC1[1] = $_[7];          # [in] source 1 ZMM register
  $SRC1[2] = $_[8];          # [in] source 1 ZMM register
  $SRC1[3] = $_[9];          # [in] source 1 ZMM register
  my @SRC2;
  $SRC2[0] = $_[10];         # [in] source 2 ZMM register
  $SRC2[1] = $_[11];         # [in] source 2 ZMM register
  $SRC2[2] = $_[12];         # [in] source 2 ZMM register
  $SRC2[3] = $_[13];         # [in] source 2 ZMM register

  die "ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16: num_blocks is out of bounds = $NUM_BLOCKS\n"
    if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $reg_idx     = 0;
  my $blocks_left = $NUM_BLOCKS;

  foreach (1 .. ($NUM_BLOCKS / 4)) {
    $code .= "$OPCODE        $SRC2[$reg_idx],$SRC1[$reg_idx],$DST[$reg_idx]\n";
    $reg_idx++;
    $blocks_left -= 4;
  }

  my $DSTREG  = $DST[$reg_idx];
  my $SRC1REG = $SRC1[$reg_idx];
  my $SRC2REG = $SRC2[$reg_idx];

  if ($blocks_left == 1) {
    $code .= "$OPCODE         @{[XWORD($SRC2REG)]},@{[XWORD($SRC1REG)]},@{[XWORD($DSTREG)]}\n";
  } elsif ($blocks_left == 2) {
    $code .= "$OPCODE         @{[YWORD($SRC2REG)]},@{[YWORD($SRC1REG)]},@{[YWORD($DSTREG)]}\n";
  } elsif ($blocks_left == 3) {
    $code .= "$OPCODE         $SRC2REG,$SRC1REG,$DSTREG\n";
  }
}

# ;; =============================================================================
# ;; Loads specified number of AES blocks into ZMM registers using mask register
# ;; for the last loaded register (xmm, ymm or zmm).
# ;; Loads take place at 1 byte granularity.
sub ZMM_LOAD_MASKED_BLOCKS_0_16 {
  my $NUM_BLOCKS  = $_[0];    # [in] numerical value, number of AES blocks (0 to 16)
  my $INP         = $_[1];    # [in] input data pointer to read from
  my $DATA_OFFSET = $_[2];    # [in] offset to the output pointer (GP or numerical)
  my @DST;
  $DST[0] = $_[3];            # [out] ZMM register with loaded data
  $DST[1] = $_[4];            # [out] ZMM register with loaded data
  $DST[2] = $_[5];            # [out] ZMM register with loaded data
  $DST[3] = $_[6];            # [out] ZMM register with loaded data
  my $MASK = $_[7];           # [in] mask register

  die "ZMM_LOAD_MASKED_BLOCKS_0_16: num_blocks is out of bounds = $NUM_BLOCKS\n"
    if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $src_offset  = 0;
  my $dst_idx     = 0;
  my $blocks_left = $NUM_BLOCKS;

  if ($NUM_BLOCKS > 0) {
    foreach (1 .. (int(($NUM_BLOCKS + 3) / 4) - 1)) {
      $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),$DST[$dst_idx]\n";
      $src_offset += 64;
      $dst_idx++;
      $blocks_left -= 4;
    }
  }

  my $DSTREG = $DST[$dst_idx];

  if ($blocks_left == 1) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),@{[XWORD($DSTREG)]}\{$MASK\}{z}\n";
  } elsif ($blocks_left == 2) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),@{[YWORD($DSTREG)]}\{$MASK\}{z}\n";
  } elsif (($blocks_left == 3 || $blocks_left == 4)) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),$DSTREG\{$MASK\}{z}\n";
  }
}

# ;; =============================================================================
# ;; Stores specified number of AES blocks from ZMM registers with mask register
# ;; for the last loaded register (xmm, ymm or zmm).
# ;; Stores take place at 1 byte granularity.
sub ZMM_STORE_MASKED_BLOCKS_0_16 {
  my $NUM_BLOCKS  = $_[0];    # [in] numerical value, number of AES blocks (0 to 16)
  my $OUTP        = $_[1];    # [in] output data pointer to write to
  my $DATA_OFFSET = $_[2];    # [in] offset to the output pointer (GP or numerical)
  my @SRC;
  $SRC[0] = $_[3];            # [in] ZMM register with data to store
  $SRC[1] = $_[4];            # [in] ZMM register with data to store
  $SRC[2] = $_[5];            # [in] ZMM register with data to store
  $SRC[3] = $_[6];            # [in] ZMM register with data to store
  my $MASK = $_[7];           # [in] mask register

  die "ZMM_STORE_MASKED_BLOCKS_0_16: num_blocks is out of bounds = $NUM_BLOCKS\n"
    if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $dst_offset  = 0;
  my $src_idx     = 0;
  my $blocks_left = $NUM_BLOCKS;

  if ($NUM_BLOCKS > 0) {
    foreach (1 .. (int(($NUM_BLOCKS + 3) / 4) - 1)) {
      $code .= "vmovdqu8          $SRC[$src_idx],`$dst_offset`($OUTP,$DATA_OFFSET,1)\n";
      $dst_offset += 64;
      $src_idx++;
      $blocks_left -= 4;
    }
  }

  my $SRCREG = $SRC[$src_idx];

  if ($blocks_left == 1) {
    $code .= "vmovdqu8          @{[XWORD($SRCREG)]},`$dst_offset`($OUTP,$DATA_OFFSET,1){$MASK}\n";
  } elsif ($blocks_left == 2) {
    $code .= "vmovdqu8          @{[YWORD($SRCREG)]},`$dst_offset`($OUTP,$DATA_OFFSET,1){$MASK}\n";
  } elsif ($blocks_left == 3 || $blocks_left == 4) {
    $code .= "vmovdqu8          $SRCREG,`$dst_offset`($OUTP,$DATA_OFFSET,1){$MASK}\n";
  }
}

# ;; =============================================================================
# ;; Loads specified number of AES blocks into ZMM registers
# ;; $FLAGS are optional and only affect behavior when 3 trailing blocks are left
# ;; - if $FlAGS not provided then exactly 3 blocks are loaded (move and insert)
# ;; - if "load_4_instead_of_3" option is passed then 4 blocks are loaded
sub ZMM_LOAD_BLOCKS_0_16 {
  my $NUM_BLOCKS  = $_[0];    # [in] numerical value, number of AES blocks (0 to 16)
  my $INP         = $_[1];    # [in] input data pointer to read from
  my $DATA_OFFSET = $_[2];    # [in] offset to the output pointer (GP or numerical)
  my @DST;
  $DST[0] = $_[3];            # [out] ZMM register with loaded data
  $DST[1] = $_[4];            # [out] ZMM register with loaded data
  $DST[2] = $_[5];            # [out] ZMM register with loaded data
  $DST[3] = $_[6];            # [out] ZMM register with loaded data
  my $FLAGS = $_[7];          # [in] optional "load_4_instead_of_3"

  die "ZMM_LOAD_BLOCKS_0_16: num_blocks is out of bounds = $NUM_BLOCKS\n" if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $src_offset = 0;
  my $dst_idx    = 0;

  foreach (1 .. int($NUM_BLOCKS / 4)) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),$DST[$dst_idx]\n";
    $src_offset += 64;
    $dst_idx++;
  }

  my $blocks_left = ($NUM_BLOCKS % 4);
  my $DSTREG      = $DST[$dst_idx];

  if ($blocks_left == 1) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),@{[XWORD($DSTREG)]}\n";
  } elsif ($blocks_left == 2) {
    $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),@{[YWORD($DSTREG)]}\n";
  } elsif ($blocks_left == 3) {
    if ($FLAGS eq "load_4_instead_of_3") {
      $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),$DSTREG\n";
    } else {
      $code .= "vmovdqu8          `$src_offset`($INP,$DATA_OFFSET,1),@{[YWORD($DSTREG)]}\n";
      $code .= "vinserti64x2      \$2,`$src_offset+32`($INP,$DATA_OFFSET,1),$DSTREG,$DSTREG\n";
    }
  }
}

# ;; =============================================================================
# ;; Stores specified number of AES blocks from ZMM registers
sub ZMM_STORE_BLOCKS_0_16 {
  my $NUM_BLOCKS  = $_[0];    # [in] numerical value, number of AES blocks (0 to 16)
  my $OUTP        = $_[1];    # [in] output data pointer to write to
  my $DATA_OFFSET = $_[2];    # [in] offset to the output pointer (GP or numerical)
  my @SRC;
  $SRC[0] = $_[3];            # [in] ZMM register with data to store
  $SRC[1] = $_[4];            # [in] ZMM register with data to store
  $SRC[2] = $_[5];            # [in] ZMM register with data to store
  $SRC[3] = $_[6];            # [in] ZMM register with data to store

  die "ZMM_STORE_BLOCKS_0_16: num_blocks is out of bounds = $NUM_BLOCKS\n" if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $dst_offset = 0;
  my $src_idx    = 0;

  foreach (1 .. int($NUM_BLOCKS / 4)) {
    $code .= "vmovdqu8          $SRC[$src_idx],`$dst_offset`($OUTP,$DATA_OFFSET,1)\n";
    $dst_offset += 64;
    $src_idx++;
  }

  my $blocks_left = ($NUM_BLOCKS % 4);
  my $SRCREG      = $SRC[$src_idx];

  if ($blocks_left == 1) {
    $code .= "vmovdqu8          @{[XWORD($SRCREG)]},`$dst_offset`($OUTP,$DATA_OFFSET,1)\n";
  } elsif ($blocks_left == 2) {
    $code .= "vmovdqu8          @{[YWORD($SRCREG)]},`$dst_offset`($OUTP,$DATA_OFFSET,1)\n";
  } elsif ($blocks_left == 3) {
    $code .= "vmovdqu8          @{[YWORD($SRCREG)]},`$dst_offset`($OUTP,$DATA_OFFSET,1)\n";
    $code .= "vextracti32x4     \$2,$SRCREG,`$dst_offset + 32`($OUTP,$DATA_OFFSET,1)\n";
  }
}

# ;;; ===========================================================================
# ;;; Handles AES encryption rounds
# ;;; It handles special cases: the last and first rounds
# ;;; Optionally, it performs XOR with data after the last AES round.
# ;;; Uses NROUNDS parameterto check what needs to be done for the current round.
# ;;; If 3 blocks are trailing then operation on whole ZMM is performed (4 blocks).
sub ZMM_AESENC_ROUND_BLOCKS_0_16 {
  my $L0B0_3   = $_[0];     # [in/out] zmm; blocks 0 to 3
  my $L0B4_7   = $_[1];     # [in/out] zmm; blocks 4 to 7
  my $L0B8_11  = $_[2];     # [in/out] zmm; blocks 8 to 11
  my $L0B12_15 = $_[3];     # [in/out] zmm; blocks 12 to 15
  my $KEY      = $_[4];     # [in] zmm containing round key
  my $ROUND    = $_[5];     # [in] round number
  my $D0_3     = $_[6];     # [in] zmm or no_data; plain/cipher text blocks 0-3
  my $D4_7     = $_[7];     # [in] zmm or no_data; plain/cipher text blocks 4-7
  my $D8_11    = $_[8];     # [in] zmm or no_data; plain/cipher text blocks 8-11
  my $D12_15   = $_[9];     # [in] zmm or no_data; plain/cipher text blocks 12-15
  my $NUMBL    = $_[10];    # [in] number of blocks; numerical value
  my $NROUNDS  = $_[11];    # [in] number of rounds; numerical value

  # ;;; === first AES round
  if ($ROUND < 1) {

    # ;;  round 0
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
      $NUMBL,  "vpxorq", $L0B0_3,   $L0B4_7, $L0B8_11, $L0B12_15, $L0B0_3,
      $L0B4_7, $L0B8_11, $L0B12_15, $KEY,    $KEY,     $KEY,      $KEY);
  }

  # ;;; === middle AES rounds
  if ($ROUND >= 1 && $ROUND <= $NROUNDS) {

    # ;; rounds 1 to 9/11/13
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
      $NUMBL,  "vaesenc", $L0B0_3,   $L0B4_7, $L0B8_11, $L0B12_15, $L0B0_3,
      $L0B4_7, $L0B8_11,  $L0B12_15, $KEY,    $KEY,     $KEY,      $KEY);
  }

  # ;;; === last AES round
  if ($ROUND > $NROUNDS) {

    # ;; the last round - mix enclast with text xor's
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
      $NUMBL,  "vaesenclast", $L0B0_3,   $L0B4_7, $L0B8_11, $L0B12_15, $L0B0_3,
      $L0B4_7, $L0B8_11,      $L0B12_15, $KEY,    $KEY,     $KEY,      $KEY);

    # ;;; === XOR with data
    if ( ($D0_3 ne "no_data")
      && ($D4_7 ne "no_data")
      && ($D8_11 ne "no_data")
      && ($D12_15 ne "no_data"))
    {
      &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
        $NUMBL,  "vpxorq", $L0B0_3,   $L0B4_7, $L0B8_11, $L0B12_15, $L0B0_3,
        $L0B4_7, $L0B8_11, $L0B12_15, $D0_3,   $D4_7,    $D8_11,    $D12_15);
    }
  }
}

# ;;; Horizontal XOR - 4 x 128bits xored together
sub VHPXORI4x128 {
  my $REG = $_[0];    # [in/out] ZMM with 4x128bits to xor; 128bit output
  my $TMP = $_[1];    # [clobbered] ZMM temporary register
  $code .= <<___;
        vextracti64x4     \$1,$REG,@{[YWORD($TMP)]}
        vpxorq            @{[YWORD($TMP)]},@{[YWORD($REG)]},@{[YWORD($REG)]}
        vextracti32x4     \$1,@{[YWORD($REG)]},@{[XWORD($TMP)]}
        vpxorq            @{[XWORD($TMP)]},@{[XWORD($REG)]},@{[XWORD($REG)]}
___
}

# ;;; Horizontal XOR - 2 x 128bits xored together
sub VHPXORI2x128 {
  my $REG = $_[0];    # [in/out] YMM/ZMM with 2x128bits to xor; 128bit output
  my $TMP = $_[1];    # [clobbered] XMM/YMM/ZMM temporary register
  $code .= <<___;
        vextracti32x4     \$1,$REG,@{[XWORD($TMP)]}
        vpxorq            @{[XWORD($TMP)]},@{[XWORD($REG)]},@{[XWORD($REG)]}
___
}

# ;;; schoolbook multiply - 1st step
sub VCLMUL_STEP1 {
  my $GCM128_CTX = $_[0];    # [in] context pointer
  my $HI         = $_[1];    # [in] previous blocks 4 to 7
  my $TMP        = $_[2];    # [clobbered] ZMM/YMM/XMM temporary
  my $TH         = $_[3];    # [out] high product
  my $TM         = $_[4];    # [out] medium product
  my $TL         = $_[5];    # [out] low product
  my $HKEY       = $_[6];    # [in/optional] hash key for multiplication

  if (scalar(@_) == 6) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(4,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP\n";
  } else {
    $code .= "vmovdqa64         $HKEY,$TMP\n";
  }
  $code .= <<___;
        vpclmulqdq        \$0x11,$TMP,$HI,$TH  # ; T5 = a1*b1
        vpclmulqdq        \$0x00,$TMP,$HI,$TL  # ; T7 = a0*b0
        vpclmulqdq        \$0x01,$TMP,$HI,$TM  # ; T6 = a1*b0
        vpclmulqdq        \$0x10,$TMP,$HI,$TMP # ; T4 = a0*b1
        vpxorq            $TMP,$TM,$TM         # ; [TH : TM : TL]
___
}

# ;;; schoolbook multiply - 2nd step
sub VCLMUL_STEP2 {
  my $GCM128_CTX = $_[0];     # [in] key pointer
  my $HI         = $_[1];     # [out] ghash high 128 bits
  my $LO         = $_[2];     # [in/out] cipher text blocks 0-3 (in); ghash low 128 bits (out)
  my $TMP0       = $_[3];     # [clobbered] ZMM/YMM/XMM temporary
  my $TMP1       = $_[4];     # [clobbered] ZMM/YMM/XMM temporary
  my $TMP2       = $_[5];     # [clobbered] ZMM/YMM/XMM temporary
  my $TH         = $_[6];     # [in] high product
  my $TM         = $_[7];     # [in] medium product
  my $TL         = $_[8];     # [in] low product
  my $HKEY       = $_[9];     # [in/optional] hash key for multiplication
  my $HXOR       = $_[10];    # [in/optional] type of horizontal xor (4 - 4x128; 2 - 2x128; 1 - none)

  if (scalar(@_) == 9) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(8,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP0\n";
  } else {
    $code .= "vmovdqa64         $HKEY,$TMP0\n";
  }
  $code .= <<___;
        vpclmulqdq        \$0x10,$TMP0,$LO,$TMP1    #  ; $TMP1 = a0*b1
        vpclmulqdq        \$0x11,$TMP0,$LO,$TMP2    #  ; $TMP2 = a1*b1
        vpxorq            $TMP2,$TH,$TH
        vpclmulqdq        \$0x00,$TMP0,$LO,$TMP2    #  ; $TMP2 = a0*b0
        vpxorq            $TMP2,$TL,$TL
        vpclmulqdq        \$0x01,$TMP0,$LO,$TMP0    #  ; $TMP0 = a1*b0
        vpternlogq        \$0x96,$TMP0,$TMP1,$TM    #  ; $TM = TM xor TMP1 xor TMP0
        # ;; finish multiplications
        vpsrldq           \$8,$TM,$TMP2
        vpxorq            $TMP2,$TH,$HI
        vpslldq           \$8,$TM,$TMP2
        vpxorq            $TMP2,$TL,$LO
___

  # ;; xor 128bit words horizontally and compute [(X8*H1) + (X7*H2) + ... ((X1+Y0)*H8]
  # ;; note: (X1+Y0) handled elsewhere
  if (scalar(@_) < 11) {
    &VHPXORI4x128($HI, $TMP2);
    &VHPXORI4x128($LO, $TMP1);
  } else {
    if ($HXOR == 4) {
      &VHPXORI4x128($HI, $TMP2);
      &VHPXORI4x128($LO, $TMP1);
    } elsif ($HXOR == 2) {
      &VHPXORI2x128($HI, $TMP2);
      &VHPXORI2x128($LO, $TMP1);
    }

    # ;; for HXOR == 1 there is nothing to be done
  }

  # ;; HIx holds top 128 bits
  # ;; LOx holds low 128 bits
  # ;; - further reductions to follow
}

# ;;; AVX512 reduction macro
sub VCLMUL_REDUCE {
  my $OUT   = $_[0];    # [out] zmm/ymm/xmm: result (must not be $TMP1 or $HI128)
  my $POLY  = $_[1];    # [in] zmm/ymm/xmm: polynomial
  my $HI128 = $_[2];    # [in] zmm/ymm/xmm: high 128b of hash to reduce
  my $LO128 = $_[3];    # [in] zmm/ymm/xmm: low 128b of hash to reduce
  my $TMP0  = $_[4];    # [in] zmm/ymm/xmm: temporary register
  my $TMP1  = $_[5];    # [in] zmm/ymm/xmm: temporary register

  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; first phase of the reduction
        vpclmulqdq        \$0x01,$LO128,$POLY,$TMP0
        vpslldq           \$8,$TMP0,$TMP0         # ; shift-L 2 DWs
        vpxorq            $TMP0,$LO128,$TMP0      # ; first phase of the reduction complete
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; second phase of the reduction
        vpclmulqdq        \$0x00,$TMP0,$POLY,$TMP1
        vpsrldq           \$4,$TMP1,$TMP1          # ; shift-R only 1-DW to obtain 2-DWs shift-R
        vpclmulqdq        \$0x10,$TMP0,$POLY,$OUT
        vpslldq           \$4,$OUT,$OUT            # ; shift-L 1-DW to obtain result with no shifts
        vpternlogq        \$0x96,$HI128,$TMP1,$OUT # ; OUT/GHASH = OUT xor TMP1 xor HI128
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
___
}

# ;;; schoolbook multiply (1 to 8 blocks) - 1st step
sub VCLMUL_1_TO_8_STEP1 {
  my $GCM128_CTX = $_[0];    # [in] context pointer
  my $HI         = $_[1];    # [in] ZMM ciphered blocks 4 to 7
  my $TMP1       = $_[2];    # [clobbered] ZMM temporary
  my $TMP2       = $_[3];    # [clobbered] ZMM temporary
  my $TH         = $_[4];    # [out] ZMM high product
  my $TM         = $_[5];    # [out] ZMM medium product
  my $TL         = $_[6];    # [out] ZMM low product
  my $NBLOCKS    = $_[7];    # [in] number of blocks to ghash (0 to 8)

  if ($NBLOCKS == 8) {
    &VCLMUL_STEP1($GCM128_CTX, $HI, $TMP1, $TH, $TM, $TL);
  } elsif ($NBLOCKS == 7) {
    $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx(3,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2
        vmovdqa64         mask_out_top_block(%rip),$TMP1
        vpandq            $TMP1,$TMP2,$TMP2
        vpandq            $TMP1,$HI,$HI
___
    &VCLMUL_STEP1(NULL, $HI, $TMP1, $TH, $TM, $TL, $TMP2);
  } elsif ($NBLOCKS == 6) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(2,$GCM128_CTX,$CTX_OFFSET_HTable)]},@{[YWORD($TMP2)]}\n";
    &VCLMUL_STEP1(NULL, &YWORD($HI), &YWORD($TMP1), &YWORD($TH), &YWORD($TM), &YWORD($TL), &YWORD($TMP2));
  } elsif ($NBLOCKS == 5) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(1,$GCM128_CTX,$CTX_OFFSET_HTable)]},@{[&XWORD($TMP2)]}\n";
    &VCLMUL_STEP1(NULL, &XWORD($HI), &XWORD($TMP1), &XWORD($TH), &XWORD($TM), &XWORD($TL), &XWORD($TMP2));
  } else {
    $code .= <<___;
        vpxorq            $TH,$TH,$TH
        vpxorq            $TM,$TM,$TM
        vpxorq            $TL,$TL,$TL
___
  }
}

# ;;; schoolbook multiply (1 to 8 blocks) - 2nd step
sub VCLMUL_1_TO_8_STEP2 {
  my $GCM128_CTX = $_[0];    # [in] key pointer
  my $HI         = $_[1];    # [out] ZMM ghash high 128bits
  my $LO         = $_[2];    # [in/out] ZMM ciphered blocks 0 to 3 (in); ghash low 128bits (out)
  my $TMP0       = $_[3];    # [clobbered] ZMM temporary
  my $TMP1       = $_[4];    # [clobbered] ZMM temporary
  my $TMP2       = $_[5];    # [clobbered] ZMM temporary
  my $TH         = $_[6];    # [in/clobbered] ZMM high sum
  my $TM         = $_[7];    # [in/clobbered] ZMM medium sum
  my $TL         = $_[8];    # [in/clobbered] ZMM low sum
  my $NBLOCKS    = $_[9];    # [in] number of blocks to ghash (0 to 8)

  if ($NBLOCKS == 8) {
    &VCLMUL_STEP2($GCM128_CTX, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL);
  } elsif ($NBLOCKS == 7) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(7,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2\n";
    &VCLMUL_STEP2(NULL, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL, $TMP2, 4);
  } elsif ($NBLOCKS == 6) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(6,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2\n";
    &VCLMUL_STEP2(NULL, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL, $TMP2, 4);
  } elsif ($NBLOCKS == 5) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(5,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2\n";
    &VCLMUL_STEP2(NULL, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL, $TMP2, 4);
  } elsif ($NBLOCKS == 4) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(4,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2\n";
    &VCLMUL_STEP2(NULL, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL, $TMP2, 4);
  } elsif ($NBLOCKS == 3) {
    $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx(3,$GCM128_CTX,$CTX_OFFSET_HTable)]},$TMP2
        vmovdqa64         mask_out_top_block(%rip),$TMP1
        vpandq            $TMP1,$TMP2,$TMP2
        vpandq            $TMP1,$LO,$LO
___
    &VCLMUL_STEP2(NULL, $HI, $LO, $TMP0, $TMP1, $TMP2, $TH, $TM, $TL, $TMP2, 4);
  } elsif ($NBLOCKS == 2) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(2,$GCM128_CTX,$CTX_OFFSET_HTable)]},@{[YWORD($TMP2)]}\n";
    &VCLMUL_STEP2(NULL, &YWORD($HI), &YWORD($LO), &YWORD($TMP0), &YWORD($TMP1), &YWORD($TMP2),
      &YWORD($TH), &YWORD($TM), &YWORD($TL), &YWORD($TMP2), 2);
  } elsif ($NBLOCKS == 1) {
    $code .= "vmovdqu64         @{[HashKeyByIdx(1,$GCM128_CTX,$CTX_OFFSET_HTable)]},@{[XWORD($TMP2)]}\n";
    &VCLMUL_STEP2(NULL, &XWORD($HI), &XWORD($LO), &XWORD($TMP0), &XWORD($TMP1), &XWORD($TMP2),
      &XWORD($TH), &XWORD($TM), &XWORD($TL), &XWORD($TMP2), 1);
  } else {
    $code .= <<___;
        vpxorq            $HI,$HI,$HI
        vpxorq            $LO,$LO,$LO
___
  }
}

# ;;; GHASH 1 to 16 blocks of cipher text
# ;;; - performs reduction at the end
sub GHASH_1_TO_16 {
  my $HTABLE      = $_[0];     # [in] pointer to hkeys table
  my $GHASH       = $_[1];     # [out] ghash output
  my $T1          = $_[2];     # [clobbered] temporary ZMM
  my $T2          = $_[3];     # [clobbered] temporary ZMM
  my $T3          = $_[4];     # [clobbered] temporary ZMM
  my $T4          = $_[5];     # [clobbered] temporary ZMM
  my $T5          = $_[6];     # [clobbered] temporary ZMM
  my $T6          = $_[7];     # [clobbered] temporary ZMM
  my $T7          = $_[8];     # [clobbered] temporary ZMM
  my $T8          = $_[9];     # [clobbered] temporary ZMM
  my $T9          = $_[10];    # [clobbered] temporary ZMM
  my $AAD_HASH_IN = $_[11];    # [in] input hash value
  my @CIPHER_IN;
  $CIPHER_IN[0] = $_[12];      # [in] ZMM with cipher text blocks 0-3
  $CIPHER_IN[1] = $_[13];      # [in] ZMM with cipher text blocks 4-7
  $CIPHER_IN[2] = $_[14];      # [in] ZMM with cipher text blocks 8-11
  $CIPHER_IN[3] = $_[15];      # [in] ZMM with cipher text blocks 12-15
  my $NUM_BLOCKS    = $_[16];  # [in] numerical value, number of blocks
  my $INSTANCE_TYPE = $_[17];  # [in] multi_call or single_call
  my $ROUND         = $_[18];  # [in] Round number (for multi_call): "first", "mid", "last"
  my $HKEY_START    = $_[19];  # [in] Hash subkey to start from (for multi_call): 48, 32, 16
  my $PREV_H        = $_[20];  # [in/out] In: High result from previous call, Out: High result of this call
  my $PREV_L        = $_[21];  # [in/out] In: Low result from previous call, Out: Low result of this call
  my $PREV_M1       = $_[22];  # [in/out] In: Medium 1 result from previous call, Out: Medium 1 result of this call
  my $PREV_M2       = $_[23];  # [in/out] In: Medium 2 result from previous call, Out: Medium 2 result of this call

  die "GHASH_1_TO_16: num_blocks is out of bounds = $NUM_BLOCKS\n" if ($NUM_BLOCKS > 16 || $NUM_BLOCKS < 0);

  my $T0H  = $T1;
  my $T0L  = $T2;
  my $T0M1 = $T3;
  my $T0M2 = $T4;

  my $T1H  = $T5;
  my $T1L  = $T6;
  my $T1M1 = $T7;
  my $T1M2 = $T8;

  my $HK = $T9;

  my $hashk_base = $INSTANCE_TYPE eq "single_call" ? "$HTABLE" : "%rsp";

  my $reg_idx      = 0;
  my $blocks_left  = $NUM_BLOCKS;
  my $first_result = -1;
  my $reduce       = -1;
  my $hashk;

  if ($INSTANCE_TYPE eq "single_call") {
    $hashk        = $NUM_BLOCKS;
    $first_result = 1;
    $reduce       = 1;
    $code .= "vpxorq            $AAD_HASH_IN,$CIPHER_IN[0],$CIPHER_IN[0]\n";
  } else {    # ; $INSTANCE_TYPE == multi_call
    $hashk = $HKEY_START;
    if ($ROUND eq "first") {
      $first_result = 1;
      $reduce       = 0;
      $code .= "vpxorq            $AAD_HASH_IN,$CIPHER_IN[0],$CIPHER_IN[0]\n";
    } elsif ($ROUND eq "mid") {
      $first_result = 0;
      $reduce       = 0;
      $code .= <<___;
        vmovdqa64         $PREV_H,$T0H
        vmovdqa64         $PREV_L,$T0L
        vmovdqa64         $PREV_M1,$T0M1
        vmovdqa64         $PREV_M2,$T0M2
___
    } else {    # ; $ROUND == last
      $first_result = 0;
      $reduce       = 1;
      $code .= <<___;
        vmovdqa64         $PREV_H,$T0H
        vmovdqa64         $PREV_L,$T0L
        vmovdqa64         $PREV_M1,$T0M1
        vmovdqa64         $PREV_M2,$T0M2
___
    }
  }

  my $REG_IN;
  foreach (1 .. int($blocks_left / 4)) {
    $REG_IN = $CIPHER_IN[$reg_idx];
    $code .= "vmovdqu64         @{[HashKeyByIdx($hashk,$hashk_base)]},$HK\n";
    if ($first_result == 1) {
      $code .= <<___;
        vpclmulqdq        \$0x11,$HK,$REG_IN,$T0H  # ; H = a1*b1
        vpclmulqdq        \$0x00,$HK,$REG_IN,$T0L  # ; L = a0*b0
        vpclmulqdq        \$0x01,$HK,$REG_IN,$T0M1 # ; M1 = a1*b0
        vpclmulqdq        \$0x10,$HK,$REG_IN,$T0M2 # ; TM2 = a0*b1
___
      $first_result = 0;
    } else {
      $code .= <<___;
        vpclmulqdq        \$0x11,$HK,$REG_IN,$T1H  # ; H = a1*b1
        vpclmulqdq        \$0x00,$HK,$REG_IN,$T1L  # ; L = a0*b0
        vpclmulqdq        \$0x01,$HK,$REG_IN,$T1M1 # ; M1 = a1*b0
        vpclmulqdq        \$0x10,$HK,$REG_IN,$T1M2 # ; M2 = a0*b1
        vpxorq            $T1H,$T0H,$T0H
        vpxorq            $T1L,$T0L,$T0L
        vpxorq            $T1M1,$T0M1,$T0M1
        vpxorq            $T1M2,$T0M2,$T0M2
___
    }
    $reg_idx++;
    $hashk       -= 4;
    $blocks_left -= 4;
  }

  if ($blocks_left > 0) {

    # ;; There are 1, 2 or 3 blocks left to process.
    # ;; It may also be that they are the only blocks to process.

    $REG_IN = $CIPHER_IN[$reg_idx];

    # ;; (first_result == 1) is the case where NUM_BLOCKS = 1, 2 or 3
    my $OUT_H  = ($first_result == 1) ? $T0H  : $T1H;
    my $OUT_L  = ($first_result == 1) ? $T0L  : $T1L;
    my $OUT_M1 = ($first_result == 1) ? $T0M1 : $T1M1;
    my $OUT_M2 = ($first_result == 1) ? $T0M2 : $T1M2;

    if ($blocks_left == 1) {
      $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx($hashk,$hashk_base)]},@{[XWORD($HK)]}
        vpclmulqdq        \$0x11,@{[XWORD($HK)]},@{[XWORD($REG_IN)]},@{[XWORD($OUT_H)]}  # ; $TH = a1*b1
        vpclmulqdq        \$0x00,@{[XWORD($HK)]},@{[XWORD($REG_IN)]},@{[XWORD($OUT_L)]}  # ; $TL = a0*b0
        vpclmulqdq        \$0x01,@{[XWORD($HK)]},@{[XWORD($REG_IN)]},@{[XWORD($OUT_M1)]} # ; $TM1 = a1*b0
        vpclmulqdq        \$0x10,@{[XWORD($HK)]},@{[XWORD($REG_IN)]},@{[XWORD($OUT_M2)]} # ; $TM2 = a0*b1
___
    } elsif ($blocks_left == 2) {
      $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx($hashk,$hashk_base)]},@{[YWORD($HK)]}
        vpclmulqdq        \$0x11,@{[YWORD($HK)]},@{[YWORD($REG_IN)]},@{[YWORD($OUT_H)]}  # ; $TH = a1*b1
        vpclmulqdq        \$0x00,@{[YWORD($HK)]},@{[YWORD($REG_IN)]},@{[YWORD($OUT_L)]}  # ; $TL = a0*b0
        vpclmulqdq        \$0x01,@{[YWORD($HK)]},@{[YWORD($REG_IN)]},@{[YWORD($OUT_M1)]} # ; $TM1 = a1*b0
        vpclmulqdq        \$0x10,@{[YWORD($HK)]},@{[YWORD($REG_IN)]},@{[YWORD($OUT_M2)]} # ; $TM2 = a0*b1
___
    } else {    # ; blocks_left == 3
      $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx($hashk,$hashk_base)]},@{[YWORD($HK)]}
        vinserti64x2      \$2,@{[HashKeyByIdx($hashk-2,$hashk_base)]},$HK,$HK
        vpclmulqdq        \$0x11,$HK,$REG_IN,$OUT_H      # ; $TH = a1*b1
        vpclmulqdq        \$0x00,$HK,$REG_IN,$OUT_L      # ; $TL = a0*b0
        vpclmulqdq        \$0x01,$HK,$REG_IN,$OUT_M1     # ; $TM1 = a1*b0
        vpclmulqdq        \$0x10,$HK,$REG_IN,$OUT_M2     # ; $TM2 = a0*b1
___
    }

    if ($first_result != 1) {
      $code .= <<___;
        vpxorq            $T1H,$T0H,$T0H
        vpxorq            $T1L,$T0L,$T0L
        vpxorq            $T1M1,$T0M1,$T0M1
        vpxorq            $T1M2,$T0M2,$T0M2
___
    }
  }

  if ($reduce == 1) {
    $code .= <<___;
        # ;; integrate TM into TH and TL
        vpxorq            $T0M2,$T0M1,$T0M1
        vpsrldq           \$8,$T0M1,$T1M1
        vpslldq           \$8,$T0M1,$T1M2
        vpxorq            $T1M1,$T0H,$T0H
        vpxorq            $T1M2,$T0L,$T0L
___

    # ;; add TH and TL 128-bit words horizontally
    &VHPXORI4x128($T0H, $T1M1);
    &VHPXORI4x128($T0L, $T1M2);
    $code .= <<___;
        # ;; reduction
        vmovdqa64         POLY2(%rip),@{[XWORD($HK)]}
___
    &VCLMUL_REDUCE(&XWORD($GHASH), &XWORD($HK), &XWORD($T0H), &XWORD($T0L), &XWORD($T0M1), &XWORD($T0M2));
  } else {    # ;; reduce == 0
    $code .= <<___;
        vmovdqa64         $T0H,$PREV_H
        vmovdqa64         $T0L,$PREV_L
        vmovdqa64         $T0M1,$PREV_M1
        vmovdqa64         $T0M2,$PREV_M2
___
  }
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; GHASH_MUL MACRO to implement: Data*HashKey mod (128,127,126,121,0)
# ;;; Input: A and B (128-bits each, bit-reflected)
# ;;; Output: C = A*B*x mod poly, (i.e. >>1 )
# ;;; To compute GH = GH*HashKey mod poly, give HK = HashKey<<1 mod poly as input
# ;;; GH = GH * HK * x mod poly which is equivalent to GH*HashKey mod poly.
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub GHASH_MUL {
  my $GH = $_[0];    #; [in/out] xmm/ymm/zmm with multiply operand(s) (128-bits)
  my $HK = $_[1];    #; [in] xmm/ymm/zmm with hash key value(s) (128-bits)
  my $T1 = $_[2];    #; [clobbered] xmm/ymm/zmm
  my $T2 = $_[3];    #; [clobbered] xmm/ymm/zmm
  my $T3 = $_[4];    #; [clobbered] xmm/ymm/zmm
  my $T4 = $_[5];    #; [clobbered] xmm/ymm/zmm
  my $T5 = $_[6];    #; [clobbered] xmm/ymm/zmm

  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vpclmulqdq        \$0x11,$HK,$GH,$T1 # ; $T1 = a1*b1
        vpclmulqdq        \$0x00,$HK,$GH,$T2 # ; $T2 = a0*b0
        vpclmulqdq        \$0x01,$HK,$GH,$T3 # ; $T3 = a1*b0
        vpclmulqdq        \$0x10,$HK,$GH,$GH # ; $GH = a0*b1
        vpxorq            $T3,$GH,$GH

        vpsrldq           \$8,$GH,$T3        # ; shift-R $GH 2 DWs
        vpslldq           \$8,$GH,$GH        # ; shift-L $GH 2 DWs
        vpxorq            $T3,$T1,$T1
        vpxorq            $T2,$GH,$GH

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;first phase of the reduction
        vmovdqu64         POLY2(%rip),$T3

        vpclmulqdq        \$0x01,$GH,$T3,$T2
        vpslldq           \$8,$T2,$T2        # ; shift-L $T2 2 DWs
        vpxorq            $T2,$GH,$GH        # ; first phase of the reduction complete

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;second phase of the reduction
        vpclmulqdq        \$0x00,$GH,$T3,$T2
        vpsrldq           \$4,$T2,$T2        # ; shift-R only 1-DW to obtain 2-DWs shift-R
        vpclmulqdq        \$0x10,$GH,$T3,$GH
        vpslldq           \$4,$GH,$GH        # ; Shift-L 1-DW to obtain result with no shifts
                                             # ; second phase of the reduction complete, the result is in $GH
        vpternlogq        \$0x96,$T2,$T1,$GH # ; GH = GH xor T1 xor T2
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
___
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; PRECOMPUTE computes HashKey_i
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub PRECOMPUTE {
  my $HTABLE = $_[0];    #; [in/out] hkeys table
  my $HK     = $_[1];    #; [in] xmm, hash key
  my $T1     = $_[2];    #; [clobbered] xmm
  my $T2     = $_[3];    #; [clobbered] xmm
  my $T3     = $_[4];    #; [clobbered] xmm
  my $T4     = $_[5];    #; [clobbered] xmm
  my $T5     = $_[6];    #; [clobbered] xmm
  my $T6     = $_[7];    #; [clobbered] xmm
  my $T7     = $_[8];    #; [clobbered] xmm
  my $T8     = $_[9];    #; [clobbered] xmm

  my $ZT1 = &ZWORD($T1);
  my $ZT2 = &ZWORD($T2);
  my $ZT3 = &ZWORD($T3);
  my $ZT4 = &ZWORD($T4);
  my $ZT5 = &ZWORD($T5);
  my $ZT6 = &ZWORD($T6);
  my $ZT7 = &ZWORD($T7);
  my $ZT8 = &ZWORD($T8);

  $code .= <<___;
        vmovdqa64         $HK,$T5
        vinserti64x2      \$3,$HK,$ZT7,$ZT7

        # ;; calculate HashKey^2<<1 mod poly
___
  &GHASH_MUL($T5, $HK, $T1, $T3, $T4, $T6, $T2);
  $code .= <<___;
        vmovdqu64         $T5,@{[HashKeyByIdx(2,$HTABLE)]}
        vinserti64x2      \$2,$T5,$ZT7,$ZT7

        # ;; calculate HashKey^3<<1 mod poly
___
  &GHASH_MUL($T5, $HK, $T1, $T3, $T4, $T6, $T2);
  $code .= <<___;
        vmovdqu64         $T5,@{[HashKeyByIdx(3,$HTABLE)]}
        vinserti64x2      \$1,$T5,$ZT7,$ZT7

        # ;; calculate HashKey^4<<1 mod poly
___
  &GHASH_MUL($T5, $HK, $T1, $T3, $T4, $T6, $T2);
  $code .= <<___;
        vmovdqu64         $T5,@{[HashKeyByIdx(4,$HTABLE)]}
        vinserti64x2      \$0,$T5,$ZT7,$ZT7

        # ;; switch to 4x128-bit computations now
        vshufi64x2        \$0x00,$ZT5,$ZT5,$ZT5 # ;; broadcast HashKey^4 across all ZT5
        vmovdqa64         $ZT7,$ZT8             # ;; save HashKey^4 to HashKey^1 in ZT8
        # ;; calculate HashKey^5<<1 mod poly, HashKey^6<<1 mod poly, ... HashKey^8<<1 mod poly
___
  &GHASH_MUL($ZT7, $ZT5, $ZT1, $ZT3, $ZT4, $ZT6, $ZT2);
  $code .= <<___;
        vmovdqu64         $ZT7,@{[HashKeyByIdx(8,$HTABLE)]} # ;; HashKey^8 to HashKey^5 in ZT7 now
        vshufi64x2        \$0x00,$ZT7,$ZT7,$ZT5                   # ;; broadcast HashKey^8 across all ZT5
___

  # ;; calculate HashKey^9<<1 mod poly, HashKey^10<<1 mod poly, ... HashKey^48<<1 mod poly
  # ;; use HashKey^8 as multiplier against ZT8 and ZT7 - this allows deeper ooo execution

  # ;; compute HashKey^(12), HashKey^(11), ... HashKey^(9)
  &GHASH_MUL($ZT8, $ZT5, $ZT1, $ZT3, $ZT4, $ZT6, $ZT2);
  $code .= "vmovdqu64         $ZT8,@{[HashKeyByIdx(12,$HTABLE)]}\n";

  # ;; compute HashKey^(16), HashKey^(15), ... HashKey^(13)
  &GHASH_MUL($ZT7, $ZT5, $ZT1, $ZT3, $ZT4, $ZT6, $ZT2);
  $code .= "vmovdqu64         $ZT7,@{[HashKeyByIdx(16,$HTABLE)]}\n";

  # ; Hkeys 17..48 will be precomputed somewhere else as context can hold only 16 hkeys
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; READ_SMALL_DATA_INPUT
# ;;; Packs xmm register with data when data input is less or equal to 16 bytes
# ;;; Returns 0 if data has length 0
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub READ_SMALL_DATA_INPUT {
  my $OUTPUT = $_[0];    # [out] xmm register
  my $INPUT  = $_[1];    # [in] buffer pointer to read from
  my $LENGTH = $_[2];    # [in] number of bytes to read
  my $TMP1   = $_[3];    # [clobbered]
  my $MASK   = $_[4];    # [out] k1 to k7 register to store the partial block mask

  my $rndsuffix = &random_string();

  $code .= <<___;
        cmpq              \$16,$LENGTH
        jge             .L_read_small_data_ge16_${rndsuffix}
        lea               byte_len_to_mask_table(%rip),$TMP1
___
  if ($win64) {
    $code .= <<___;
        add               $LENGTH,$TMP1
        add               $LENGTH,$TMP1
        kmovw             ($TMP1),$MASK
___
  } else {
    $code .= <<___;
        kmovw             ($TMP1,$LENGTH,2),$MASK
___
  }
  $code .= <<___;
        vmovdqu8          ($INPUT),${OUTPUT}{$MASK}{z}
        jmp             .L_read_small_data_end_${rndsuffix}
.L_read_small_data_ge16_${rndsuffix}:
        vmovdqu8          ($INPUT),$OUTPUT
        mov               \$0xffff,$TMP1
        kmovq             $TMP1,$MASK
.L_read_small_data_end_${rndsuffix}:
___
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; CALC_AAD_HASH: Calculates the hash of the data which will not be encrypted.
# ; Input: The input data (A_IN), that data's length (A_LEN), and the hash key (HASH_KEY).
# ; Output: The hash of the data (AAD_HASH).
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub CALC_AAD_HASH {
  my $A_IN     = $_[0];     # [in] AAD text pointer
  my $A_LEN    = $_[1];     # [in] AAD length
  my $AAD_HASH = $_[2];     # [in/out] xmm ghash value
  my $HTABLE   = $_[3];     # [in] pointer to hkeys table
  my $ZT0      = $_[4];     # [clobbered] ZMM register
  my $ZT1      = $_[5];     # [clobbered] ZMM register
  my $ZT2      = $_[6];     # [clobbered] ZMM register
  my $ZT3      = $_[7];     # [clobbered] ZMM register
  my $ZT4      = $_[8];     # [clobbered] ZMM register
  my $ZT5      = $_[9];     # [clobbered] ZMM register
  my $ZT6      = $_[10];    # [clobbered] ZMM register
  my $ZT7      = $_[11];    # [clobbered] ZMM register
  my $ZT8      = $_[12];    # [clobbered] ZMM register
  my $ZT9      = $_[13];    # [clobbered] ZMM register
  my $ZT10     = $_[14];    # [clobbered] ZMM register
  my $ZT11     = $_[15];    # [clobbered] ZMM register
  my $ZT12     = $_[16];    # [clobbered] ZMM register
  my $ZT13     = $_[17];    # [clobbered] ZMM register
  my $ZT14     = $_[18];    # [clobbered] ZMM register
  my $ZT15     = $_[19];    # [clobbered] ZMM register
  my $ZT16     = $_[20];    # [clobbered] ZMM register
  my $ZT17     = $_[21];    # [clobbered] ZMM register
  my $T1       = $_[22];    # [clobbered] GP register
  my $T2       = $_[23];    # [clobbered] GP register
  my $T3       = $_[24];    # [clobbered] GP register
  my $MASKREG  = $_[25];    # [clobbered] mask register

  my $HKEYS_READY = "%rbx";

  my $SHFMSK = $ZT13;

  my $rndsuffix = &random_string();

  $code .= <<___;
        mov              $A_IN,$T1      # ; T1 = AAD
        mov              $A_LEN,$T2     # ; T2 = aadLen
        or               $T2, $T2
        jz              .L_CALC_AAD_done_${rndsuffix}

        xor              $HKEYS_READY,$HKEYS_READY
        vmovdqa64        SHUF_MASK(%rip),$SHFMSK

.L_get_AAD_loop48x16_${rndsuffix}:
        cmp               \$`(48*16)`,$T2
jl              .L_exit_AAD_loop48x16_${rndsuffix}
___
  &precompute_hkeys_on_stack($HTABLE, $HKEYS_READY, $ZT0, $ZT1, $ZT2, $ZT3, $ZT4, $ZT5, $ZT6, $ZT7);
  $code .= <<___;
        vmovdqu64         `64*0`($T1),$ZT1  # ; Blocks 0-3
        vmovdqu64         `64*1`($T1),$ZT2  # ; Blocks 4-7
        vmovdqu64         `64*2`($T1),$ZT3  # ; Blocks 8-11
        vmovdqu64         `64*3`($T1),$ZT4  # ; Blocks 12-15
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH),
    $ZT1, $ZT2, $ZT3, $ZT4, 16, "multi_call", "first", 48, $ZT14, $ZT15, $ZT16, $ZT17);
  $code .= <<___;
        vmovdqu64         `16*16 + 64*0`($T1),$ZT1   # ; Blocks 16-19
        vmovdqu64         `16*16 + 64*1`($T1),$ZT2   # ; Blocks 20-23
        vmovdqu64         `16*16 + 64*2`($T1),$ZT3   # ; Blocks 24-27
        vmovdqu64         `16*16 + 64*3`($T1),$ZT4   # ; Blocks 28-31
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7,
    $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH), $ZT1, $ZT2, $ZT3,
    $ZT4, 16, "multi_call", "mid", 32, $ZT14, $ZT15, $ZT16, $ZT17);
  $code .= <<___;
        vmovdqu64         `32*16 + 64*0`($T1),$ZT1   # ; Blocks 32-35
        vmovdqu64         `32*16 + 64*1`($T1),$ZT2   # ; Blocks 36-39
        vmovdqu64         `32*16 + 64*2`($T1),$ZT3   # ; Blocks 40-43
        vmovdqu64         `32*16 + 64*3`($T1),$ZT4   # ; Blocks 44-47
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH),
    $ZT1, $ZT2, $ZT3, $ZT4, 16, "multi_call", "last", 16, $ZT14, $ZT15, $ZT16, $ZT17);
  $code .= <<___;
        sub               \$`(48*16)`,$T2
je              .L_CALC_AAD_done_${rndsuffix}

        add               \$`(48*16)`,$T1
jmp             .L_get_AAD_loop48x16_${rndsuffix}

.L_exit_AAD_loop48x16_${rndsuffix}:
        # ; Less than 48x16 bytes remaining
        cmp               \$`(32*16)`,$T2
jl              .L_less_than_32x16_${rndsuffix}
___
  &precompute_hkeys_on_stack($HTABLE, $HKEYS_READY, $ZT0, $ZT1, $ZT2, $ZT3, $ZT4, $ZT5, $ZT6, $ZT7);
  $code .= <<___;
        # ; Get next 16 blocks
        vmovdqu64         `64*0`($T1),$ZT1
        vmovdqu64         `64*1`($T1),$ZT2
        vmovdqu64         `64*2`($T1),$ZT3
        vmovdqu64         `64*3`($T1),$ZT4
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH),
    $ZT1, $ZT2, $ZT3, $ZT4, 16, "multi_call", "first", 32, $ZT14, $ZT15, $ZT16, $ZT17);
  $code .= <<___;
        vmovdqu64         `16*16 + 64*0`($T1),$ZT1
        vmovdqu64         `16*16 + 64*1`($T1),$ZT2
        vmovdqu64         `16*16 + 64*2`($T1),$ZT3
        vmovdqu64         `16*16 + 64*3`($T1),$ZT4
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH),
    $ZT1, $ZT2, $ZT3, $ZT4, 16, "multi_call", "last", 16, $ZT14, $ZT15, $ZT16, $ZT17);
  $code .= <<___;
        sub               \$`(32*16)`,$T2
je              .L_CALC_AAD_done_${rndsuffix}

        add               \$`(32*16)`,$T1
jmp             .L_less_than_16x16_${rndsuffix}

.L_less_than_32x16_${rndsuffix}:
        cmp               \$`(16*16)`,$T2
jl              .L_less_than_16x16_${rndsuffix}
        # ;; hkeys can be used from the context only (no frame storage needed)
        # ;; as this is the call to handle exactly 16 blocks
        # ; Get next 16 blocks
        vmovdqu64         `64*0`($T1),$ZT1
        vmovdqu64         `64*1`($T1),$ZT2
        vmovdqu64         `64*2`($T1),$ZT3
        vmovdqu64         `64*3`($T1),$ZT4
        vpshufb           $SHFMSK,$ZT1,$ZT1
        vpshufb           $SHFMSK,$ZT2,$ZT2
        vpshufb           $SHFMSK,$ZT3,$ZT3
        vpshufb           $SHFMSK,$ZT4,$ZT4
___
  &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH),
    $ZT1, $ZT2, $ZT3, $ZT4, 16, "single_call");
  $code .= <<___;
        sub               \$`(16*16)`,$T2
je              .L_CALC_AAD_done_${rndsuffix}

        add               \$`(16*16)`,$T1
        # ; Less than 16x16 bytes remaining
.L_less_than_16x16_${rndsuffix}:
        # ;; hkeys can be used from the context only (no frame storage needed)
        # ;; prep mask source address
        lea               byte64_len_to_mask_table(%rip),$T3
        lea               ($T3,$T2,8),$T3
        # ;; calculate number of blocks to ghash (including partial bytes)
        add             \$15,$T2
        and             \$(-16),$T2       # ; 1 to 16 blocks possible here
        shr             \$4,$T2
___

  foreach my $idx (1 .. 15) {
    $code .= <<___;
        cmp             \$$idx,$T2
        je              .L_AAD_blocks_${idx}_${rndsuffix}
___
  }

  # ;; fall through for 16 blocks

  # ;; The flow of each of these cases is identical:
  # ;; - load blocks plain text
  # ;; - shuffle loaded blocks
  # ;; - xor in current hash value into block 0
  # ;; - perform up multiplications with ghash keys
  # ;; - jump to reduction code

  for (my $aad_blocks = 16; $aad_blocks > 0; $aad_blocks--) {
    $code .= <<___;
.L_AAD_blocks_${aad_blocks}_${rndsuffix}:
        # ; Adjust address to range of byte64_len_to_mask_table
___
    if ($aad_blocks > 4) {
      $code .= "sub               \$`(64 * (int(($aad_blocks-1)/4)) * 8)`,$T3\n";
    }

    $code .= "kmovq             ($T3),$MASKREG\n";

    if ($aad_blocks > 4) {
      $code .= "vmovdqu8          64*0($T1),$ZT1\n";
    } elsif ($aad_blocks > 2) {    # blocks == 3,4
      $code .= "vmovdqu8          64*0($T1),${ZT1}{$MASKREG}{z}\n";
    } elsif ($aad_blocks > 1) {    # blocks == 2
      $code .= "vmovdqu8          64*0($T1),@{[YWORD($ZT1)]}\{$MASKREG\}{z}\n";
    } elsif ($aad_blocks > 0) {    # blocks == 1
      $code .= "vmovdqu8          64*0($T1),@{[XWORD($ZT1)]}\{$MASKREG\}{z}\n";
    }

    if ($aad_blocks > 8) {
      $code .= "vmovdqu8          64*1($T1),$ZT2\n";
    } elsif ($aad_blocks > 6) {    # blocks == 7,8
      $code .= "vmovdqu8          64*1($T1),${ZT2}{$MASKREG}{z}\n";
    } elsif ($aad_blocks > 5) {    # blocks == 6
      $code .= "vmovdqu8          64*1($T1),@{[YWORD($ZT2)]}\{$MASKREG\}{z}\n";
    } elsif ($aad_blocks > 4) {    # blocks == 5
      $code .= "vmovdqu8          64*1($T1),@{[XWORD($ZT2)]}\{$MASKREG\}{z}\n";
    }

    if ($aad_blocks > 12) {
      $code .= "vmovdqu8          64*2($T1),$ZT3\n";
    } elsif ($aad_blocks > 8) {
      $code .= "vmovdqu8          64*2($T1),${ZT3}{$MASKREG}{z}\n";
    }

    if ($aad_blocks > 12) {
      $code .= "vmovdqu8          64*3($T1),${ZT4}{$MASKREG}{z}\n";
    }

    if ($aad_blocks > 2) {
      $code .= "vpshufb           $SHFMSK,$ZT1,$ZT1\n";
    } elsif ($aad_blocks > 1) {    # blocks == 2
      $code .= "vpshufb           @{[YWORD($SHFMSK)]},@{[YWORD($ZT1)]},@{[YWORD($ZT1)]}\n";
    } elsif ($aad_blocks > 0) {    # blocks == 1
      $code .= "vpshufb           @{[XWORD($SHFMSK)]},@{[XWORD($ZT1)]},@{[XWORD($ZT1)]}\n";
    }

    if ($aad_blocks > 6) {
      $code .= "vpshufb           $SHFMSK,$ZT2,$ZT2\n";
    } elsif ($aad_blocks > 5) {    # blocks == 6
      $code .= "vpshufb           @{[YWORD($SHFMSK)]},@{[YWORD($ZT2)]},@{[YWORD($ZT2)]}\n";
    } elsif ($aad_blocks > 4) {    # blocks == 5
      $code .= "vpshufb           @{[XWORD($SHFMSK)]},@{[XWORD($ZT2)]},@{[XWORD($ZT2)]}\n";
    }

    $code .= "vpshufb           $SHFMSK,$ZT3,$ZT3\n" if ($aad_blocks > 8);
    $code .= "vpshufb           $SHFMSK,$ZT4,$ZT4\n" if ($aad_blocks > 12);

    if ($aad_blocks > 8) {
      &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT5, $ZT6, $ZT7,
        $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, &ZWORD($AAD_HASH), $ZT1, $ZT2, $ZT3, $aad_blocks > 12 ? $ZT4 : "no_zmm",
        $aad_blocks, "single_call");
    } else {
      &GHASH_1_TO_16($HTABLE, &ZWORD($AAD_HASH), $ZT0, $ZT3, $ZT4, $ZT5,
        $ZT6, $ZT7, $ZT8, $ZT9, $ZT10, &ZWORD($AAD_HASH), $ZT1, $aad_blocks > 4 ? $ZT2 : "no_zmm",
        "no_zmm", "no_zmm", $aad_blocks, "single_call");
    }
    $code .= "jmp             .L_CALC_AAD_done_${rndsuffix}\n";
  }
  $code .= ".L_CALC_AAD_done_${rndsuffix}:\n";

  # ;; result in AAD_HASH
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; PARTIAL_BLOCK
# ;;; Handles encryption/decryption and the tag partial blocks between
# ;;; update calls.
# ;;; Requires the input data be at least 1 byte long.
# ;;; Output:
# ;;; A cipher/plain of the first partial block (CYPH_PLAIN_OUT),
# ;;; AAD_HASH
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub PARTIAL_BLOCK {
  my $GCM128_CTX     = $_[0];     # [in] key pointer
  my $PBLOCK_LEN     = $_[1];     # [in] partial block length
  my $CYPH_PLAIN_OUT = $_[2];     # [in] output buffer
  my $PLAIN_CYPH_IN  = $_[3];     # [in] input buffer
  my $PLAIN_CYPH_LEN = $_[4];     # [in] buffer length
  my $DATA_OFFSET    = $_[5];     # [in/out] data offset (gets updated)
  my $AAD_HASH       = $_[6];     # [out] updated GHASH value
  my $ENC_DEC        = $_[7];     # [in] cipher direction
  my $GPTMP0         = $_[8];     # [clobbered] GP temporary register
  my $GPTMP1         = $_[9];     # [clobbered] GP temporary register
  my $GPTMP2         = $_[10];    # [clobbered] GP temporary register
  my $ZTMP0          = $_[11];    # [clobbered] ZMM temporary register
  my $ZTMP1          = $_[12];    # [clobbered] ZMM temporary register
  my $ZTMP2          = $_[13];    # [clobbered] ZMM temporary register
  my $ZTMP3          = $_[14];    # [clobbered] ZMM temporary register
  my $ZTMP4          = $_[15];    # [clobbered] ZMM temporary register
  my $ZTMP5          = $_[16];    # [clobbered] ZMM temporary register
  my $ZTMP6          = $_[17];    # [clobbered] ZMM temporary register
  my $ZTMP7          = $_[18];    # [clobbered] ZMM temporary register
  my $ZTMP8          = $_[19];    # [clobbered] ZMM temporary register
  my $ZTMP9          = $_[20];    # [clobbered] ZMM temporary register
  my $MASKREG        = $_[21];    # [clobbered] mask temporary register

  my $XTMP0 = &XWORD($ZTMP0);
  my $XTMP1 = &XWORD($ZTMP1);
  my $XTMP2 = &XWORD($ZTMP2);
  my $XTMP3 = &XWORD($ZTMP3);
  my $XTMP4 = &XWORD($ZTMP4);
  my $XTMP5 = &XWORD($ZTMP5);
  my $XTMP6 = &XWORD($ZTMP6);
  my $XTMP7 = &XWORD($ZTMP7);
  my $XTMP8 = &XWORD($ZTMP8);
  my $XTMP9 = &XWORD($ZTMP9);

  my $LENGTH = $GPTMP0;
  my $IA0    = $GPTMP1;
  my $IA1    = $GPTMP2;

  my $rndsuffix = &random_string();

  $code .= <<___;
        mov             ($PBLOCK_LEN),$LENGTH
        or              $LENGTH, $LENGTH
        je              .L_partial_block_done_${rndsuffix}           # ;Leave Macro if no partial blocks
___
  &READ_SMALL_DATA_INPUT($XTMP0, $PLAIN_CYPH_IN, $PLAIN_CYPH_LEN, $IA0, $MASKREG);
  $code .= <<___;
        # ;; XTMP1 = my_ctx_data.partial_block_enc_key
        vmovdqu64         $CTX_OFFSET_PEncBlock($GCM128_CTX),$XTMP1
        vmovdqu64         @{[HashKeyByIdx(1,$GCM128_CTX,$CTX_OFFSET_HTable)]},$XTMP2

        # ;; adjust the shuffle mask pointer to be able to shift right $LENGTH bytes
        # ;; (16 - $LENGTH) is the number of bytes in plaintext mod 16)
        lea               SHIFT_MASK(%rip),$IA0
        add               $LENGTH,$IA0
        vmovdqu64         ($IA0),$XTMP3   # ; shift right shuffle mask,$XTMP3
        vpshufb           $XTMP3,$XTMP1,$XTMP1
___
  if ($ENC_DEC eq "DEC") {

    # ;;  keep copy of cipher text in $XTMP4
    $code .= "vmovdqa64         $XTMP0,$XTMP4\n";
  }
  $code .= <<___;
        vpxorq            $XTMP0,$XTMP1,$XTMP1      # ; Cyphertext XOR E(K, Yn)
        # ;; Set $IA1 to be the amount of data left in CYPH_PLAIN_IN after filling the block
        # ;; Determine if partial block is not being filled and shift mask accordingly
        mov               $PLAIN_CYPH_LEN,$IA1
        add               $LENGTH,$IA1
        sub               \$16,$IA1
        jge               .L_no_extra_mask_${rndsuffix}
        sub               $IA1,$IA0
.L_no_extra_mask_${rndsuffix}:
        # ;; get the appropriate mask to mask out bottom $LENGTH bytes of $XTMP1
        # ;; - mask out bottom $LENGTH bytes of $XTMP1
        # ;; sizeof(SHUF_MASK) == 0x10
        vmovdqu64         0x10($IA0),$XTMP0
        vpand             $XTMP0,$XTMP1,$XTMP1
___

  if ($ENC_DEC eq "DEC") {
    $code .= <<___;
        vpand             $XTMP0,$XTMP4,$XTMP4
        vpshufb           SHUF_MASK(%rip),$XTMP4,$XTMP4
        vpshufb           $XTMP3,$XTMP4,$XTMP4
        vpxorq            $XTMP4,$AAD_HASH,$AAD_HASH
___
  } else {
    $code .= <<___;
        vpshufb           SHUF_MASK(%rip),$XTMP1,$XTMP1
        vpshufb           $XTMP3,$XTMP1,$XTMP1
        vpxorq            $XTMP1,$AAD_HASH,$AAD_HASH
___
  }
  $code .= <<___;
        cmp               \$0,$IA1
        jl              .L_partial_incomplete_${rndsuffix}
___

  # ;; GHASH computation for the last <16 Byte block
  &GHASH_MUL($AAD_HASH, $XTMP2, $XTMP5, $XTMP6, $XTMP7, $XTMP8, $XTMP9);

  $code .= <<___;
        movq              \$0, ($PBLOCK_LEN)
        # ;;  Set $IA1 to be the number of bytes to write out
        mov               $LENGTH,$IA0
        mov               \$16,$LENGTH
        sub               $IA0,$LENGTH
        jmp             .L_enc_dec_done_${rndsuffix}

.L_partial_incomplete_${rndsuffix}:
___
  if ($win64) {
    $code .= "mov               $PLAIN_CYPH_LEN,$IA0\n";
    $code .= "add               $IA0,($PBLOCK_LEN)\n";
  } else {
    $code .= "add               $PLAIN_CYPH_LEN,($PBLOCK_LEN)\n";
  }
  $code .= <<___;
        mov               $PLAIN_CYPH_LEN,$LENGTH

.L_enc_dec_done_${rndsuffix}:
        # ;; output encrypted Bytes

        lea               byte_len_to_mask_table(%rip),$IA0
        kmovw             ($IA0,$LENGTH,2),$MASKREG
___

  if ($ENC_DEC eq "ENC") {
    $code .= <<___;
        # ;; shuffle XTMP1 back to output as ciphertext
        vpshufb           SHUF_MASK(%rip),$XTMP1,$XTMP1
        vpshufb           $XTMP3,$XTMP1,$XTMP1
___
  }
  $code .= <<___;
        mov               $CYPH_PLAIN_OUT,$IA0
        vmovdqu8          $XTMP1,($IA0,$DATA_OFFSET,1){$MASKREG}
        add               $LENGTH,$DATA_OFFSET
.L_partial_block_done_${rndsuffix}:
___
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; This macro is used to "warm-up" pipeline for GHASH_8_ENCRYPT_8_PARALLEL
# ;;; macro code. It is called only for data lengths 128 and above.
# ;;; The flow is as follows:
# ;;; - encrypt the initial $num_initial_blocks blocks (can be 0)
# ;;; - encrypt the next 8 blocks and stitch with
# ;;;   GHASH for the first $num_initial_blocks
# ;;;   - the last 8th block can be partial (lengths between 129 and 239)
# ;;;   - partial block ciphering is handled within this macro
# ;;;     - top bytes of such block are cleared for
# ;;;       the subsequent GHASH calculations
# ;;;   - PBLOCK needs to be setup in case of multi-call
# ;;;     - top bytes of the block need to include encrypted counter block so that
# ;;;       when handling partial block case text is read and XOR'ed against it.
# ;;;       This needs to be in un-shuffled format.
sub INITIAL_BLOCKS {
  my $AES_EXPKEYS        = $_[0];     # [in] pointer to AES keys
  my $GCM128_CTX         = $_[1];     # [in] pointer to GCM context
  my $CYPH_PLAIN_OUT     = $_[2];     # [in] output buffer
  my $PLAIN_CYPH_IN      = $_[3];     # [in] input buffer
  my $LENGTH             = $_[4];     # [in/out] number of bytes to process
  my $DATA_OFFSET        = $_[5];     # [in/out] data offset
  my $num_initial_blocks = $_[6];     # [in] can be 0, 1, 2, 3, 4, 5, 6 or 7
  my $CTR                = $_[7];     # [in/out] XMM counter block
  my $AAD_HASH           = $_[8];     # [in/out] ZMM with AAD hash
  my $ZT1                = $_[9];     # [out] ZMM cipher blocks 0-3 for GHASH
  my $ZT2                = $_[10];    # [out] ZMM cipher blocks 4-7 for GHASH
  my $ZT3                = $_[11];    # [clobbered] ZMM temporary
  my $ZT4                = $_[12];    # [clobbered] ZMM temporary
  my $ZT5                = $_[13];    # [clobbered] ZMM temporary
  my $ZT6                = $_[14];    # [clobbered] ZMM temporary
  my $ZT7                = $_[15];    # [clobbered] ZMM temporary
  my $ZT8                = $_[16];    # [clobbered] ZMM temporary
  my $ZT9                = $_[17];    # [clobbered] ZMM temporary
  my $ZT10               = $_[18];    # [clobbered] ZMM temporary
  my $ZT11               = $_[19];    # [clobbered] ZMM temporary
  my $ZT12               = $_[20];    # [clobbered] ZMM temporary
  my $ZT13               = $_[21];    # [clobbered] ZMM temporary ; ZT13-ZT20 used for hkeys precomputation
  my $ZT14               = $_[22];    # [clobbered] ZMM temporary
  my $ZT15               = $_[23];    # [clobbered] ZMM temporary
  my $ZT16               = $_[24];    # [clobbered] ZMM temporary
  my $ZT17               = $_[25];    # [clobbered] ZMM temporary
  my $ZT18               = $_[26];    # [clobbered] ZMM temporary
  my $ZT19               = $_[27];    # [clobbered] ZMM temporary
  my $ZT20               = $_[28];    # [clobbered] ZMM temporary
  my $IA0                = $_[29];    # [clobbered] GP temporary
  my $IA1                = $_[30];    # [clobbered] GP temporary
  my $ENC_DEC            = $_[31];    # [in] ENC/DEC selector
  my $MASKREG            = $_[32];    # [clobbered] mask register
  my $SHUFMASK           = $_[33];    # [in] ZMM with BE/LE shuffle mask
  my $PARTIAL_PRESENT
    = $_[34];    # [in] "no_partial_block" option can be passed here (if length is guaranteed to be > 15*16 bytes)
  my $PBLOCK_LEN  = $_[35];    # [in] partial block length
  my $HKEYS_READY = $_[36];    # [in/out] marker that stack frame is popullated with hkeys

  my $T1 = &XWORD($ZT1);
  my $T2 = &XWORD($ZT2);
  my $T3 = &XWORD($ZT3);
  my $T4 = &XWORD($ZT4);
  my $T5 = &XWORD($ZT5);
  my $T6 = &XWORD($ZT6);
  my $T7 = &XWORD($ZT7);
  my $T8 = &XWORD($ZT8);
  my $T9 = &XWORD($ZT9);

  my $TH = $ZT10;
  my $TM = $ZT11;
  my $TL = $ZT12;

  my $rndsuffix = &random_string();

  # ;; determine if partial block code needs to be added
  my $partial_block_possible = 1;
  if ($PARTIAL_PRESENT eq "no_partial_block") {
    $partial_block_possible = 0;
  }

  if ($num_initial_blocks > 0) {

    # ;; prepare AES counter blocks
    if ($num_initial_blocks == 1) {
      $code .= "vpaddd            ONE(%rip),$CTR,$T3\n";
    } elsif ($num_initial_blocks == 2) {
      $code .= "vshufi64x2        \$0,@{[YWORD($CTR)]},@{[YWORD($CTR)]},@{[YWORD($ZT3)]}\n";
      $code .= "vpaddd            ddq_add_1234(%rip),@{[YWORD($ZT3)]},@{[YWORD($ZT3)]}\n";
    } else {
      $code .= "vshufi64x2        \$0,@{[ZWORD($CTR)]},@{[ZWORD($CTR)]},@{[ZWORD($CTR)]}\n";
      $code .= "vpaddd            ddq_add_1234(%rip),@{[ZWORD($CTR)]},$ZT3\n";
      $code .= "vpaddd            ddq_add_5678(%rip),@{[ZWORD($CTR)]},$ZT4\n";
    }

    # ;; extract new counter value ($T3)
    # ;; shuffle the counters for AES rounds
    if ($num_initial_blocks <= 4) {
      $code .= "vextracti32x4     \$`($num_initial_blocks - 1)`,$ZT3,$CTR\n";
    } else {
      $code .= "vextracti32x4     \$`($num_initial_blocks - 5)`,$ZT4,$CTR\n";
    }
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
      $num_initial_blocks, "vpshufb", $ZT3,     $ZT4,     "no_zmm",  "no_zmm",
      $ZT3,                $ZT4,      "no_zmm", "no_zmm", $SHUFMASK, $SHUFMASK,
      $SHUFMASK,           $SHUFMASK);

    # ;; load plain/cipher text
    &ZMM_LOAD_BLOCKS_0_16($num_initial_blocks, $PLAIN_CYPH_IN, $DATA_OFFSET, $ZT5, $ZT6, "no_zmm", "no_zmm");

    # ;; AES rounds and XOR with plain/cipher text
    for (my $j = 0; $j < $NROUNDS + 2; $j++) {
      $code .= "vbroadcastf64x2 `$j*16`($AES_EXPKEYS),$ZT1\n";
      &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT3, $ZT4, "no_zmm", "no_zmm", $ZT1, $j, $ZT5,
        $ZT6, "no_zmm", "no_zmm", $num_initial_blocks, $NROUNDS);
    }

    # ;; write cipher/plain text back to output and
    # ;; zero bytes outside the mask before hashing
    $code .= "mov       $CYPH_PLAIN_OUT,$IA0\n";
    &ZMM_STORE_BLOCKS_0_16($num_initial_blocks, $IA0, $DATA_OFFSET, $ZT3, $ZT4, "no_zmm", "no_zmm");

    # ;; Shuffle the cipher text blocks for hashing part
    # ;; ZT5 and ZT6 are expected outputs with blocks for hashing
    if ($ENC_DEC eq "DEC") {

      # ;; Decrypt case
      # ;; - cipher blocks are in ZT5 & ZT6
      &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
        $num_initial_blocks, "vpshufb", $ZT5,     $ZT6,     "no_zmm",  "no_zmm",
        $ZT5,                $ZT6,      "no_zmm", "no_zmm", $SHUFMASK, $SHUFMASK,
        $SHUFMASK,           $SHUFMASK);
    } else {

      # ;; Encrypt case
      # ;; - cipher blocks are in ZT3 & ZT4
      &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16(
        $num_initial_blocks, "vpshufb", $ZT5,     $ZT6,     "no_zmm",  "no_zmm",
        $ZT3,                $ZT4,      "no_zmm", "no_zmm", $SHUFMASK, $SHUFMASK,
        $SHUFMASK,           $SHUFMASK);
    }

    # ;; adjust data offset and length
    $code .= "sub               \$`($num_initial_blocks * 16)`,$LENGTH\n";
    $code .= "add               \$`($num_initial_blocks * 16)`,$DATA_OFFSET\n";

    # ;; At this stage
    # ;; - ZT5:ZT6 include cipher blocks to be GHASH'ed
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; - cipher of $num_initial_blocks is done
  # ;; - prepare counter blocks for the next 8 blocks (ZT3 & ZT4)
  # ;;   - save the last block in $CTR
  # ;;   - shuffle the blocks for AES
  # ;; - stitch encryption of the new blocks with
  # ;;   GHASHING the previous blocks
  $code .= <<___;
        vshufi64x2        \$0,@{[ZWORD($CTR)]},@{[ZWORD($CTR)]},@{[ZWORD($CTR)]}
        vpaddd            ddq_add_1234(%rip),@{[ZWORD($CTR)]},$ZT3
        vpaddd            ddq_add_5678(%rip),@{[ZWORD($CTR)]},$ZT4
        vextracti32x4     \$3,$ZT4,$CTR

        vpshufb           $SHUFMASK,$ZT3,$ZT3
        vpshufb           $SHUFMASK,$ZT4,$ZT4
___

  if ($partial_block_possible != 0) {

    # ;; get text load/store mask (assume full mask by default)
    $code .= "mov               \$0xffffffffffffffff,$IA0\n";
    if ($num_initial_blocks > 0) {

      # ;; NOTE: 'jge' is always taken for $num_initial_blocks = 0
      # ;;      This macro is executed for length 128 and up,
      # ;;      zero length is checked in GCM_ENC_DEC.
      # ;; We know there is partial block if:
      # ;;      LENGTH - 16*num_initial_blocks < 128
      $code .= <<___;
        cmp               \$128,$LENGTH
        jge               .L_initial_partial_block_continue_${rndsuffix}
        mov               %rcx,$IA1
        mov               \$128, %rcx
        sub               $LENGTH,%rcx
        shr               %cl,@{[BYTE($IA0)]}
        mov               $IA1, %rcx
.L_initial_partial_block_continue_${rndsuffix}:
___
    }
    $code .= "kmovq             $IA0,$MASKREG\n";

    # ;; load plain or cipher text (masked)
    &ZMM_LOAD_MASKED_BLOCKS_0_16(8, $PLAIN_CYPH_IN, $DATA_OFFSET, $ZT1, $ZT2, "no_zmm", "no_zmm", $MASKREG);
  } else {

    # ;; load plain or cipher text
    &ZMM_LOAD_BLOCKS_0_16(8, $PLAIN_CYPH_IN, $DATA_OFFSET, $ZT1, $ZT2, "no_zmm", "no_zmm");
  }

  # ;; === AES ROUND 0
  my $aes_round = 0;
  $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS),$ZT8\n";
  &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT3, $ZT4, "no_zmm", "no_zmm", $ZT8,
    $aes_round, $ZT1, $ZT2, "no_zmm", "no_zmm", 8, $NROUNDS);
  $aes_round++;

  # ;; ===  GHASH blocks 4-7
  if ($num_initial_blocks > 0) {

    # ;; Hash in AES state
    $code .= "vpxorq            $AAD_HASH,$ZT5,$ZT5\n";
    &VCLMUL_1_TO_8_STEP1($GCM128_CTX, $ZT6, $ZT8, $ZT9, $TH, $TM, $TL, $num_initial_blocks);
  }

  # ;; === [1/3] of AES rounds

  foreach (1 .. int(($NROUNDS + 1) / 3)) {
    $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS),$ZT8\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT3, $ZT4, "no_zmm", "no_zmm", $ZT8,
      $aes_round, $ZT1, $ZT2, "no_zmm", "no_zmm", 8, $NROUNDS);
    $aes_round++;
  }

  # ;; Get Htable pointer
  $code .= "lea               `$CTX_OFFSET_HTable`($GCM128_CTX),$IA0\n";
  &precompute_hkeys_on_stack($IA0, $HKEYS_READY, $ZT13, $ZT14, $ZT15, $ZT16, $ZT17, $ZT18, $ZT19, $ZT20);

  # ;; ===  GHASH blocks 0-3 and gather
  if ($num_initial_blocks > 0) {
    &VCLMUL_1_TO_8_STEP2($GCM128_CTX, $ZT6, $ZT5, $ZT7, $ZT8, $ZT9, $TH, $TM, $TL, $num_initial_blocks);
  }

  # ;; === [2/3] of AES rounds

  foreach (1 .. int(($NROUNDS + 1) / 3)) {
    $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS),$ZT8\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT3, $ZT4, "no_zmm", "no_zmm", $ZT8,
      $aes_round, $ZT1, $ZT2, "no_zmm", "no_zmm", 8, $NROUNDS);
    $aes_round++;
  }

  # ;; ===  GHASH reduction

  if ($num_initial_blocks > 0) {

    # ;; [out] AAD_HASH - hash output
    # ;; [in]  T8 - polynomial
    # ;; [in]  T6 - high, T5 - low
    # ;; [clobbered] T9, T7 - temporary
    $code .= "vmovdqu64         POLY2(%rip),$T8\n";
    &VCLMUL_REDUCE(&XWORD($AAD_HASH), $T8, $T6, $T5, $T7, $T9);
  }

  # ;; === [3/3] of AES rounds

  foreach (1 .. (int(($NROUNDS + 1) / 3) + 2)) {
    if ($aes_round < ($NROUNDS + 2)) {
      $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS),$ZT8\n";
      &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT3, $ZT4, "no_zmm", "no_zmm", $ZT8,
        $aes_round, $ZT1, $ZT2, "no_zmm", "no_zmm", 8, $NROUNDS);
      $aes_round++;
    }
  }

  if ($partial_block_possible != 0) {

    # ;; write cipher/plain text back to output and
    # ;; zero bytes outside the mask before hashing
    $code .= "mov       $CYPH_PLAIN_OUT,$IA0\n";
    &ZMM_STORE_MASKED_BLOCKS_0_16(8, $IA0, $DATA_OFFSET, $ZT3, $ZT4, "no_zmm", "no_zmm", $MASKREG);

    # ;; check if there is partial block
    $code .= "cmp               \$128,$LENGTH\n";
    $code .= "jl              .L_initial_save_partial_${rndsuffix}\n";

    # ;; adjust offset and length
    $code .= <<___;
        add               \$128,$DATA_OFFSET
        sub               \$128,$LENGTH
        jmp             .L_initial_blocks_done_${rndsuffix}
.L_initial_save_partial_${rndsuffix}:
___

    # ;; partial block case
    # ;; - save the partial block in unshuffled format
    # ;;   - ZT4 is partially XOR'ed with data and top bytes contain
    # ;;     encrypted counter block only
    # ;; - save number of bytes process in the partial block
    # ;; - adjust offset and zero the length
    # ;; - clear top bytes of the partial block for subsequent GHASH calculations
    $code .= <<___;
        vextracti32x4     \$3,$ZT4,$CTX_OFFSET_PEncBlock($GCM128_CTX)
        add               $LENGTH,$DATA_OFFSET
        sub               `(128 - 16)`,$LENGTH
        mov               $LENGTH,($PBLOCK_LEN)
        xor               $LENGTH, $LENGTH
        vmovdqu8          $ZT4,${ZT4}{$MASKREG}{z}
.L_initial_blocks_done_${rndsuffix}:
___
  } else {
    $code .= "mov       $CYPH_PLAIN_OUT,$IA0\n";
    &ZMM_STORE_BLOCKS_0_16(8, $IA0, $DATA_OFFSET, $ZT3, $ZT4, "no_zmm", "no_zmm");
    $code .= "add               \$128,$DATA_OFFSET\n";
    $code .= "sub               \$128,$LENGTH\n";
  }

  # ;; Shuffle AES result for GHASH.
  if ($ENC_DEC eq "DEC") {

    # ;; Decrypt case
    # ;; - cipher blocks are in ZT1 & ZT2
    $code .= "vpshufb           $SHUFMASK,$ZT1,$ZT1\n";
    $code .= "vpshufb           $SHUFMASK,$ZT2,$ZT2\n";
  } else {

    # ;; Encrypt case
    # ;; - cipher blocks are in ZT3 & ZT4
    $code .= "vpshufb           $SHUFMASK,$ZT3,$ZT1\n";
    $code .= "vpshufb           $SHUFMASK,$ZT4,$ZT2\n";
  }

  # ;; Current hash value is in AAD_HASH

  # ;; Combine GHASHed value with the corresponding ciphertext
  $code .= "vpxorq            $AAD_HASH,$ZT1,$ZT1\n";

}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; INITIAL_BLOCKS_PARTIAL macro with support for a partial final block.
# ;;; It may look similar to INITIAL_BLOCKS but its usage is different:
# ;;; - first encrypts/decrypts required number of blocks and then
# ;;;   ghashes these blocks
# ;;; - Small packets or left over data chunks (<256 bytes)
# ;;;     - single or multi call
# ;;; - Remaining data chunks below 256 bytes (multi buffer code)
# ;;;
# ;;; num_initial_blocks is expected to include the partial final block
# ;;; in the count.
sub INITIAL_BLOCKS_PARTIAL {
  my $AES_EXPKEYS        = $_[0];     # [in] key pointer
  my $GCM128_CTX         = $_[1];     # [in] pointer to context
  my $CYPH_PLAIN_OUT     = $_[2];     # [in] text out pointer
  my $PLAIN_CYPH_IN      = $_[3];     # [in] text out pointer
  my $LENGTH             = $_[4];     # [in/clobbered] length in bytes
  my $DATA_OFFSET        = $_[5];     # [in/out] current data offset (updated)
  my $num_initial_blocks = $_[6];     # [in] can only be 1, 2, 3, 4, 5, ..., 15 or 16 (not 0)
  my $CTR                = $_[7];     # [in/out] current counter value
  my $HASH_IN_OUT        = $_[8];     # [in/out] XMM ghash in/out value
  my $ENC_DEC            = $_[9];     # [in] cipher direction (ENC/DEC)
  my $INSTANCE_TYPE      = $_[10];    # [in] multi_call or single_call
  my $ZT0                = $_[11];    # [clobbered] ZMM temporary
  my $ZT1                = $_[12];    # [clobbered] ZMM temporary
  my $ZT2                = $_[13];    # [clobbered] ZMM temporary
  my $ZT3                = $_[14];    # [clobbered] ZMM temporary
  my $ZT4                = $_[15];    # [clobbered] ZMM temporary
  my $ZT5                = $_[16];    # [clobbered] ZMM temporary
  my $ZT6                = $_[17];    # [clobbered] ZMM temporary
  my $ZT7                = $_[18];    # [clobbered] ZMM temporary
  my $ZT8                = $_[19];    # [clobbered] ZMM temporary
  my $ZT9                = $_[20];    # [clobbered] ZMM temporary
  my $ZT10               = $_[21];    # [clobbered] ZMM temporary
  my $ZT11               = $_[22];    # [clobbered] ZMM temporary
  my $ZT12               = $_[23];    # [clobbered] ZMM temporary
  my $ZT13               = $_[24];    # [clobbered] ZMM temporary
  my $ZT14               = $_[25];    # [clobbered] ZMM temporary
  my $ZT15               = $_[26];    # [clobbered] ZMM temporary
  my $ZT16               = $_[27];    # [clobbered] ZMM temporary
  my $ZT17               = $_[28];    # [clobbered] ZMM temporary
  my $ZT18               = $_[29];    # [clobbered] ZMM temporary
  my $ZT19               = $_[30];    # [clobbered] ZMM temporary
  my $ZT20               = $_[31];    # [clobbered] ZMM temporary
  my $ZT21               = $_[32];    # [clobbered] ZMM temporary
  my $ZT22               = $_[33];    # [clobbered] ZMM temporary
  my $IA0                = $_[34];    # [clobbered] GP temporary
  my $IA1                = $_[35];    # [clobbered] GP temporary
  my $MASKREG            = $_[36];    # [clobbered] mask register
  my $SHUFMASK           = $_[37];    # [in] ZMM with BE/LE shuffle mask
  my $PBLOCK_LEN         = $_[38];    # [in] partial block length
  my $HKEYS_READY        = $_[39];    # [in/out]

  my $T1 = &XWORD($ZT1);
  my $T2 = &XWORD($ZT2);
  my $T7 = &XWORD($ZT7);

  my $CTR0 = $ZT3;
  my $CTR1 = $ZT4;
  my $CTR2 = $ZT8;
  my $CTR3 = $ZT9;

  my $DAT0 = $ZT5;
  my $DAT1 = $ZT6;
  my $DAT2 = $ZT10;
  my $DAT3 = $ZT11;

  my $rndsuffix = &random_string();

  # ;; Copy ghash to temp reg
  $code .= "vmovdqa64         $HASH_IN_OUT,$T2\n";

  # ;; prepare AES counter blocks
  if ($num_initial_blocks == 1) {
    $code .= "vpaddd            ONE(%rip),$CTR,@{[XWORD($CTR0)]}\n";
  } elsif ($num_initial_blocks == 2) {
    $code .= "vshufi64x2        \$0,@{[YWORD($CTR)]},@{[YWORD($CTR)]},@{[YWORD($CTR0)]}\n";
    $code .= "vpaddd            ddq_add_1234(%rip),@{[YWORD($CTR0)]},@{[YWORD($CTR0)]}\n";
  } else {
    $code .= "vshufi64x2        \$0,@{[ZWORD($CTR)]},@{[ZWORD($CTR)]},@{[ZWORD($CTR)]}\n";
    $code .= "vpaddd            ddq_add_1234(%rip),@{[ZWORD($CTR)]},$CTR0\n";
    if ($num_initial_blocks > 4) {
      $code .= "vpaddd            ddq_add_5678(%rip),@{[ZWORD($CTR)]},$CTR1\n";
    }
    if ($num_initial_blocks > 8) {
      $code .= "vpaddd            ddq_add_8888(%rip),$CTR0,$CTR2\n";
    }
    if ($num_initial_blocks > 12) {
      $code .= "vpaddd            ddq_add_8888(%rip),$CTR1,$CTR3\n";
    }
  }

  # ;; get load/store mask
  $code .= "lea               byte64_len_to_mask_table(%rip),$IA0\n";
  $code .= "mov               $LENGTH,$IA1\n";
  if ($num_initial_blocks > 12) {
    $code .= "sub               \$`3*64`,$IA1\n";
  } elsif ($num_initial_blocks > 8) {
    $code .= "sub               \$`2*64`,$IA1\n";
  } elsif ($num_initial_blocks > 4) {
    $code .= "sub               \$`1*64`,$IA1\n";
  }
  $code .= "kmovq             ($IA0,$IA1,8),$MASKREG\n";

  # ;; extract new counter value
  # ;; shuffle the counters for AES rounds
  if ($num_initial_blocks <= 4) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 1)`,$CTR0,$CTR\n";
  } elsif ($num_initial_blocks <= 8) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 5)`,$CTR1,$CTR\n";
  } elsif ($num_initial_blocks <= 12) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 9)`,$CTR2,$CTR\n";
  } else {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 13)`,$CTR3,$CTR\n";
  }
  &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16($num_initial_blocks,
    "vpshufb", $CTR0, $CTR1, $CTR2, $CTR3, $CTR0, $CTR1, $CTR2, $CTR3, $SHUFMASK, $SHUFMASK, $SHUFMASK, $SHUFMASK);

  # ;; load plain/cipher text
  &ZMM_LOAD_MASKED_BLOCKS_0_16($num_initial_blocks, $PLAIN_CYPH_IN, $DATA_OFFSET, $DAT0, $DAT1, $DAT2, $DAT3, $MASKREG);

  # ;; AES rounds and XOR with plain/cipher text
  for (my $j = 0; $j < ($NROUNDS + 2); $j++) {
    $code .= "vbroadcastf64x2  `($j*16)`($AES_EXPKEYS),$ZT1\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($CTR0, $CTR1, $CTR2, $CTR3, $ZT1, $j,
      $DAT0, $DAT1, $DAT2, $DAT3, $num_initial_blocks, $NROUNDS);
  }

  # ;; retrieve the last cipher counter block (partially XOR'ed with text)
  # ;; - this is needed for partial block cases
  if ($num_initial_blocks <= 4) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 1)`,$CTR0,$T1\n";
  } elsif ($num_initial_blocks <= 8) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 5)`,$CTR1,$T1\n";
  } elsif ($num_initial_blocks <= 12) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 9)`,$CTR2,$T1\n";
  } else {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 13)`,$CTR3,$T1\n";
  }

  # ;; write cipher/plain text back to output and
  $code .= "mov       $CYPH_PLAIN_OUT,$IA0\n";
  &ZMM_STORE_MASKED_BLOCKS_0_16($num_initial_blocks, $IA0, $DATA_OFFSET, $CTR0, $CTR1, $CTR2, $CTR3, $MASKREG);

  # ;; zero bytes outside the mask before hashing
  if ($num_initial_blocks <= 4) {
    $code .= "vmovdqu8          $CTR0,${CTR0}{$MASKREG}{z}\n";
  } elsif ($num_initial_blocks <= 8) {
    $code .= "vmovdqu8          $CTR1,${CTR1}{$MASKREG}{z}\n";
  } elsif ($num_initial_blocks <= 12) {
    $code .= "vmovdqu8          $CTR2,${CTR2}{$MASKREG}{z}\n";
  } else {
    $code .= "vmovdqu8          $CTR3,${CTR3}{$MASKREG}{z}\n";
  }

  # ;; Shuffle the cipher text blocks for hashing part
  # ;; ZT5 and ZT6 are expected outputs with blocks for hashing
  if ($ENC_DEC eq "DEC") {

    # ;; Decrypt case
    # ;; - cipher blocks are in ZT5 & ZT6
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16($num_initial_blocks,
      "vpshufb", $DAT0, $DAT1, $DAT2, $DAT3, $DAT0, $DAT1, $DAT2, $DAT3, $SHUFMASK, $SHUFMASK, $SHUFMASK, $SHUFMASK);
  } else {

    # ;; Encrypt case
    # ;; - cipher blocks are in CTR0-CTR3
    &ZMM_OPCODE3_DSTR_SRC1R_SRC2R_BLOCKS_0_16($num_initial_blocks,
      "vpshufb", $DAT0, $DAT1, $DAT2, $DAT3, $CTR0, $CTR1, $CTR2, $CTR3, $SHUFMASK, $SHUFMASK, $SHUFMASK, $SHUFMASK);
  }

  # ;; Extract the last block for partials and multi_call cases
  if ($num_initial_blocks <= 4) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 1)`,$DAT0,$T7\n";
  } elsif ($num_initial_blocks <= 8) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 5)`,$DAT1,$T7\n";
  } elsif ($num_initial_blocks <= 12) {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 9)`,$DAT2,$T7\n";
  } else {
    $code .= "vextracti32x4     \$`($num_initial_blocks - 13)`,$DAT3,$T7\n";
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;;; Hash all but the last block of data
  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

  # ;; update data offset
  if ($num_initial_blocks > 1) {

    # ;; The final block of data may be <16B
    $code .= "add               \$`16 * ($num_initial_blocks - 1)`,$DATA_OFFSET\n";
    $code .= "sub               \$`16 * ($num_initial_blocks - 1)`,$LENGTH\n";
  }

  if ($num_initial_blocks < 16) {

    # ;; NOTE: the 'jl' is always taken for num_initial_blocks = 16.
    # ;;      This is run in the context of GCM_ENC_DEC_SMALL for length < 256.
    $code .= "cmp               \$16,$LENGTH\n";
    $code .= "jl                .L_small_initial_partial_block_${rndsuffix}\n";

    # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    # ;;; Handle a full length final block - encrypt and hash all blocks
    # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    $code .= "sub               \$16,$LENGTH\n";
    $code .= "add               \$16,$DATA_OFFSET\n";
    $code .= "mov               $LENGTH,($PBLOCK_LEN)\n";

    # ;; Get Htable pointer
    $code .= "lea               `$CTX_OFFSET_HTable`($GCM128_CTX),$IA0\n";

    # ;; Hash all of the data
    # ;; ZT2 - incoming AAD hash (low 128bits)
    # ;; ZT12-ZT20 - temporary registers
    &GHASH_1_TO_16($IA0, $HASH_IN_OUT, $ZT12, $ZT13, $ZT14, $ZT15, $ZT16,
      $ZT17, $ZT18, $ZT19, $ZT20, $ZT2, $DAT0, $DAT1, $DAT2, $DAT3, $num_initial_blocks, "single_call");

    $code .= "jmp             .L_small_initial_compute_done_${rndsuffix}\n";
  }

  $code .= <<___;
.L_small_initial_partial_block_${rndsuffix}:

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;;; Handle ghash for a <16B final block
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        # ;; In this case if it's a single call to encrypt we can
        # ;; hash all of the data but if it's an init / update / finalize
        # ;; series of call we need to leave the last block if it's
        # ;; less than a full block of data.

        mov               $LENGTH,($PBLOCK_LEN)
        # ;; $T1 is ciphered counter block
        vmovdqu64         $T1,$CTX_OFFSET_PEncBlock($GCM128_CTX)
___

  my $k;
  my $last_block_to_hash;
  if ($INSTANCE_TYPE eq "multi_call") {
    $k                  = ($num_initial_blocks - 1);
    $last_block_to_hash = 1;
  } else {
    $k                  = ($num_initial_blocks);
    $last_block_to_hash = 0;
  }

  if ($num_initial_blocks > $last_block_to_hash) {

    # ;; Get Htable pointer
    $code .= "lea               `$CTX_OFFSET_HTable`($GCM128_CTX),$IA0\n";

    # ;; ZT12-ZT20 - temporary registers
    &GHASH_1_TO_16(
      $IA0,  $HASH_IN_OUT, $ZT12, $ZT13, $ZT14, $ZT15, $ZT16, $ZT17, $ZT18,
      $ZT19, $ZT20,        $ZT2,  $DAT0, $DAT1, $DAT2, $DAT3, $k,    "single_call");

    # ;; just fall through no jmp needed
  } else {

    # ;; Record that a reduction is not needed -
    # ;; In this case no hashes are computed because there
    # ;; is only one initial block and it is < 16B in length.
    # ;; We only need to check if a reduction is needed if
    # ;; initial_blocks == 1 and init/update/final is being used.
    # ;; In this case we may just have a partial block, and that
    # ;; gets hashed in finalize.

    # ;; The hash should end up in HASH_IN_OUT.
    # ;; The only way we should get here is if there is
    # ;; a partial block of data, so xor that into the hash.
    $code .= "vpxorq            $T7,$T2,$HASH_IN_OUT\n";

    # ;; The result is in HASH_IN_OUT
    $code .= "jmp             .L_after_reduction_${rndsuffix}\n";
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;;; After GHASH reduction
  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

  $code .= ".L_small_initial_compute_done_${rndsuffix}:\n";

  if ($INSTANCE_TYPE eq "multi_call") {

    # ;; If using init/update/finalize, we need to xor any partial block data
    # ;; into the hash.
    if ($num_initial_blocks > 1) {

      # ;; NOTE: for $num_initial_blocks = 0 the xor never takes place
      if ($num_initial_blocks != 16) {

        # ;; NOTE: for $num_initial_blocks = 16, $LENGTH, stored in [PBLOCK_LEN] is never zero
        $code .= "or              $LENGTH, $LENGTH\n";
        $code .= "je              .L_after_reduction_${rndsuffix}\n";
      }
      $code .= "vpxorq          $T7,$HASH_IN_OUT,$HASH_IN_OUT\n";
    }
  }

  $code .= <<___;
.L_after_reduction_${rndsuffix}:
        # ;; Final hash is now in HASH_IN_OUT
___
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Main GCM macro stitching cipher with GHASH
# ;;; - operates on single stream
# ;;; - encrypts 8 blocks at a time
# ;;; - ghash the 8 previously encrypted ciphertext blocks
# ;;; For partial block case and multi_call , AES_PARTIAL_BLOCK on output
# ;;; contains encrypted counter block.
sub GHASH_8_ENCRYPT_8_PARALLEL {
  my $AES_EXPKEYS        = $_[0];     # [in] key pointer
  my $CYPH_PLAIN_OUT     = $_[1];     # [in] pointer to output buffer
  my $PLAIN_CYPH_IN      = $_[2];     # [in] pointer to input buffer
  my $DATA_OFFSET        = $_[3];     # [in] data offset
  my $CTR1               = $_[4];     # [in/out] ZMM counter blocks 0 to 3
  my $CTR2               = $_[5];     # [in/out] ZMM counter blocks 4 to 7
  my $GHASHIN_AESOUT_B03 = $_[6];     # [in/out] ZMM ghash in / aes out blocks 0 to 3
  my $GHASHIN_AESOUT_B47 = $_[7];     # [in/out] ZMM ghash in / aes out blocks 4 to 7
  my $AES_PARTIAL_BLOCK  = $_[8];     # [out] XMM partial block (AES)
  my $loop_idx           = $_[9];     # [in] counter block prep selection "add+shuffle" or "add"
  my $ENC_DEC            = $_[10];    # [in] cipher direction
  my $FULL_PARTIAL       = $_[11];    # [in] last block type selection "full" or "partial"
  my $IA0                = $_[12];    # [clobbered] temporary GP register
  my $IA1                = $_[13];    # [clobbered] temporary GP register
  my $LENGTH             = $_[14];    # [in] length
  my $INSTANCE_TYPE      = $_[15];    # [in] 'single_call' or 'multi_call' selection
  my $GH4KEY             = $_[16];    # [in] ZMM with GHASH keys 4 to 1
  my $GH8KEY             = $_[17];    # [in] ZMM with GHASH keys 8 to 5
  my $SHFMSK             = $_[18];    # [in] ZMM with byte swap mask for pshufb
  my $ZT1                = $_[19];    # [clobbered] temporary ZMM (cipher)
  my $ZT2                = $_[20];    # [clobbered] temporary ZMM (cipher)
  my $ZT3                = $_[21];    # [clobbered] temporary ZMM (cipher)
  my $ZT4                = $_[22];    # [clobbered] temporary ZMM (cipher)
  my $ZT5                = $_[23];    # [clobbered] temporary ZMM (cipher)
  my $ZT10               = $_[24];    # [clobbered] temporary ZMM (ghash)
  my $ZT11               = $_[25];    # [clobbered] temporary ZMM (ghash)
  my $ZT12               = $_[26];    # [clobbered] temporary ZMM (ghash)
  my $ZT13               = $_[27];    # [clobbered] temporary ZMM (ghash)
  my $ZT14               = $_[28];    # [clobbered] temporary ZMM (ghash)
  my $ZT15               = $_[29];    # [clobbered] temporary ZMM (ghash)
  my $ZT16               = $_[30];    # [clobbered] temporary ZMM (ghash)
  my $ZT17               = $_[31];    # [clobbered] temporary ZMM (ghash)
  my $MASKREG            = $_[32];    # [clobbered] mask register for partial loads/stores
  my $DO_REDUCTION       = $_[33];    # [in] "reduction", "no_reduction", "final_reduction"
  my $TO_REDUCE_L        = $_[34];    # [in/out] ZMM for low 4x128-bit in case of "no_reduction"
  my $TO_REDUCE_H        = $_[35];    # [in/out] ZMM for hi 4x128-bit in case of "no_reduction"
  my $TO_REDUCE_M        = $_[36];    # [in/out] ZMM for medium 4x128-bit in case of "no_reduction"

  my $GH1H  = $ZT10;
  my $GH1L  = $ZT11;
  my $GH1M1 = $ZT12;
  my $GH1M2 = $ZT13;

  my $GH2H  = $ZT14;
  my $GH2L  = $ZT15;
  my $GH2M1 = $ZT16;
  my $GH2M2 = $ZT17;

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; populate counter blocks for cipher part
  if ($loop_idx eq "in_order") {

    # ;; $CTR1 & $CTR2 are shuffled outside the scope of this macro
    # ;; it has to be kept in unshuffled format
    $code .= "vpshufb           $SHFMSK,$CTR1,$ZT1\n";
    $code .= "vpshufb           $SHFMSK,$CTR2,$ZT2\n";
  } else {
    $code .= "vmovdqa64         $CTR1,$ZT1\n";
    $code .= "vmovdqa64         $CTR2,$ZT2\n";
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; stitch AES rounds with GHASH

  my $aes_round = 0;

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; AES round 0 - ARK
  $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
  &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
    $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);

  $aes_round++;

  # ;;==================================================
  # ;; GHASH 4 blocks
  $code .= <<___;
        vpclmulqdq        \$0x11,$GH4KEY,$GHASHIN_AESOUT_B47,$GH1H      # ; a1*b1
        vpclmulqdq        \$0x00,$GH4KEY,$GHASHIN_AESOUT_B47,$GH1L      # ; a0*b0
        vpclmulqdq        \$0x01,$GH4KEY,$GHASHIN_AESOUT_B47,$GH1M1     # ; a1*b0
        vpclmulqdq        \$0x10,$GH4KEY,$GHASHIN_AESOUT_B47,$GH1M2     # ; a0*b1
___

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; 3 AES rounds
  foreach (1 .. 3) {
    $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
      $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
    $aes_round++;
  }

  # ;; =================================================
  # ;; GHASH 4 blocks
  $code .= <<___;
        vpclmulqdq        \$0x10,$GH8KEY,$GHASHIN_AESOUT_B03,$GH2M1     # ; a0*b1
        vpclmulqdq        \$0x01,$GH8KEY,$GHASHIN_AESOUT_B03,$GH2M2     # ; a1*b0
        vpclmulqdq        \$0x11,$GH8KEY,$GHASHIN_AESOUT_B03,$GH2H      # ; a1*b1
        vpclmulqdq        \$0x00,$GH8KEY,$GHASHIN_AESOUT_B03,$GH2L      # ; a0*b0
___

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; 3 AES rounds
  foreach (1 .. 3) {
    $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
      $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
    $aes_round++;
  }

  # ;; =================================================
  # ;; gather GHASH in GH1L (low) and GH1H (high)
  if ($DO_REDUCTION eq "no_reduction") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M1,$GH1M2,$GH1M1          # ; TM: GH1M1 ^= GH1M2 ^ GH2M1
        vpternlogq        \$0x96,$GH2M2,$GH1M1,$TO_REDUCE_M    # ; TM: TO_REDUCE_M ^= GH1M1 ^ GH2M2
        vpternlogq        \$0x96,$GH2H,$GH1H,$TO_REDUCE_H      # ; TH: TO_REDUCE_H ^= GH1H ^ GH2H
        vpternlogq        \$0x96,$GH2L,$GH1L,$TO_REDUCE_L      # ; TL: TO_REDUCE_L ^= GH1L ^ GH2L
___
  }
  if ($DO_REDUCTION eq "do_reduction") {

    # ;; phase 1: add mid products together
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M1,$GH1M2,$GH1M1          # ; TM: GH1M1 ^= GH1M2 ^ GH2M1
        vpxorq            $GH2M2,$GH1M1,$GH1M1

        vpsrldq           \$8,$GH1M1,$GH2M1
        vpslldq           \$8,$GH1M1,$GH1M1
___
  }
  if ($DO_REDUCTION eq "final_reduction") {

    # ;; phase 1: add mid products together
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M1,$GH1M2,$GH1M1          # ; TM: GH1M1 ^= GH1M2 ^ GH2M1
        vpternlogq        \$0x96,$GH2M2,$TO_REDUCE_M,$GH1M1    # ; TM: GH1M1 ^= TO_REDUCE_M ^ GH2M2
        vpsrldq           \$8,$GH1M1,$GH2M1
        vpslldq           \$8,$GH1M1,$GH1M1
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; 2 AES rounds
  foreach (1 .. 2) {
    $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
    &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
      $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
    $aes_round++;
  }

  # ;; =================================================
  # ;; Add mid product to high and low then
  # ;; horizontal xor of low and high 4x128
  if ($DO_REDUCTION eq "final_reduction") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M1,$GH2H,$GH1H      # ; TH = TH1 + TH2 + TM>>64
        vpxorq            $TO_REDUCE_H,$GH1H,$GH1H
        vpternlogq        \$0x96,$GH1M1,$GH2L,$GH1L      # ; TL = TL1 + TL2 + TM<<64
        vpxorq            $TO_REDUCE_L,$GH1L,$GH1L
___
  }
  if ($DO_REDUCTION eq "do_reduction") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M1,$GH2H,$GH1H      # ; TH = TH1 + TH2 + TM>>64
        vpternlogq        \$0x96,$GH1M1,$GH2L,$GH1L      # ; TL = TL1 + TL2 + TM<<64
___
  }
  if ($DO_REDUCTION ne "no_reduction") {
    $code .= <<___;
        VHPXORI4x128    $GH1H, $GH2H
        VHPXORI4x128    $GH1L, $GH2L
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; 2 AES rounds
  foreach (1 .. 2) {
    if ($aes_round < ($NROUNDS + 1)) {
      $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
      &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
        $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
      $aes_round++;
    }
  }

  # ;; =================================================
  # ;; first phase of reduction
  if ($DO_REDUCTION ne "no_reduction") {
    $code .= <<___;
        vmovdqu64         POLY2(%rip),@{[XWORD($GH2M2)]}
        vpclmulqdq        \$0x01,@{[XWORD($GH1L)]},@{[XWORD($GH2M2)]},@{[XWORD($ZT15)]}
        vpslldq           \$8,@{[XWORD($ZT15)]},@{[XWORD($ZT15)]}                    # ; shift-L 2 DWs
        vpxorq            @{[XWORD($ZT15)]},@{[XWORD($GH1L)]},@{[XWORD($ZT15)]}      # ; first phase of the reduct
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; 2 AES rounds
  foreach (1 .. 2) {
    if ($aes_round < ($NROUNDS + 1)) {
      $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
      &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
        $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
      $aes_round++;
    }
  }

  # ;; =================================================
  # ;; second phase of the reduction
  if ($DO_REDUCTION ne "no_reduction") {
    $code .= <<___;
        vpclmulqdq        \$0x00,@{[XWORD($ZT15)]},@{[XWORD($GH2M2)]},@{[XWORD($ZT16)]}
        vpsrldq           \$4,@{[XWORD($ZT16)]},@{[XWORD($ZT16)]}      # ; shift-R 1-DW to obtain 2-DWs shift-R
        vpclmulqdq        \$0x10,@{[XWORD($ZT15)]},@{[XWORD($GH2M2)]},@{[XWORD($ZT13)]}
        vpslldq           \$4,@{[XWORD($ZT13)]},@{[XWORD($ZT13)]}      # ; shift-L 1-DW for result without shifts
        # ;; ZT13 = ZT13 xor ZT16 xor GH1H
        vpternlogq        \$0x96,@{[XWORD($GH1H)]},@{[XWORD($ZT16)]},@{[XWORD($ZT13)]}
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; all remaining AES rounds but the last
  foreach (1 .. ($NROUNDS + 2)) {
    if ($aes_round < ($NROUNDS + 1)) {
      $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
      &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
        $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);
      $aes_round++;
    }
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; load/store mask (partial case) and load the text data
  if ($FULL_PARTIAL eq "full") {
    $code .= <<___;
        vmovdqu8          ($PLAIN_CYPH_IN,$DATA_OFFSET,1),$ZT4
        vmovdqu8          64($PLAIN_CYPH_IN,$DATA_OFFSET,1),$ZT5
___
  } else {
    $code .= <<___;
        lea               byte64_len_to_mask_table(%rip),$IA0
        mov               $LENGTH,$IA1
        sub               \$64,$IA1
        kmovq             ($IA0,$IA1,8),$MASKREG
        vmovdqu8          ($PLAIN_CYPH_IN,$DATA_OFFSET,1),$ZT4
        vmovdqu8          64($PLAIN_CYPH_IN,$DATA_OFFSET,1),${ZT5}{$MASKREG}{z}
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; the last AES round  (NROUNDS + 1) and XOR against plain/cipher text
  $code .= "vbroadcastf64x2 `$aes_round * 16`($AES_EXPKEYS), $ZT3\n";
  &ZMM_AESENC_ROUND_BLOCKS_0_16($ZT1, $ZT2, "no_zmm", "no_zmm", $ZT3,
    $aes_round, $ZT4, $ZT5, "no_zmm", "no_zmm", 8, $NROUNDS);

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; store the cipher/plain text data
  if ($FULL_PARTIAL eq "full") {
    $code .= <<___;
        mov               $CYPH_PLAIN_OUT,$IA0
        vmovdqu8          $ZT1,($IA0,$DATA_OFFSET,1)
        vmovdqu8          $ZT2,64($IA0,$DATA_OFFSET,1)
___
  } else {
    $code .= <<___;
        mov               $CYPH_PLAIN_OUT,$IA0
        vmovdqu8          $ZT1,($IA0,$DATA_OFFSET,1)
        vmovdqu8          $ZT2,64($IA0,$DATA_OFFSET,1){$MASKREG}
___
  }

  # ;; =================================================
  # ;; prep cipher text blocks for the next ghash round

  if ($FULL_PARTIAL ne "full") {
    if ($INSTANCE_TYPE eq "multi_call") {

      # ;; for partial block & multi_call we need encrypted counter block
      $code .= <<___;
        vpxorq            $ZT5,$ZT2,$ZT3
        vextracti32x4     \$3,$ZT3,$AES_PARTIAL_BLOCK
___
    }

    # ;; for GHASH computation purpose clear the top bytes of the partial block
    if ($ENC_DEC eq "ENC") {
      $code .= "vmovdqu8          $ZT2,${ZT2}{$MASKREG}{z}\n";
    } else {
      $code .= "vmovdqu8          $ZT5,${ZT5}{$MASKREG}{z}\n";
    }
  }

  # ;; =================================================
  # ;; shuffle cipher text blocks for GHASH computation
  if ($ENC_DEC eq "ENC") {
    $code .= <<___;
        vpshufb           $SHFMSK,$ZT1,$GHASHIN_AESOUT_B03
        vpshufb           $SHFMSK,$ZT2,$GHASHIN_AESOUT_B47
___
  } else {
    $code .= <<___;
        vpshufb           $SHFMSK,$ZT4,$GHASHIN_AESOUT_B03
        vpshufb           $SHFMSK,$ZT5,$GHASHIN_AESOUT_B47
___
  }

  if ($DO_REDUCTION eq "do_reduction") {

    # ;; =================================================
    # ;; XOR current GHASH value (ZT13) into block 0
    $code .= "vpxorq            $ZT13,$GHASHIN_AESOUT_B03\n";
  }
  if ($DO_REDUCTION eq "final_reduction") {

    # ;; =================================================
    # ;; Return GHASH value (ZT13) in TO_REDUCE_L
    $code .= "vmovdqa64         $ZT13,$TO_REDUCE_L\n";
  }
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Main GCM macro stitching cipher with GHASH
# ;;; - operates on single stream
# ;;; - encrypts 16 blocks at a time
# ;;; - ghash the 16 previously encrypted ciphertext blocks
# ;;; - no partial block or multi_call handling here
sub GHASH_16_ENCRYPT_16_PARALLEL {
  my $AES_EXPKEYS        = $_[0];     # [in] key pointer
  my $CYPH_PLAIN_OUT     = $_[1];     # [in] pointer to output buffer
  my $PLAIN_CYPH_IN      = $_[2];     # [in] pointer to input buffer
  my $DATA_OFFSET        = $_[3];     # [in] data offset
  my $CTR_BE             = $_[4];     # [in/out] ZMM counter blocks (last 4) in big-endian
  my $CTR_CHECK          = $_[5];     # [in/out] GP with 8-bit counter for overflow check
  my $HASHKEY_OFFSET     = $_[6];     # [in] numerical offset for the highest hash key
  my $AESOUT_BLK_OFFSET  = $_[7];     # [in] numerical offset for AES-CTR out
  my $GHASHIN_BLK_OFFSET = $_[8];     # [in] numerical offset for GHASH blocks in
  my $SHFMSK             = $_[9];     # [in] ZMM with byte swap mask for pshufb
  my $ZT1                = $_[10];    # [clobbered] temporary ZMM (cipher)
  my $ZT2                = $_[11];    # [clobbered] temporary ZMM (cipher)
  my $ZT3                = $_[12];    # [clobbered] temporary ZMM (cipher)
  my $ZT4                = $_[13];    # [clobbered] temporary ZMM (cipher)
  my $ZT5                = $_[14];    # [clobbered/out] temporary ZMM or GHASH OUT (final_reduction)
  my $ZT6                = $_[15];    # [clobbered] temporary ZMM (cipher)
  my $ZT7                = $_[16];    # [clobbered] temporary ZMM (cipher)
  my $ZT8                = $_[17];    # [clobbered] temporary ZMM (cipher)
  my $ZT9                = $_[18];    # [clobbered] temporary ZMM (cipher)
  my $ZT10               = $_[19];    # [clobbered] temporary ZMM (ghash)
  my $ZT11               = $_[20];    # [clobbered] temporary ZMM (ghash)
  my $ZT12               = $_[21];    # [clobbered] temporary ZMM (ghash)
  my $ZT13               = $_[22];    # [clobbered] temporary ZMM (ghash)
  my $ZT14               = $_[23];    # [clobbered] temporary ZMM (ghash)
  my $ZT15               = $_[24];    # [clobbered] temporary ZMM (ghash)
  my $ZT16               = $_[25];    # [clobbered] temporary ZMM (ghash)
  my $ZT17               = $_[26];    # [clobbered] temporary ZMM (ghash)
  my $ZT18               = $_[27];    # [clobbered] temporary ZMM (ghash)
  my $ZT19               = $_[28];    # [clobbered] temporary ZMM
  my $ZT20               = $_[29];    # [clobbered] temporary ZMM
  my $ZT21               = $_[30];    # [clobbered] temporary ZMM
  my $ZT22               = $_[31];    # [clobbered] temporary ZMM
  my $ZT23               = $_[32];    # [clobbered] temporary ZMM
  my $ADDBE_4x4          = $_[33];    # [in] ZMM with 4x128bits 4 in big-endian
  my $ADDBE_1234         = $_[34];    # [in] ZMM with 4x128bits 1, 2, 3 and 4 in big-endian
  my $TO_REDUCE_L        = $_[35];    # [in/out] ZMM for low 4x128-bit GHASH sum
  my $TO_REDUCE_H        = $_[36];    # [in/out] ZMM for hi 4x128-bit GHASH sum
  my $TO_REDUCE_M        = $_[37];    # [in/out] ZMM for medium 4x128-bit GHASH sum
  my $DO_REDUCTION       = $_[38];    # [in] "no_reduction", "final_reduction", "first_time"
  my $ENC_DEC            = $_[39];    # [in] cipher direction
  my $DATA_DISPL         = $_[40];    # [in] fixed numerical data displacement/offset
  my $GHASH_IN           = $_[41];    # [in] current GHASH value or "no_ghash_in"
  my $GCM128_CTX         = $_[42];    # [in] pointer to context
  my $IA0                = $_[43];    # [clobbered] temporary GPR

  my $B00_03 = $ZT1;
  my $B04_07 = $ZT2;
  my $B08_11 = $ZT3;
  my $B12_15 = $ZT4;

  my $GH1H = $ZT5;

  # ; @note: do not change this mapping
  my $GH1L = $ZT6;
  my $GH1M = $ZT7;
  my $GH1T = $ZT8;

  my $GH2H = $ZT9;
  my $GH2L = $ZT10;
  my $GH2M = $ZT11;
  my $GH2T = $ZT12;

  my $RED_POLY = $GH2T;
  my $RED_P1   = $GH2L;
  my $RED_T1   = $GH2H;
  my $RED_T2   = $GH2M;

  my $GH3H = $ZT13;
  my $GH3L = $ZT14;
  my $GH3M = $ZT15;
  my $GH3T = $ZT16;

  my $DATA1 = $ZT13;
  my $DATA2 = $ZT14;
  my $DATA3 = $ZT15;
  my $DATA4 = $ZT16;

  my $AESKEY1 = $ZT17;
  my $AESKEY2 = $ZT18;

  my $GHKEY1 = $ZT19;
  my $GHKEY2 = $ZT20;
  my $GHDAT1 = $ZT21;
  my $GHDAT2 = $ZT22;

  my $rndsuffix = &random_string();

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; prepare counter blocks

  $code .= <<___;
        cmpb              \$`(256 - 16)`,@{[BYTE($CTR_CHECK)]}
        jae             .L_16_blocks_overflow_${rndsuffix}
        vpaddd            $ADDBE_1234,$CTR_BE,$B00_03
        vpaddd            $ADDBE_4x4,$B00_03,$B04_07
        vpaddd            $ADDBE_4x4,$B04_07,$B08_11
        vpaddd            $ADDBE_4x4,$B08_11,$B12_15
        jmp             .L_16_blocks_ok_${rndsuffix}
.L_16_blocks_overflow_${rndsuffix}:
        vpshufb           $SHFMSK,$CTR_BE,$CTR_BE
        vmovdqa64         ddq_add_4444(%rip),$B12_15
        vpaddd            ddq_add_1234(%rip),$CTR_BE,$B00_03
        vpaddd            $B12_15,$B00_03,$B04_07
        vpaddd            $B12_15,$B04_07,$B08_11
        vpaddd            $B12_15,$B08_11,$B12_15
        vpshufb           $SHFMSK,$B00_03,$B00_03
        vpshufb           $SHFMSK,$B04_07,$B04_07
        vpshufb           $SHFMSK,$B08_11,$B08_11
        vpshufb           $SHFMSK,$B12_15,$B12_15
.L_16_blocks_ok_${rndsuffix}:

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; pre-load constants
        vbroadcastf64x2 `16*0`($AES_EXPKEYS),$AESKEY1
___
  if ($GHASH_IN ne "no_ghash_in") {
    $code .= "vpxorq            `$GHASHIN_BLK_OFFSET + (0*64)`(%rsp),$GHASH_IN,$GHDAT1\n";
  } else {
    $code .= "vmovdqa64         `$GHASHIN_BLK_OFFSET + (0*64)`(%rsp),$GHDAT1\n";
  }
  $code .= <<___;
        vmovdqu64         @{[HashKeyByIdx(($HASHKEY_OFFSET - (0*4)),"%rsp")]},$GHKEY1

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; save counter for the next round
        # ;; increment counter overflow check register
        vshufi64x2        \$0b11111111,$B12_15,$B12_15,$CTR_BE
        addb              \$16,@{[BYTE($CTR_CHECK)]}
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; pre-load constants
        vbroadcastf64x2    `(16 * 1)`($AES_EXPKEYS),$AESKEY2
        vmovdqu64         @{[HashKeyByIdx(($HASHKEY_OFFSET - (1*4)),"%rsp")]},$GHKEY2
        vmovdqa64         `$GHASHIN_BLK_OFFSET + (1*64)`(%rsp),$GHDAT2

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; stitch AES rounds with GHASH

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 0 - ARK

        vpxorq            $AESKEY1,$B00_03,$B00_03
        vpxorq            $AESKEY1,$B04_07,$B04_07
        vpxorq            $AESKEY1,$B08_11,$B08_11
        vpxorq            $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 2)`($AES_EXPKEYS),$AESKEY1

        # ;;==================================================
        # ;; GHASH 4 blocks (15 to 12)
        vpclmulqdq        \$0x11,$GHKEY1,$GHDAT1,$GH1H      # ; a1*b1
        vpclmulqdq        \$0x00,$GHKEY1,$GHDAT1,$GH1L      # ; a0*b0
        vpclmulqdq        \$0x01,$GHKEY1,$GHDAT1,$GH1M      # ; a1*b0
        vpclmulqdq        \$0x10,$GHKEY1,$GHDAT1,$GH1T      # ; a0*b1
        vmovdqu64         @{[HashKeyByIdx(($HASHKEY_OFFSET - (2*4)),"%rsp")]},$GHKEY1
        vmovdqa64         `$GHASHIN_BLK_OFFSET + (2*64)`(%rsp),$GHDAT1

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 1
        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 3)`($AES_EXPKEYS),$AESKEY2

        # ;; =================================================
        # ;; GHASH 4 blocks (11 to 8)
        vpclmulqdq        \$0x10,$GHKEY2,$GHDAT2,$GH2M      # ; a0*b1
        vpclmulqdq        \$0x01,$GHKEY2,$GHDAT2,$GH2T      # ; a1*b0
        vpclmulqdq        \$0x11,$GHKEY2,$GHDAT2,$GH2H      # ; a1*b1
        vpclmulqdq        \$0x00,$GHKEY2,$GHDAT2,$GH2L      # ; a0*b0
        vmovdqu64         @{[HashKeyByIdx(($HASHKEY_OFFSET - (3*4)),"%rsp")]},$GHKEY2
        vmovdqa64         `$GHASHIN_BLK_OFFSET + (3*64)`(%rsp),$GHDAT2

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 2
        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 4)`($AES_EXPKEYS),$AESKEY1

        # ;; =================================================
        # ;; GHASH 4 blocks (7 to 4)
        vpclmulqdq        \$0x10,$GHKEY1,$GHDAT1,$GH3M      # ; a0*b1
        vpclmulqdq        \$0x01,$GHKEY1,$GHDAT1,$GH3T      # ; a1*b0
        vpclmulqdq        \$0x11,$GHKEY1,$GHDAT1,$GH3H      # ; a1*b1
        vpclmulqdq        \$0x00,$GHKEY1,$GHDAT1,$GH3L      # ; a0*b0
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES rounds 3
        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 5)`($AES_EXPKEYS),$AESKEY2

        # ;; =================================================
        # ;; Gather (XOR) GHASH for 12 blocks
        vpternlogq        \$0x96,$GH3H,$GH2H,$GH1H
        vpternlogq        \$0x96,$GH3L,$GH2L,$GH1L
        vpternlogq        \$0x96,$GH3T,$GH2T,$GH1T
        vpternlogq        \$0x96,$GH3M,$GH2M,$GH1M

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES rounds 4
        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 6)`($AES_EXPKEYS),$AESKEY1

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; load plain/cipher text (recycle GH3xx registers)
        vmovdqu8          `$DATA_DISPL + (0 * 64)`($PLAIN_CYPH_IN,$DATA_OFFSET),$DATA1
        vmovdqu8          `$DATA_DISPL + (1 * 64)`($PLAIN_CYPH_IN,$DATA_OFFSET),$DATA2
        vmovdqu8          `$DATA_DISPL + (2 * 64)`($PLAIN_CYPH_IN,$DATA_OFFSET),$DATA3
        vmovdqu8          `$DATA_DISPL + (3 * 64)`($PLAIN_CYPH_IN,$DATA_OFFSET),$DATA4

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES rounds 5
        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 7)`($AES_EXPKEYS),$AESKEY2

        # ;; =================================================
        # ;; GHASH 4 blocks (3 to 0)
        vpclmulqdq        \$0x10,$GHKEY2,$GHDAT2,$GH2M      # ; a0*b1
        vpclmulqdq        \$0x01,$GHKEY2,$GHDAT2,$GH2T      # ; a1*b0
        vpclmulqdq        \$0x11,$GHKEY2,$GHDAT2,$GH2H      # ; a1*b1
        vpclmulqdq        \$0x00,$GHKEY2,$GHDAT2,$GH2L      # ; a0*b0
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 6
        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 8)`($AES_EXPKEYS),$AESKEY1

        # ;; =================================================
        # ;; gather GHASH in GH1L (low) and GH1H (high)
___
  if ($DO_REDUCTION eq "first_time") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2T,$GH1T,$GH1M      # ; TM
        vpxorq            $GH2M,$GH1M,$TO_REDUCE_M      # ; TM
        vpxorq            $GH2H,$GH1H,$TO_REDUCE_H      # ; TH
        vpxorq            $GH2L,$GH1L,$TO_REDUCE_L      # ; TL
___
  }
  if ($DO_REDUCTION eq "no_reduction") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2T,$GH1T,$GH1M             # ; TM
        vpternlogq        \$0x96,$GH2M,$GH1M,$TO_REDUCE_M      # ; TM
        vpternlogq        \$0x96,$GH2H,$GH1H,$TO_REDUCE_H      # ; TH
        vpternlogq        \$0x96,$GH2L,$GH1L,$TO_REDUCE_L      # ; TL
___
  }
  if ($DO_REDUCTION eq "final_reduction") {
    $code .= <<___;
        # ;; phase 1: add mid products together
        # ;; also load polynomial constant for reduction
        vpternlogq        \$0x96,$GH2T,$GH1T,$GH1M      # ; TM
        vpternlogq        \$0x96,$GH2M,$TO_REDUCE_M,$GH1M

        vpsrldq           \$8,$GH1M,$GH2M
        vpslldq           \$8,$GH1M,$GH1M

        vmovdqa64         POLY2(%rip),@{[XWORD($RED_POLY)]}
___
  }
  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 7
        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 9)`($AES_EXPKEYS),$AESKEY2

        # ;; =================================================
        # ;; Add mid product to high and low
___
  if ($DO_REDUCTION eq "final_reduction") {
    $code .= <<___;
        vpternlogq        \$0x96,$GH2M,$GH2H,$GH1H      # ; TH = TH1 + TH2 + TM>>64
        vpxorq            $TO_REDUCE_H,$GH1H,$GH1H
        vpternlogq        \$0x96,$GH1M,$GH2L,$GH1L      # ; TL = TL1 + TL2 + TM<<64
        vpxorq            $TO_REDUCE_L,$GH1L,$GH1L
___
  }
  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 8
        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 10)`($AES_EXPKEYS),$AESKEY1

        # ;; =================================================
        # ;; horizontal xor of low and high 4x128
___
  if ($DO_REDUCTION eq "final_reduction") {
    &VHPXORI4x128($GH1H, $GH2H);
    &VHPXORI4x128($GH1L, $GH2L);
  }
  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; AES round 9
        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
___
  if (($NROUNDS >= 11)) {
    $code .= "vbroadcastf64x2    `(16 * 11)`($AES_EXPKEYS),$AESKEY2\n";
  }

  # ;; =================================================
  # ;; first phase of reduction
  if ($DO_REDUCTION eq "final_reduction") {
    $code .= <<___;
        vpclmulqdq        \$0x01,@{[XWORD($GH1L)]},@{[XWORD($RED_POLY)]},@{[XWORD($RED_P1)]}
        vpslldq           \$8,@{[XWORD($RED_P1)]},@{[XWORD($RED_P1)]}               # ; shift-L 2 DWs
        vpxorq            @{[XWORD($RED_P1)]},@{[XWORD($GH1L)]},@{[XWORD($RED_P1)]} # ; first phase of the reduct
___
  }

  # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  # ;; AES rounds up to 11 (AES192) or 13 (AES256)
  # ;; AES128 is done
  if (($NROUNDS >= 11)) {
    $code .= <<___;
        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 12)`($AES_EXPKEYS),$AESKEY1

        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
___
    if (($NROUNDS == 13)) {
      $code .= <<___;
        vbroadcastf64x2    `(16 * 13)`($AES_EXPKEYS),$AESKEY2

        vaesenc         $AESKEY1,$B00_03,$B00_03
        vaesenc         $AESKEY1,$B04_07,$B04_07
        vaesenc         $AESKEY1,$B08_11,$B08_11
        vaesenc         $AESKEY1,$B12_15,$B12_15
        vbroadcastf64x2    `(16 * 14)`($AES_EXPKEYS),$AESKEY1

        vaesenc         $AESKEY2,$B00_03,$B00_03
        vaesenc         $AESKEY2,$B04_07,$B04_07
        vaesenc         $AESKEY2,$B08_11,$B08_11
        vaesenc         $AESKEY2,$B12_15,$B12_15
___
    }
  }

  # ;; =================================================
  # ;; second phase of the reduction
  if ($DO_REDUCTION eq "final_reduction") {
    $code .= <<___;
        vpclmulqdq        \$0x00,@{[XWORD($RED_P1)]},@{[XWORD($RED_POLY)]},@{[XWORD($RED_T1)]}
        vpsrldq           \$4,@{[XWORD($RED_T1)]},@{[XWORD($RED_T1)]}      # ; shift-R 1-DW to obtain 2-DWs shift-R
        vpclmulqdq        \$0x10,@{[XWORD($RED_P1)]},@{[XWORD($RED_POLY)]},@{[XWORD($RED_T2)]}
        vpslldq           \$4,@{[XWORD($RED_T2)]},@{[XWORD($RED_T2)]}      # ; shift-L 1-DW for result without shifts
        # ;; GH1H = GH1H x RED_T1 x RED_T2
        vpternlogq        \$0x96,@{[XWORD($RED_T1)]},@{[XWORD($RED_T2)]},@{[XWORD($GH1H)]}
___
  }
  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; the last AES round
        vaesenclast     $AESKEY1,$B00_03,$B00_03
        vaesenclast     $AESKEY1,$B04_07,$B04_07
        vaesenclast     $AESKEY1,$B08_11,$B08_11
        vaesenclast     $AESKEY1,$B12_15,$B12_15

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; XOR against plain/cipher text
        vpxorq            $DATA1,$B00_03,$B00_03
        vpxorq            $DATA2,$B04_07,$B04_07
        vpxorq            $DATA3,$B08_11,$B08_11
        vpxorq            $DATA4,$B12_15,$B12_15

        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; store cipher/plain text
        mov               $CYPH_PLAIN_OUT,$IA0
        vmovdqu8          $B00_03,`$DATA_DISPL + (0 * 64)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B04_07,`$DATA_DISPL + (1 * 64)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B08_11,`$DATA_DISPL + (2 * 64)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B12_15,`$DATA_DISPL + (3 * 64)`($IA0,$DATA_OFFSET,1)

        # ;; =================================================
        # ;; shuffle cipher text blocks for GHASH computation
___
  if ($ENC_DEC eq "ENC") {
    $code .= <<___;
        vpshufb           $SHFMSK,$B00_03,$B00_03
        vpshufb           $SHFMSK,$B04_07,$B04_07
        vpshufb           $SHFMSK,$B08_11,$B08_11
        vpshufb           $SHFMSK,$B12_15,$B12_15
___
  } else {
    $code .= <<___;
        vpshufb           $SHFMSK,$DATA1,$B00_03
        vpshufb           $SHFMSK,$DATA2,$B04_07
        vpshufb           $SHFMSK,$DATA3,$B08_11
        vpshufb           $SHFMSK,$DATA4,$B12_15
___
  }
  $code .= <<___;
        # ;; =================================================
        # ;; store shuffled cipher text for ghashing
        vmovdqa64         $B00_03,`$AESOUT_BLK_OFFSET + (0*64)`(%rsp)
        vmovdqa64         $B04_07,`$AESOUT_BLK_OFFSET + (1*64)`(%rsp)
        vmovdqa64         $B08_11,`$AESOUT_BLK_OFFSET + (2*64)`(%rsp)
        vmovdqa64         $B12_15,`$AESOUT_BLK_OFFSET + (3*64)`(%rsp)
___
  if ($DO_REDUCTION eq "final_reduction") {

    # ;; =================================================
    # ;; Return GHASH value  through $GH1H
  }
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; GHASH the last 8 ciphertext blocks.
# ;;; - optionally accepts GHASH product sums as input
sub GHASH_LAST_8 {
  my $GCM128_CTX = $_[0];     # [in] context pointer
  my $BL47       = $_[1];     # [in/clobbered] ZMM AES blocks 4 to 7
  my $BL03       = $_[2];     # [in/cloberred] ZMM AES blocks 0 to 3
  my $ZTH        = $_[3];     # [cloberred] ZMM temporary
  my $ZTM        = $_[4];     # [cloberred] ZMM temporary
  my $ZTL        = $_[5];     # [cloberred] ZMM temporary
  my $ZT01       = $_[6];     # [cloberred] ZMM temporary
  my $ZT02       = $_[7];     # [cloberred] ZMM temporary
  my $ZT03       = $_[8];     # [cloberred] ZMM temporary
  my $AAD_HASH   = $_[9];     # [out] XMM hash value
  my $GH         = $_[10];    # [in/optional] ZMM with GHASH high product sum
  my $GL         = $_[11];    # [in/optional] ZMM with GHASH low product sum
  my $GM         = $_[12];    # [in/optional] ZMM with GHASH mid product sum

  &VCLMUL_STEP1($GCM128_CTX, $BL47, $ZT01, $ZTH, $ZTM, $ZTL);

  if (scalar(@_) > 10) {
    $code .= <<___;
        # ;; add optional sums before step2
        vpxorq            $GH,$ZTH,$ZTH
        vpxorq            $GL,$ZTL,$ZTL
        vpxorq            $GM,$ZTM,$ZTM
___
  }

  &VCLMUL_STEP2($GCM128_CTX, $BL47, $BL03, $ZT01, $ZT02, $ZT03, $ZTH, $ZTM, $ZTL);

  $code .= "vmovdqa64         POLY2(%rip),@{[XWORD($ZT03)]}\n";
  &VCLMUL_REDUCE($AAD_HASH, &XWORD($ZT03), &XWORD($BL47), &XWORD($BL03), &XWORD($ZT01), &XWORD($ZT02));
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; GHASH the last 7 cipher text blocks.
# ;;; - it uses same GHASH macros as GHASH_LAST_8 but with some twist
# ;;; - it loads GHASH keys for each of the data blocks, so that:
# ;;;     - blocks 4, 5 and 6 will use GHASH keys 3, 2, 1 respectively
# ;;;     - code ensures that unused block 7 and corresponding GHASH key are zeroed
# ;;;       (clmul product is zero this way and will not affect the result)
# ;;;     - blocks 0, 1, 2 and 3 will use USE GHASH keys 7, 6, 5 and 4 respectively
# ;;; - optionally accepts GHASH product sums as input
sub GHASH_LAST_7 {
  my $GCM128_CTX = $_[0];     # [in] key pointer
  my $BL47       = $_[1];     # [in/clobbered] ZMM AES blocks 4 to 7
  my $BL03       = $_[2];     # [in/cloberred] ZMM AES blocks 0 to 3
  my $ZTH        = $_[3];     # [cloberred] ZMM temporary
  my $ZTM        = $_[4];     # [cloberred] ZMM temporary
  my $ZTL        = $_[5];     # [cloberred] ZMM temporary
  my $ZT01       = $_[6];     # [cloberred] ZMM temporary
  my $ZT02       = $_[7];     # [cloberred] ZMM temporary
  my $ZT03       = $_[8];     # [cloberred] ZMM temporary
  my $ZT04       = $_[9];     # [cloberred] ZMM temporary
  my $AAD_HASH   = $_[10];    # [out] XMM hash value
  my $MASKREG    = $_[11];    # [clobbered] mask register to use for loads
  my $IA0        = $_[12];    # [clobbered] GP temporary register
  my $GH         = $_[13];    # [in/optional] ZMM with GHASH high product sum
  my $GL         = $_[14];    # [in/optional] ZMM with GHASH low product sum
  my $GM         = $_[15];    # [in/optional] ZMM with GHASH mid product sum

  $code .= "vmovdqa64         POLY2(%rip),@{[XWORD($ZT04)]}\n";

  &VCLMUL_1_TO_8_STEP1($GCM128_CTX, $BL47, $ZT01, $ZT02, $ZTH, $ZTM, $ZTL, 7);

  if (scalar(@_) > 13) {
    $code .= <<___;
        # ;; add optional sums before step2
        vpxorq            $GH,$ZTH,$ZTH
        vpxorq            $GL,$ZTL,$ZTL
        vpxorq            $GM,$ZTM,$ZTM
___
  }
  &VCLMUL_1_TO_8_STEP2($GCM128_CTX, $BL47, $BL03, $ZT01, $ZT02, $ZT03, $ZTH, $ZTM, $ZTL, 7);
  &VCLMUL_REDUCE($AAD_HASH, &XWORD($ZT04), &XWORD($BL47), &XWORD($BL03), &XWORD($ZT01), &XWORD($ZT02));
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Encryption of a single block
sub ENCRYPT_SINGLE_BLOCK {
  my $AES_KEY = $_[0];    # ; [in]
  my $XMM0    = $_[1];    # ; [in/out]
  my $GPR1    = $_[2];    # ; [clobbered]

  $code .= <<___;
        # ; load number of rounds from AES_KEY structure (offset in bytes is
        # ; size of the |rd_key| buffer)
        mov             `4*15*4`($AES_KEY),@{[DWORD($GPR1)]}
        cmp             \$9,@{[DWORD($GPR1)]}
        je              .Laes_128
        cmp             \$11,@{[DWORD($GPR1)]}
        je              .Laes_192
        cmp             \$13,@{[DWORD($GPR1)]}
        je              .Laes_256
        jmp             .Lexit_aes
___
  for my $keylen (sort keys %aes_rounds) {
    my $nr = $aes_rounds{$keylen};
    $code .= <<___;
.align 32
.Laes_${keylen}:
___
    $code .= "vpxorq          `16*0`($AES_KEY),$XMM0, $XMM0\n";
    for (my $i = 1; $i <= $nr; $i++) {
      $code .= "vaesenc         `16*$i`($AES_KEY),$XMM0,$XMM0\n";
    }
    $code .= <<___;
        vaesenclast     `16*($nr+1)`($AES_KEY),$XMM0,$XMM0
        jmp .Lexit_aes
___
  }
  $code .= ".Lexit_aes:\n";
}

sub CALC_J0 {
  my $GCM128_CTX = $_[0];     #; [in] Pointer to GCM context
  my $IV         = $_[1];     #; [in] Pointer to IV
  my $IV_LEN     = $_[2];     #; [in] IV length
  my $J0         = $_[3];     #; [out] XMM reg to contain J0
  my $ZT0        = $_[4];     #; [clobbered] ZMM register
  my $ZT1        = $_[5];     #; [clobbered] ZMM register
  my $ZT2        = $_[6];     #; [clobbered] ZMM register
  my $ZT3        = $_[7];     #; [clobbered] ZMM register
  my $ZT4        = $_[8];     #; [clobbered] ZMM register
  my $ZT5        = $_[9];     #; [clobbered] ZMM register
  my $ZT6        = $_[10];    #; [clobbered] ZMM register
  my $ZT7        = $_[11];    #; [clobbered] ZMM register
  my $ZT8        = $_[12];    #; [clobbered] ZMM register
  my $ZT9        = $_[13];    #; [clobbered] ZMM register
  my $ZT10       = $_[14];    #; [clobbered] ZMM register
  my $ZT11       = $_[15];    #; [clobbered] ZMM register
  my $ZT12       = $_[16];    #; [clobbered] ZMM register
  my $ZT13       = $_[17];    #; [clobbered] ZMM register
  my $ZT14       = $_[18];    #; [clobbered] ZMM register
  my $ZT15       = $_[19];    #; [clobbered] ZMM register
  my $ZT16       = $_[20];    #; [clobbered] ZMM register
  my $ZT17       = $_[21];    #; [clobbered] ZMM register
  my $T1         = $_[22];    #; [clobbered] GP register
  my $T2         = $_[23];    #; [clobbered] GP register
  my $T3         = $_[24];    #; [clobbered] GP register
  my $MASKREG    = $_[25];    #; [clobbered] mask register

  my $POLY = $ZT8;
  my $TH   = $ZT7;
  my $TM   = $ZT6;
  my $TL   = $ZT5;

  # ;; J0 = GHASH(IV || 0s+64 || len(IV)64)
  # ;; s = 16 * RoundUp(len(IV)/16) -  len(IV) */

  # ;; Calculate GHASH of (IV || 0s)
  $code .= "vpxor             $J0,$J0,$J0\n";

  # ;; Get Htable pointer
  $code .= "lea               `$CTX_OFFSET_HTable`($GCM128_CTX),%r13\n";
  &CALC_AAD_HASH(
    $IV,  $IV_LEN, $J0,   "%r13", $ZT0,  $ZT1,  $ZT2,  $ZT3,  $ZT4,  $ZT5, $ZT6, $ZT7, $ZT8,
    $ZT9, $ZT10,   $ZT11, $ZT12,  $ZT13, $ZT14, $ZT15, $ZT16, $ZT17, $T1,  $T2,  $T3,  $MASKREG);

  $code .= <<___;
        # ;; Calculate GHASH of last 16-byte block (0 || len(IV)64)
        mov               $IV_LEN,$T1
        shl               \$3,$T1                 # ;; IV length in bits
        vmovq             $T1,@{[XWORD($ZT2)]}
        # ;; Might need shuffle of ZT2
        vpxorq            @{[ZWORD($J0)]},$ZT2,$ZT2
___
  &VCLMUL_1_TO_8_STEP1($GCM128_CTX, $ZT1, $ZT0, $ZT3, $TH, $TM, $TL, 1);
  &VCLMUL_1_TO_8_STEP2($GCM128_CTX, $ZT1, $ZT2, $ZT0, $ZT3, $ZT4, $TH, $TM, $TL, 1);

  # ;; Multiplications have been done. Do the reduction now
  $code .= "vmovdqa64         POLY2(%rip),@{[XWORD($POLY)]}\n";
  &VCLMUL_REDUCE($J0, &XWORD($POLY), &XWORD($ZT1), &XWORD($ZT2), &XWORD($ZT0), &XWORD($ZT3));
  $code .= "vpshufb           SHUF_MASK(%rip),$J0,$J0    # ; perform a 16Byte swap\n";
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; GCM_INIT_IV performs an initialization of gcm128_ctx struct to prepare for
# ;;; encoding/decoding.
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub GCM_INIT_IV {
  my $AES_KEY    = $_[0];     # [in] pointer to AES key schedule
  my $GCM128_CTX = $_[1];     # [in/out] GCM context
  my $IV         = $_[2];     # [in] IV pointer
  my $IV_LEN     = $_[3];     # [in] IV length
  my $GPR1       = $_[4];     # [clobbered] GP register
  my $GPR2       = $_[5];     # [clobbered] GP register
  my $GPR3       = $_[6];     # [clobbered] GP register
  my $MASKREG    = $_[7];     # [clobbered] mask register
  my $CUR_COUNT  = $_[8];     # [out] XMM with current counter (xmm2)
  my $ZT0        = $_[9];     # [clobbered] ZMM register
  my $ZT1        = $_[10];    # [clobbered] ZMM register
  my $ZT2        = $_[11];    # [clobbered] ZMM register
  my $ZT3        = $_[12];    # [clobbered] ZMM register
  my $ZT4        = $_[13];    # [clobbered] ZMM register
  my $ZT5        = $_[14];    # [clobbered] ZMM register
  my $ZT6        = $_[15];    # [clobbered] ZMM register
  my $ZT7        = $_[16];    # [clobbered] ZMM register
  my $ZT8        = $_[17];    # [clobbered] ZMM register
  my $ZT9        = $_[18];    # [clobbered] ZMM register
  my $ZT10       = $_[19];    # [clobbered] ZMM register
  my $ZT11       = $_[20];    # [clobbered] ZMM register
  my $ZT12       = $_[21];    # [clobbered] ZMM register
  my $ZT13       = $_[22];    # [clobbered] ZMM register
  my $ZT14       = $_[23];    # [clobbered] ZMM register
  my $ZT15       = $_[24];    # [clobbered] ZMM register
  my $ZT16       = $_[25];    # [clobbered] ZMM register
  my $ZT17       = $_[26];    # [clobbered] ZMM register

  my $ZT0x = $ZT0;
  $ZT0x =~ s/zmm/xmm/;

  $code .= <<___;
        cmp     \$12,$IV_LEN
        je      iv_len_12_init_IV
___

  # ;; IV is different than 12 bytes
  &CALC_J0($GCM128_CTX, $IV, $IV_LEN, $CUR_COUNT, $ZT0, $ZT1, $ZT2, $ZT3, $ZT4, $ZT5, $ZT6, $ZT7,
    $ZT8, $ZT9, $ZT10, $ZT11, $ZT12, $ZT13, $ZT14, $ZT15, $ZT16, $ZT17, $GPR1, $GPR2, $GPR3, $MASKREG);
  $code .= <<___;
       jmp      skip_iv_len_12_init_IV
iv_len_12_init_IV:   # ;; IV is 12 bytes
        # ;; read 12 IV bytes and pad with 0x00000001
        vmovdqu8          ONEf(%rip),$CUR_COUNT
        mov               $IV,$GPR2
        mov               \$0x0000000000000fff,@{[DWORD($GPR1)]}
        kmovq             $GPR1,$MASKREG
        vmovdqu8          ($GPR2),${CUR_COUNT}{$MASKREG}         # ; ctr = IV | 0x1
skip_iv_len_12_init_IV:
        vmovdqu           $CUR_COUNT,$ZT0x
___
  &ENCRYPT_SINGLE_BLOCK($AES_KEY, "$ZT0x", "$GPR1");    # ; E(K, Y0)
  $code .= <<___;
        vmovdqu           $ZT0x,`$CTX_OFFSET_EK0`($GCM128_CTX)   # ; save EK0 for finalization stage

        # ;; store IV as counter in LE format
        vpshufb           SHUF_MASK(%rip),$CUR_COUNT,$CUR_COUNT
        vmovdqu           $CUR_COUNT,`$CTX_OFFSET_CurCount`($GCM128_CTX)    # ; save current counter Yi
___
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Cipher and ghash of payloads shorter than 256 bytes
# ;;; - number of blocks in the message comes as argument
# ;;; - depending on the number of blocks an optimized variant of
# ;;;   INITIAL_BLOCKS_PARTIAL is invoked
sub GCM_ENC_DEC_SMALL {
  my $AES_EXPKEYS    = $_[0];     # [in] key pointer
  my $GCM128_CTX     = $_[1];     # [in] context pointer
  my $CYPH_PLAIN_OUT = $_[2];     # [in] output buffer
  my $PLAIN_CYPH_IN  = $_[3];     # [in] input buffer
  my $PLAIN_CYPH_LEN = $_[4];     # [in] buffer length
  my $ENC_DEC        = $_[5];     # [in] cipher direction
  my $DATA_OFFSET    = $_[6];     # [in] data offset
  my $LENGTH         = $_[7];     # [in] data length
  my $NUM_BLOCKS     = $_[8];     # [in] number of blocks to process 1 to 16
  my $CTR            = $_[9];     # [in/out] XMM counter block
  my $HASH_IN_OUT    = $_[10];    # [in/out] XMM GHASH value
  my $INSTANCE_TYPE  = $_[11];    # [in] single or multi call
  my $ZTMP0          = $_[12];    # [clobbered] ZMM register
  my $ZTMP1          = $_[13];    # [clobbered] ZMM register
  my $ZTMP2          = $_[14];    # [clobbered] ZMM register
  my $ZTMP3          = $_[15];    # [clobbered] ZMM register
  my $ZTMP4          = $_[16];    # [clobbered] ZMM register
  my $ZTMP5          = $_[17];    # [clobbered] ZMM register
  my $ZTMP6          = $_[18];    # [clobbered] ZMM register
  my $ZTMP7          = $_[19];    # [clobbered] ZMM register
  my $ZTMP8          = $_[20];    # [clobbered] ZMM register
  my $ZTMP9          = $_[21];    # [clobbered] ZMM register
  my $ZTMP10         = $_[22];    # [clobbered] ZMM register
  my $ZTMP11         = $_[23];    # [clobbered] ZMM register
  my $ZTMP12         = $_[24];    # [clobbered] ZMM register
  my $ZTMP13         = $_[25];    # [clobbered] ZMM register
  my $ZTMP14         = $_[26];    # [clobbered] ZMM register
  my $ZTMP15         = $_[27];    # [clobbered] ZMM register
  my $ZTMP16         = $_[28];    # [clobbered] ZMM register
  my $ZTMP17         = $_[29];    # [clobbered] ZMM register
  my $ZTMP18         = $_[30];    # [clobbered] ZMM register
  my $ZTMP19         = $_[31];    # [clobbered] ZMM register
  my $ZTMP20         = $_[32];    # [clobbered] ZMM register
  my $ZTMP21         = $_[33];    # [clobbered] ZMM register
  my $ZTMP22         = $_[34];    # [clobbered] ZMM register
  my $IA0            = $_[35];    # [clobbered] GP register
  my $IA1            = $_[36];    # [clobbered] GP register
  my $MASKREG        = $_[37];    # [clobbered] mask register
  my $SHUFMASK       = $_[38];    # [in] ZMM with BE/LE shuffle mask
  my $PBLOCK_LEN     = $_[39];    # [in] partial block length
  my $HKEYS_READY    = $_[40];    # [in/out]

  my $rndsuffix = &random_string();

  $code .= <<___;
        cmp               \$8,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_8_${rndsuffix}
        jl            .L_small_initial_num_blocks_is_7_1_${rndsuffix}


        cmp               \$12,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_12_${rndsuffix}
        jl            .L_small_initial_num_blocks_is_11_9_${rndsuffix}

        # ;; 16, 15, 14 or 13
        cmp               \$16,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_16_${rndsuffix}
        cmp               \$15,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_15_${rndsuffix}
        cmp               \$14,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_14_${rndsuffix}
        jmp           .L_small_initial_num_blocks_is_13_${rndsuffix}

.L_small_initial_num_blocks_is_11_9_${rndsuffix}:
        # ;; 11, 10 or 9
        cmp               \$11,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_11_${rndsuffix}
        cmp               \$10,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_10_${rndsuffix}
        jmp           .L_small_initial_num_blocks_is_9_${rndsuffix}

.L_small_initial_num_blocks_is_7_1_${rndsuffix}:
        cmp               \$4,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_4_${rndsuffix}
        jl            .L_small_initial_num_blocks_is_3_1_${rndsuffix}
        # ;; 7, 6 or 5
        cmp               \$7,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_7_${rndsuffix}
        cmp               \$6,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_6_${rndsuffix}
        jmp           .L_small_initial_num_blocks_is_5_${rndsuffix}

.L_small_initial_num_blocks_is_3_1_${rndsuffix}:
        # ;; 3, 2 or 1
        cmp               \$3,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_3_${rndsuffix}
        cmp               \$2,$NUM_BLOCKS
        je            .L_small_initial_num_blocks_is_2_${rndsuffix}

        # ;; for $NUM_BLOCKS == 1, just fall through and no 'jmp' needed

        # ;; Generation of different block size variants
        # ;; - one block size has to be the first one
___

  for (my $num_blocks = 1; $num_blocks <= 16; $num_blocks++) {
    $code .= ".L_small_initial_num_blocks_is_${num_blocks}_${rndsuffix}:\n";
    &INITIAL_BLOCKS_PARTIAL(
      $AES_EXPKEYS, $GCM128_CTX, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN, $LENGTH,        $DATA_OFFSET,
      $num_blocks,  $CTR,        $HASH_IN_OUT,    $ENC_DEC,       $INSTANCE_TYPE, $ZTMP0,
      $ZTMP1,       $ZTMP2,      $ZTMP3,          $ZTMP4,         $ZTMP5,         $ZTMP6,
      $ZTMP7,       $ZTMP8,      $ZTMP9,          $ZTMP10,        $ZTMP11,        $ZTMP12,
      $ZTMP13,      $ZTMP14,     $ZTMP15,         $ZTMP16,        $ZTMP17,        $ZTMP18,
      $ZTMP19,      $ZTMP20,     $ZTMP21,         $ZTMP22,        $IA0,           $IA1,
      $MASKREG,     $SHUFMASK,   $PBLOCK_LEN,     $HKEYS_READY);
    if ($num_blocks != 16) {
      $code .= "jmp           .L_small_initial_blocks_encrypted_${rndsuffix}\n";
    }
  }

  $code .= ".L_small_initial_blocks_encrypted_${rndsuffix}:\n";
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; GCM_ENC_DEC Encodes/Decodes given data. Assumes that the passed gcm128_context
# ; struct has been initialized by GCM_INIT_IV().
# ; Requires the input data be at least 1 byte long because of READ_SMALL_INPUT_DATA.
# ; Clobbers rax, r10-r15, and zmm0-zmm31, k1
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
sub GCM_ENC_DEC {
  my $AES_EXPKEYS    = $_[0];    # [in] AES Key schedule
  my $GCM128_CTX     = $_[1];    # [in] context pointer
  my $PBLOCK_LEN     = $_[2];    # [in] length of partial block at the moment of previous update
  my $PLAIN_CYPH_IN  = $_[3];    # [in] input buffer pointer
  my $PLAIN_CYPH_LEN = $_[4];    # [in] buffer length
  my $CYPH_PLAIN_OUT = $_[5];    # [in] output buffer pointer
  my $ENC_DEC        = $_[6];    # [in] cipher direction
  my $INSTANCE_TYPE  = $_[7];    # [in] 'single_call' or 'multi_call' selection

  my $IA0 = "%r10";
  my $IA1 = "%r12";
  my $IA2 = "%r13";
  my $IA3 = "%r15";
  my $IA4 = "%r11";
  my $IA5 = "%rax";
  my $IA6 = "%rbx";

  my $LENGTH      = $IA2;
  my $CTR_CHECK   = $IA3;
  my $DATA_OFFSET = $IA4;

  my $HASHK_PTR = $IA5;

  my $HKEYS_READY = $IA6;

  my $GCM_INIT_CTR_BLOCK = "%xmm2";    # ; hardcoded in GCM_INIT for now

  my $AES_PARTIAL_BLOCK = "%xmm8";
  my $CTR_BLOCK2z       = "%zmm18";
  my $CTR_BLOCKz        = "%zmm9";
  my $CTR_BLOCKx        = "%xmm9";
  my $AAD_HASHz         = "%zmm14";
  my $AAD_HASHx         = "%xmm14";

  # ;;; ZTMP0 - ZTMP12 - used in by8 code, by48 code and GCM_ENC_DEC_SMALL
  my $ZTMP0  = "%zmm0";
  my $ZTMP1  = "%zmm3";
  my $ZTMP2  = "%zmm4";
  my $ZTMP3  = "%zmm5";
  my $ZTMP4  = "%zmm6";
  my $ZTMP5  = "%zmm7";
  my $ZTMP6  = "%zmm10";
  my $ZTMP7  = "%zmm11";
  my $ZTMP8  = "%zmm12";
  my $ZTMP9  = "%zmm13";
  my $ZTMP10 = "%zmm15";
  my $ZTMP11 = "%zmm16";
  my $ZTMP12 = "%zmm17";

  # ;;; ZTMP13 - ZTMP22 - used in by48 code and GCM_ENC_DEC_SMALL
  # ;;; - some used by8 code as well through TMPxy names
  my $ZTMP13 = "%zmm19";
  my $ZTMP14 = "%zmm20";
  my $ZTMP15 = "%zmm21";
  my $ZTMP16 = "%zmm30";

  # ; can be used in big_loop part
  my $ZTMP17 = "%zmm31";

  # ; can be used in big_loop part
  my $ZTMP18 = "%zmm1";
  my $ZTMP19 = "%zmm2";
  my $ZTMP20 = "%zmm8";
  my $ZTMP21 = "%zmm22";
  my $ZTMP22 = "%zmm23";

  # ;;; Free to use: zmm24 - zmm29
  # ;;; - used by by48 and by8
  my $GH             = "%zmm24";
  my $GL             = "%zmm25";
  my $GM             = "%zmm26";
  my $SHUF_MASK      = "%zmm29";
  my $CTR_BLOCK_SAVE = "%zmm28";

  # ;;; - used by by48 code only
  my $ADDBE_4x4  = "%zmm27";
  my $ADDBE_1234 = "%zmm28";

  # ; conflicts with CTR_BLOCK_SAVE

  # ;; used by8 code only
  my $GH4KEY = $ZTMP17;
  my $GH8KEY = $ZTMP16;
  my $BLK0   = $ZTMP18;
  my $BLK1   = $ZTMP19;
  my $ADD8BE = "%zmm27";
  my $ADD8LE = $ZTMP13;

  my $MASKREG = "%k1";

  my $rndsuffix = &random_string();

  # ;; reduction every 48 blocks, depth 32 blocks
  # ;; @note 48 blocks is the maximum capacity of the stack frame
  my $big_loop_nblocks = 48;
  my $big_loop_depth   = 32;

  # ;;; Macro flow:
  # ;;; - for message size bigger than big_loop_nblocks process data
  # ;;;   with "big_loop" parameters
  # ;;; - calculate the number of 16byte blocks in the message
  # ;;; - process (number of 16byte blocks) mod 8
  # ;;;   '.L_initial_num_blocks_is_#_${rndsuffix}# .. .L_initial_blocks_encrypted_${rndsuffix}'
  # ;;; - process 8 16 byte blocks at a time until all are done in .L_encrypt_by_8_new_${rndsuffix}

  if ($win64) {
    $code .= "cmpq            \$0,$PLAIN_CYPH_LEN\n";
  } else {
    $code .= "or              $PLAIN_CYPH_LEN, $PLAIN_CYPH_LEN\n";
  }
  $code .= <<___;
        je            .L_enc_dec_abort_${rndsuffix}

        xor             $HKEYS_READY, $HKEYS_READY
        xor             $DATA_OFFSET, $DATA_OFFSET

        # ;; Update length of data processed
        vmovdqu64         `$CTX_OFFSET_AadHash`($GCM128_CTX),$AAD_HASHx
        # BE -> LE conversion
        vpshufb           SHUF_MASK(%rip),$AAD_HASHx,$AAD_HASHx
___
  if ($INSTANCE_TYPE eq "multi_call") {

    # ;; NOTE: partial block processing makes only sense for multi_call here.
    # ;; Used for the update flow - if there was a previous partial
    # ;; block fill the remaining bytes here.
    &PARTIAL_BLOCK(
      $GCM128_CTX, $PBLOCK_LEN, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN, $PLAIN_CYPH_LEN, $DATA_OFFSET,
      $AAD_HASHx,  $ENC_DEC,    $IA0,            $IA1,           $IA2,            $ZTMP0,
      $ZTMP1,      $ZTMP2,      $ZTMP3,          $ZTMP4,         $ZTMP5,          $ZTMP6,
      $ZTMP7,      $ZTMP8,      $ZTMP9,          $MASKREG);
  }

  # ;;  lift counter block from GCM_INIT to here
  if ($INSTANCE_TYPE eq "single_call") {
    $code .= "vmovdqu64         $GCM_INIT_CTR_BLOCK,$CTR_BLOCKx\n";
  } else {
    $code .= "vmovdqu64         `$CTX_OFFSET_CurCount`($GCM128_CTX),$CTR_BLOCKx\n";
  }

  # ;; Save the amount of data left to process in $LENGTH
  $code .= "mov               $PLAIN_CYPH_LEN,$LENGTH\n";
  if ($INSTANCE_TYPE eq "multi_call") {
    $code .= <<___;
        # ;; NOTE: $DATA_OFFSET is zero in single_call case.
        # ;;      Consequently PLAIN_CYPH_LEN will never be zero after
        # ;;      $DATA_OFFSET subtraction below.
        # ;; There may be no more data if it was consumed in the partial block.
        sub               $DATA_OFFSET,$LENGTH
        je            .L_enc_dec_done_${rndsuffix}
___
  }
  $code .= <<___;
        vmovdqa64         SHUF_MASK(%rip),$SHUF_MASK
        vmovdqa64         ddq_addbe_4444(%rip),$ADDBE_4x4

        cmp               \$`($big_loop_nblocks * 16)`,$LENGTH
jl            .L_message_below_big_nblocks_${rndsuffix}

        # ;; overwritten above by CTR_BLOCK_SAVE
        vmovdqa64         ddq_addbe_1234(%rip),$ADDBE_1234
___
  &INITIAL_BLOCKS_Nx16(
    $PLAIN_CYPH_IN, $CYPH_PLAIN_OUT,   $AES_EXPKEYS,    $DATA_OFFSET, $AAD_HASHz,  $CTR_BLOCKz,
    $CTR_CHECK,     $ZTMP0,            $ZTMP1,          $ZTMP2,       $ZTMP3,      $ZTMP4,
    $ZTMP5,         $ZTMP6,            $ZTMP7,          $ZTMP8,       $ZTMP9,      $ZTMP10,
    $ZTMP11,        $ZTMP12,           $ZTMP13,         $ZTMP14,      $ZTMP15,     $ZTMP16,
    $ZTMP17,        $ZTMP18,           $ZTMP19,         $ZTMP20,      $ZTMP21,     $ZTMP22,
    $GH,            $GL,               $GM,             $ADDBE_4x4,   $ADDBE_1234, $SHUF_MASK,
    $ENC_DEC,       $big_loop_nblocks, $big_loop_depth, $GCM128_CTX,  $IA0,        $HKEYS_READY);

  $code .= <<___;
        sub               \$`($big_loop_nblocks * 16)`,$LENGTH
        cmp               \$`($big_loop_nblocks * 16)`,$LENGTH
jl            .L_no_more_big_nblocks_${rndsuffix}

.L_encrypt_big_nblocks_${rndsuffix}:
___
  &GHASH_ENCRYPT_Nx16_PARALLEL(
    $PLAIN_CYPH_IN,    $CYPH_PLAIN_OUT, $AES_EXPKEYS, $DATA_OFFSET, $CTR_BLOCKz, $SHUF_MASK,
    $ZTMP0,            $ZTMP1,          $ZTMP2,       $ZTMP3,       $ZTMP4,      $ZTMP5,
    $ZTMP6,            $ZTMP7,          $ZTMP8,       $ZTMP9,       $ZTMP10,     $ZTMP11,
    $ZTMP12,           $ZTMP13,         $ZTMP14,      $ZTMP15,      $ZTMP16,     $ZTMP17,
    $ZTMP18,           $ZTMP19,         $ZTMP20,      $ZTMP21,      $ZTMP22,     $GH,
    $GL,               $GM,             $ADDBE_4x4,   $ADDBE_1234,  $AAD_HASHz,  $ENC_DEC,
    $big_loop_nblocks, $big_loop_depth, $CTR_CHECK,   $GCM128_CTX,  $IA0);
  $code .= <<___;
        sub               \$`($big_loop_nblocks * 16)`,$LENGTH
        cmp               \$`($big_loop_nblocks * 16)`,$LENGTH
jge           .L_encrypt_big_nblocks_${rndsuffix}

.L_no_more_big_nblocks_${rndsuffix}:
        vpshufb           @{[XWORD($SHUF_MASK)]},$CTR_BLOCKx,$CTR_BLOCKx
        vmovdqa64         $CTR_BLOCKx,@{[XWORD($CTR_BLOCK_SAVE)]}
___
  &GHASH_LAST_Nx16($GCM128_CTX, $AAD_HASHz, $ZTMP0, $ZTMP1, $ZTMP2,
    $ZTMP3, $ZTMP4, $ZTMP5, $ZTMP6, $ZTMP7, $ZTMP8, $ZTMP9, $ZTMP10,
    $ZTMP11, $ZTMP12, $ZTMP13, $ZTMP14, $ZTMP15, $GH, $GL, $GM, $big_loop_nblocks, $big_loop_depth);
  $code .= <<___;
        or              $LENGTH, $LENGTH
        jz            .L_ghash_done_${rndsuffix}

.L_message_below_big_nblocks_${rndsuffix}:

        # ;; Less than 256 bytes will be handled by the small message code, which
        # ;; can process up to 16 x blocks (16 bytes each)
        cmp               \$`(16 * 16)`,$LENGTH
jg            .L_large_message_path_${rndsuffix}

        # ;; Determine how many blocks to process
        # ;; - process one additional block if there is a partial block
        mov               $LENGTH,$IA1
        add               \$15,$IA1
        shr               \$4,$IA1
        # ;; $IA1 can be in the range from 0 to 16
___
  &GCM_ENC_DEC_SMALL(
    $AES_EXPKEYS, $GCM128_CTX, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN, $PLAIN_CYPH_LEN, $ENC_DEC,
    $DATA_OFFSET, $LENGTH,     $IA1,            $CTR_BLOCKx,    $AAD_HASHx,      $INSTANCE_TYPE,
    $ZTMP0,       $ZTMP1,      $ZTMP2,          $ZTMP3,         $ZTMP4,          $ZTMP5,
    $ZTMP6,       $ZTMP7,      $ZTMP8,          $ZTMP9,         $ZTMP10,         $ZTMP11,
    $ZTMP12,      $ZTMP13,     $ZTMP14,         $ZTMP15,        $ZTMP16,         $ZTMP17,
    $ZTMP18,      $ZTMP19,     $ZTMP20,         $ZTMP21,        $ZTMP22,         $IA0,
    $IA3,         $MASKREG,    $SHUF_MASK,      $PBLOCK_LEN,    $HKEYS_READY);
  $code .= <<___;
        vmovdqa64         $CTR_BLOCKx,@{[XWORD($CTR_BLOCK_SAVE)]}

        jmp           .L_ghash_done_${rndsuffix}

.L_large_message_path_${rndsuffix}:
        # ;; Determine how many blocks to process in INITIAL
        # ;; - process one additional block in INITIAL if there is a partial block
        mov               $LENGTH,$IA1
        and               \$0xff,$IA1
        add               \$15,$IA1
        shr               \$4,$IA1
        # ;; Don't allow 8 INITIAL blocks since this will
        # ;; be handled by the x8 partial loop.
        and               \$7,$IA1
        je            .L_initial_num_blocks_is_0_${rndsuffix}
        cmp               \$1,$IA1
        je            .L_initial_num_blocks_is_1_${rndsuffix}
        cmp               \$2,$IA1
        je            .L_initial_num_blocks_is_2_${rndsuffix}
        cmp               \$3,$IA1
        je            .L_initial_num_blocks_is_3_${rndsuffix}
        cmp               \$4,$IA1
        je            .L_initial_num_blocks_is_4_${rndsuffix}
        cmp               \$5,$IA1
        je            .L_initial_num_blocks_is_5_${rndsuffix}
        cmp               \$6,$IA1
        je            .L_initial_num_blocks_is_6_${rndsuffix}
___

  foreach (my $number_of_blocks = 7; $number_of_blocks >= 0; $number_of_blocks--) {
    $code .= ".L_initial_num_blocks_is_${number_of_blocks}_${rndsuffix}:\n";
    &INITIAL_BLOCKS(
      $AES_EXPKEYS,      $GCM128_CTX, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN, $LENGTH,            $DATA_OFFSET,
      $number_of_blocks, $CTR_BLOCKx, $AAD_HASHz,      $ZTMP0,         $ZTMP1,             $ZTMP2,
      $ZTMP3,            $ZTMP4,      $ZTMP5,          $ZTMP6,         $ZTMP7,             $ZTMP8,
      $ZTMP9,            $ZTMP10,     $ZTMP11,         $ZTMP12,        $ZTMP13,            $ZTMP14,
      $ZTMP15,           $ZTMP16,     $ZTMP17,         $ZTMP18,        $ZTMP19,            $IA0,
      $IA1,              $ENC_DEC,    $MASKREG,        $SHUF_MASK,     "no_partial_block", $PBLOCK_LEN,
      $HKEYS_READY);
    if ($number_of_blocks != 0) {
      $code .= "jmp           .L_initial_blocks_encrypted_${rndsuffix}\n";
    }
  }

  $code .= <<___;
.L_initial_blocks_encrypted_${rndsuffix}:
        vmovdqa64         $CTR_BLOCKx,@{[XWORD($CTR_BLOCK_SAVE)]}

        # ;; move cipher blocks from initial blocks to input of by8 macro
        # ;; and for GHASH_LAST_8/7
        # ;; - ghash value already xor'ed into block 0
        vmovdqa64         $ZTMP0,$BLK0
        vmovdqa64         $ZTMP1,$BLK1

        # ;; The entire message cannot get processed in INITIAL_BLOCKS
        # ;; - GCM_ENC_DEC_SMALL handles up to 16 blocks
        # ;; - INITIAL_BLOCKS processes up to 15 blocks
        # ;; - no need to check for zero length at this stage

        # ;; In order to have only one reduction at the end
        # ;; start HASH KEY pointer needs to be determined based on length and
        # ;; call type.
        # ;; - note that 8 blocks are already ciphered in INITIAL_BLOCKS and
        # ;;   subtracted from LENGTH
        lea               `(8 * 16)`($LENGTH),$IA1
        add               \$15,$IA1
        and               \$0x3f0,$IA1
___
  if ($INSTANCE_TYPE eq "multi_call") {
    $code .= <<___;
        # ;; if partial block and multi_call then change hash key start by one
        mov               $LENGTH,$IA0
        and               \$15,$IA0
        add               \$15,$IA0
        and               \$16,$IA0
        sub               $IA0,$IA1
___
  }
  $code .= <<___;
        lea               @{[HashKeyByIdx(1,"%rsp",16)]},$HASHK_PTR
        sub               $IA1,$HASHK_PTR
        # ;; HASHK_PTR
        # ;; - points at the first hash key to start GHASH with
        # ;; - needs to be updated as the message is processed (incremented)

        # ;; pre-load constants
        vmovdqa64         ddq_addbe_8888(%rip),$ADD8BE
        vmovdqa64         ddq_add_8888(%rip),$ADD8LE
        vpxorq            $GH,$GH,$GH
        vpxorq            $GL,$GL,$GL
        vpxorq            $GM,$GM,$GM

        # ;; prepare counter 8 blocks
        vshufi64x2        \$0,$CTR_BLOCKz,$CTR_BLOCKz,$CTR_BLOCKz
        vpaddd            ddq_add_5678(%rip),$CTR_BLOCKz,$CTR_BLOCK2z
        vpaddd            ddq_add_1234(%rip),$CTR_BLOCKz,$CTR_BLOCKz
        vpshufb           $SHUF_MASK,$CTR_BLOCKz,$CTR_BLOCKz
        vpshufb           $SHUF_MASK,$CTR_BLOCK2z,$CTR_BLOCK2z

        # ;; Process 7 full blocks plus a partial block
        cmp               \$128,$LENGTH
        jl            .L_encrypt_by_8_partial_${rndsuffix}

.L_encrypt_by_8_parallel_${rndsuffix}:
        # ;; in_order vs. out_order is an optimization to increment the counter
        # ;; without shuffling it back into little endian.
        # ;; $CTR_CHECK keeps track of when we need to increment in order so
        # ;; that the carry is handled correctly.

        vmovq             @{[XWORD($CTR_BLOCK_SAVE)]},$CTR_CHECK

.L_encrypt_by_8_new_${rndsuffix}:
        andw              \$255,@{[WORD($CTR_CHECK)]},
        addw              \$8,@{[WORD($CTR_CHECK)]},
        vmovdqu64         `(4 * 16)`($HASHK_PTR),$GH4KEY
        vmovdqu64         `(0 * 16)`($HASHK_PTR),$GH8KEY
___
  &GHASH_8_ENCRYPT_8_PARALLEL(
    $AES_EXPKEYS, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN,     $DATA_OFFSET,   $CTR_BLOCKz, $CTR_BLOCK2z,
    $BLK0,        $BLK1,           $AES_PARTIAL_BLOCK, "out_order",    $ENC_DEC,    "full",
    $IA0,         $IA1,            $LENGTH,            $INSTANCE_TYPE, $GH4KEY,     $GH8KEY,
    $SHUF_MASK,   $ZTMP0,          $ZTMP1,             $ZTMP2,         $ZTMP3,      $ZTMP4,
    $ZTMP5,       $ZTMP6,          $ZTMP7,             $ZTMP8,         $ZTMP9,      $ZTMP10,
    $ZTMP11,      $ZTMP12,         $MASKREG,           "no_reduction", $GL,         $GH,
    $GM);
  $code .= <<___;
        add               \$`(8 * 16)`,$HASHK_PTR
        add               \$128,$DATA_OFFSET
        sub               \$128,$LENGTH
        jz            .L_encrypt_done_${rndsuffix}

        cmpw              \$`(256 - 8)`,@{[WORD($CTR_CHECK)]}
        jae           .L_encrypt_by_8_${rndsuffix}

        vpaddd            $ADD8BE,$CTR_BLOCKz,$CTR_BLOCKz
        vpaddd            $ADD8BE,$CTR_BLOCK2z,$CTR_BLOCK2z

        cmp               \$128,$LENGTH
        jl            .L_encrypt_by_8_partial_${rndsuffix}

        jmp           .L_encrypt_by_8_new_${rndsuffix}

.L_encrypt_by_8_${rndsuffix}:
        vpshufb           $SHUF_MASK,$CTR_BLOCKz,$CTR_BLOCKz
        vpshufb           $SHUF_MASK,$CTR_BLOCK2z,$CTR_BLOCK2z
        vpaddd            $ADD8LE,$CTR_BLOCKz,$CTR_BLOCKz
        vpaddd            $ADD8LE,$CTR_BLOCK2z,$CTR_BLOCK2z
        vpshufb           $SHUF_MASK,$CTR_BLOCKz,$CTR_BLOCKz
        vpshufb           $SHUF_MASK,$CTR_BLOCK2z,$CTR_BLOCK2z

        cmp               \$128,$LENGTH
        jge           .L_encrypt_by_8_new_${rndsuffix}

.L_encrypt_by_8_partial_${rndsuffix}:
        # ;; Test to see if we need a by 8 with partial block. At this point
        # ;; bytes remaining should be either zero or between 113-127.
        # ;; 'in_order' shuffle needed to align key for partial block xor.
        # ;; 'out_order' is a little faster because it avoids extra shuffles.
        # ;;  - counter blocks for the next 8 blocks are prepared and in BE format
        # ;;  - we can go ahead with out_order scenario

        vmovdqu64         `(4 * 16)`($HASHK_PTR),$GH4KEY
        vmovdqu64         `(0 * 16)`($HASHK_PTR),$GH8KEY
___
  &GHASH_8_ENCRYPT_8_PARALLEL(
    $AES_EXPKEYS, $CYPH_PLAIN_OUT, $PLAIN_CYPH_IN,     $DATA_OFFSET,   $CTR_BLOCKz, $CTR_BLOCK2z,
    $BLK0,        $BLK1,           $AES_PARTIAL_BLOCK, "out_order",    $ENC_DEC,    "partial",
    $IA0,         $IA1,            $LENGTH,            $INSTANCE_TYPE, $GH4KEY,     $GH8KEY,
    $SHUF_MASK,   $ZTMP0,          $ZTMP1,             $ZTMP2,         $ZTMP3,      $ZTMP4,
    $ZTMP5,       $ZTMP6,          $ZTMP7,             $ZTMP8,         $ZTMP9,      $ZTMP10,
    $ZTMP11,      $ZTMP12,         $MASKREG,           "no_reduction", $GL,         $GH,
    $GM);
  $code .= <<___;
        add               \$`(8 * 16)`,$HASHK_PTR
        add               \$`(128 - 16)`,$DATA_OFFSET
        sub               \$`(128 - 16)`,$LENGTH
___
  if ($INSTANCE_TYPE eq "multi_call") {
    $code .= <<___;
        mov               $LENGTH,($PBLOCK_LEN)
        vmovdqu64         $AES_PARTIAL_BLOCK,$CTX_OFFSET_PEncBlock($GCM128_CTX)
___
  }
  $code .= <<___;
.L_encrypt_done_${rndsuffix}:
        # ;; Extract the last counter block in LE format
        vextracti32x4     \$3,$CTR_BLOCK2z,@{[XWORD($CTR_BLOCK_SAVE)]}
        vpshufb           @{[XWORD($SHUF_MASK)]},@{[XWORD($CTR_BLOCK_SAVE)]},@{[XWORD($CTR_BLOCK_SAVE)]}

        # ;; GHASH last cipher text blocks in xmm1-xmm8
        # ;; - if block 8th is partial in a multi-call path then skip the block
___
  if ($INSTANCE_TYPE eq "multi_call") {
    $code .= <<___;
        cmpq           \$0,($PBLOCK_LEN)
        jz            .L_hash_last_8_${rndsuffix}

        # ;; save the 8th partial block as GHASH_LAST_7 will clobber $BLK1
        vextracti32x4     \$3,$BLK1,@{[XWORD($ZTMP7)]}
___
    &GHASH_LAST_7(
      $GCM128_CTX, $BLK1,  $BLK0,      $ZTMP0,   $ZTMP1, $ZTMP2, $ZTMP3, $ZTMP4,
      $ZTMP5,      $ZTMP6, $AAD_HASHx, $MASKREG, $IA0,   $GH,    $GL,    $GM);
    $code .= <<___;
        # ;; XOR the partial word into the hash
        vpxorq            @{[XWORD($ZTMP7)]},$AAD_HASHx,$AAD_HASHx
        jmp           .L_ghash_done_${rndsuffix}
.L_hash_last_8_${rndsuffix}:
___
  }
  &GHASH_LAST_8($GCM128_CTX, $BLK1, $BLK0, $ZTMP0, $ZTMP1, $ZTMP2, $ZTMP3, $ZTMP4, $ZTMP5, $AAD_HASHx, $GH, $GL, $GM);
  $code .= <<___;
.L_ghash_done_${rndsuffix}:
        vmovdqu64         @{[XWORD($CTR_BLOCK_SAVE)]},`$CTX_OFFSET_CurCount`($GCM128_CTX)
.L_enc_dec_done_${rndsuffix}:
        # LE->BE conversion
        vpshufb           SHUF_MASK(%rip),$AAD_HASHx,$AAD_HASHx
        vmovdqu64         $AAD_HASHx,`$CTX_OFFSET_AadHash`($GCM128_CTX)
.L_enc_dec_abort_${rndsuffix}:
___
}

# ;;; ===========================================================================
# ;;; Encrypt/decrypt the initial 16 blocks
sub INITIAL_BLOCKS_16 {
  my $IN          = $_[0];     # [in] input buffer
  my $OUT         = $_[1];     # [in] output buffer
  my $AES_EXPKEYS = $_[2];     # [in] pointer to expanded keys
  my $DATA_OFFSET = $_[3];     # [in] data offset
  my $GHASH       = $_[4];     # [in] ZMM with AAD (low 128 bits)
  my $CTR         = $_[5];     # [in] ZMM with CTR BE blocks 4x128 bits
  my $CTR_CHECK   = $_[6];     # [in/out] GPR with counter overflow check
  my $ADDBE_4x4   = $_[7];     # [in] ZMM 4x128bits with value 4 (big endian)
  my $ADDBE_1234  = $_[8];     # [in] ZMM 4x128bits with values 1, 2, 3 & 4 (big endian)
  my $T0          = $_[9];     # [clobered] temporary ZMM register
  my $T1          = $_[10];    # [clobered] temporary ZMM register
  my $T2          = $_[11];    # [clobered] temporary ZMM register
  my $T3          = $_[12];    # [clobered] temporary ZMM register
  my $T4          = $_[13];    # [clobered] temporary ZMM register
  my $T5          = $_[14];    # [clobered] temporary ZMM register
  my $T6          = $_[15];    # [clobered] temporary ZMM register
  my $T7          = $_[16];    # [clobered] temporary ZMM register
  my $T8          = $_[17];    # [clobered] temporary ZMM register
  my $SHUF_MASK   = $_[18];    # [in] ZMM with BE/LE shuffle mask
  my $ENC_DEC     = $_[19];    # [in] ENC (encrypt) or DEC (decrypt) selector
  my $BLK_OFFSET  = $_[20];    # [in] stack frame offset to ciphered blocks
  my $DATA_DISPL  = $_[21];    # [in] fixed numerical data displacement/offset
  my $IA0         = $_[22];    # [clobered] temporary GP register

  my $B00_03 = $T5;
  my $B04_07 = $T6;
  my $B08_11 = $T7;
  my $B12_15 = $T8;

  my $rndsuffix = &random_string();

  my $stack_offset = $BLK_OFFSET;
  $code .= <<___;
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        # ;; prepare counter blocks

        cmpb              \$`(256 - 16)`,@{[BYTE($CTR_CHECK)]}
        jae           .L_next_16_overflow_${rndsuffix}
        vpaddd            $ADDBE_1234,$CTR,$B00_03
        vpaddd            $ADDBE_4x4,$B00_03,$B04_07
        vpaddd            $ADDBE_4x4,$B04_07,$B08_11
        vpaddd            $ADDBE_4x4,$B08_11,$B12_15
        jmp           .L_next_16_ok_${rndsuffix}
.L_next_16_overflow_${rndsuffix}:
        vpshufb           $SHUF_MASK,$CTR,$CTR
        vmovdqa64         ddq_add_4444(%rip),$B12_15
        vpaddd            ddq_add_1234(%rip),$CTR,$B00_03
        vpaddd            $B12_15,$B00_03,$B04_07
        vpaddd            $B12_15,$B04_07,$B08_11
        vpaddd            $B12_15,$B08_11,$B12_15
        vpshufb           $SHUF_MASK,$B00_03,$B00_03
        vpshufb           $SHUF_MASK,$B04_07,$B04_07
        vpshufb           $SHUF_MASK,$B08_11,$B08_11
        vpshufb           $SHUF_MASK,$B12_15,$B12_15
.L_next_16_ok_${rndsuffix}:
        vshufi64x2        \$0b11111111,$B12_15,$B12_15,$CTR
        addb               \$16,@{[BYTE($CTR_CHECK)]}
        # ;; === load 16 blocks of data
        vmovdqu8          `$DATA_DISPL + (64*0)`($IN,$DATA_OFFSET,1),$T0
        vmovdqu8          `$DATA_DISPL + (64*1)`($IN,$DATA_OFFSET,1),$T1
        vmovdqu8          `$DATA_DISPL + (64*2)`($IN,$DATA_OFFSET,1),$T2
        vmovdqu8          `$DATA_DISPL + (64*3)`($IN,$DATA_OFFSET,1),$T3

        # ;; move to AES encryption rounds
        vbroadcastf64x2    `(16*0)`($AES_EXPKEYS),$T4
        vpxorq            $T4,$B00_03,$B00_03
        vpxorq            $T4,$B04_07,$B04_07
        vpxorq            $T4,$B08_11,$B08_11
        vpxorq            $T4,$B12_15,$B12_15
___
  foreach (1 .. ($NROUNDS)) {
    $code .= <<___;
        vbroadcastf64x2    `(16*$_)`($AES_EXPKEYS),$T4
        vaesenc            $T4,$B00_03,$B00_03
        vaesenc            $T4,$B04_07,$B04_07
        vaesenc            $T4,$B08_11,$B08_11
        vaesenc            $T4,$B12_15,$B12_15
___
  }
  $code .= <<___;
        vbroadcastf64x2    `(16*($NROUNDS+1))`($AES_EXPKEYS),$T4
        vaesenclast         $T4,$B00_03,$B00_03
        vaesenclast         $T4,$B04_07,$B04_07
        vaesenclast         $T4,$B08_11,$B08_11
        vaesenclast         $T4,$B12_15,$B12_15

        # ;;  xor against text
        vpxorq            $T0,$B00_03,$B00_03
        vpxorq            $T1,$B04_07,$B04_07
        vpxorq            $T2,$B08_11,$B08_11
        vpxorq            $T3,$B12_15,$B12_15

        # ;; store
        mov               $OUT, $IA0
        vmovdqu8          $B00_03,`$DATA_DISPL + (64*0)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B04_07,`$DATA_DISPL + (64*1)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B08_11,`$DATA_DISPL + (64*2)`($IA0,$DATA_OFFSET,1)
        vmovdqu8          $B12_15,`$DATA_DISPL + (64*3)`($IA0,$DATA_OFFSET,1)
___
  if ($ENC_DEC eq "DEC") {
    $code .= <<___;
        # ;; decryption - cipher text needs to go to GHASH phase
        vpshufb           $SHUF_MASK,$T0,$B00_03
        vpshufb           $SHUF_MASK,$T1,$B04_07
        vpshufb           $SHUF_MASK,$T2,$B08_11
        vpshufb           $SHUF_MASK,$T3,$B12_15
___
  } else {
    $code .= <<___;
        # ;; encryption
        vpshufb           $SHUF_MASK,$B00_03,$B00_03
        vpshufb           $SHUF_MASK,$B04_07,$B04_07
        vpshufb           $SHUF_MASK,$B08_11,$B08_11
        vpshufb           $SHUF_MASK,$B12_15,$B12_15
___
  }

  if ($GHASH ne "no_ghash") {
    $code .= <<___;
        # ;; === xor cipher block 0 with GHASH for the next GHASH round
        vpxorq            $GHASH,$B00_03,$B00_03
___
  }
  $code .= <<___;
        vmovdqa64         $B00_03,`$stack_offset + (0 * 64)`(%rsp)
        vmovdqa64         $B04_07,`$stack_offset + (1 * 64)`(%rsp)
        vmovdqa64         $B08_11,`$stack_offset + (2 * 64)`(%rsp)
        vmovdqa64         $B12_15,`$stack_offset + (3 * 64)`(%rsp)
___
}

# ;;; ===========================================================================
# ;;; Encrypt the initial N x 16 blocks
# ;;; - A x 16 blocks are encrypted/decrypted first (pipeline depth)
# ;;; - B x 16 blocks are encrypted/decrypted and previous A x 16 are ghashed
# ;;; - A + B = N
sub INITIAL_BLOCKS_Nx16 {
  my $IN          = $_[0];     # [in] input buffer
  my $OUT         = $_[1];     # [in] output buffer
  my $AES_EXPKEYS = $_[2];     # [in] pointer to expanded keys
  my $DATA_OFFSET = $_[3];     # [in/out] data offset
  my $GHASH       = $_[4];     # [in] ZMM with AAD (low 128 bits)
  my $CTR         = $_[5];     # [in/out] ZMM with CTR: in - LE & 128b; out - BE & 4x128b
  my $CTR_CHECK   = $_[6];     # [in/out] GPR with counter overflow check
  my $T0          = $_[7];     # [clobered] temporary ZMM register
  my $T1          = $_[8];     # [clobered] temporary ZMM register
  my $T2          = $_[9];     # [clobered] temporary ZMM register
  my $T3          = $_[10];    # [clobered] temporary ZMM register
  my $T4          = $_[11];    # [clobered] temporary ZMM register
  my $T5          = $_[12];    # [clobered] temporary ZMM register
  my $T6          = $_[13];    # [clobered] temporary ZMM register
  my $T7          = $_[14];    # [clobered] temporary ZMM register
  my $T8          = $_[15];    # [clobered] temporary ZMM register
  my $T9          = $_[16];    # [clobered] temporary ZMM register
  my $T10         = $_[17];    # [clobered] temporary ZMM register
  my $T11         = $_[18];    # [clobered] temporary ZMM register
  my $T12         = $_[19];    # [clobered] temporary ZMM register
  my $T13         = $_[20];    # [clobered] temporary ZMM register
  my $T14         = $_[21];    # [clobered] temporary ZMM register
  my $T15         = $_[22];    # [clobered] temporary ZMM register
  my $T16         = $_[23];    # [clobered] temporary ZMM register
  my $T17         = $_[24];    # [clobered] temporary ZMM register
  my $T18         = $_[25];    # [clobered] temporary ZMM register
  my $T19         = $_[26];    # [clobered] temporary ZMM register
  my $T20         = $_[27];    # [clobered] temporary ZMM register
  my $T21         = $_[28];    # [clobered] temporary ZMM register
  my $T22         = $_[29];    # [clobered] temporary ZMM register
  my $GH          = $_[30];    # [out] ZMM ghash sum (high)
  my $GL          = $_[31];    # [out] ZMM ghash sum (low)
  my $GM          = $_[32];    # [out] ZMM ghash sum (middle)
  my $ADDBE_4x4   = $_[33];    # [in] ZMM 4x128bits with value 4 (big endian)
  my $ADDBE_1234  = $_[34];    # [in] ZMM 4x128bits with values 1, 2, 3 & 4 (big endian)
  my $SHUF_MASK   = $_[35];    # [in] ZMM with BE/LE shuffle mask
  my $ENC_DEC     = $_[36];    # [in] ENC (encrypt) or DEC (decrypt) selector
  my $NBLOCKS     = $_[37];    # [in] number of blocks: multiple of 16
  my $DEPTH_BLK   = $_[38];    # [in] pipline depth, number of blocks (multiple of 16)
  my $GCM128_CTX  = $_[39];    # [in] pointer to context
  my $IA0         = $_[40];    # [clobered] temporary GP register
  my $HKEYS_READY = $_[41];    # [in/out]

  my $aesout_offset  = ($STACK_LOCAL_OFFSET + (0 * 16));
  my $ghashin_offset = ($STACK_LOCAL_OFFSET + (0 * 16));
  my $hkey_offset    = $NBLOCKS;
  my $data_in_out_offset = 0;
  $code .= <<___;
        # ;; set up CTR_CHECK
        vmovd             @{[XWORD($CTR)]},@{[DWORD($CTR_CHECK)]}
        and               \$255,@{[DWORD($CTR_CHECK)]}
        # ;; in LE format after init, convert to BE
        vshufi64x2        \$0,$CTR,$CTR,$CTR
        vpshufb           $SHUF_MASK,$CTR,$CTR

        # ;; ==== AES lead in

        # ;; first 16 blocks - just cipher
___
  &INITIAL_BLOCKS_16($IN, $OUT, $AES_EXPKEYS, $DATA_OFFSET, $GHASH, $CTR,
    $CTR_CHECK, $ADDBE_4x4, $ADDBE_1234, $T0, $T1, $T2, $T3, $T4,
    $T5, $T6, $T7, $T8, $SHUF_MASK, $ENC_DEC, $aesout_offset, $data_in_out_offset, $IA0);

  # ;; Get Htable pointer
  $code .= "lea               `$CTX_OFFSET_HTable`($GCM128_CTX),$IA0\n";
  &precompute_hkeys_on_stack($IA0, $HKEYS_READY, $T9, $T10, $T11, $T12, $T13, $T14, $T15, $T16);

  $aesout_offset      += (16 * 16);
  $data_in_out_offset += (16 * 16);
  if ($DEPTH_BLK > 16) {
    foreach (1 .. int(($DEPTH_BLK - 16) / 16)) {
      &INITIAL_BLOCKS_16($IN, $OUT, $AES_EXPKEYS, $DATA_OFFSET, "no_ghash",
        $CTR, $CTR_CHECK, $ADDBE_4x4, $ADDBE_1234, $T0, $T1, $T2, $T3,
        $T4, $T5, $T6, $T7, $T8, $SHUF_MASK, $ENC_DEC, $aesout_offset, $data_in_out_offset, $IA0);
      $aesout_offset      += (16 * 16);
      $data_in_out_offset += (16 * 16);
    }
  }

  # ;; ==== GHASH + AES follows

  # ;; first 16 blocks stitched
  &GHASH_16_ENCRYPT_16_PARALLEL(
    $AES_EXPKEYS, $OUT,           $IN,             $DATA_OFFSET, $CTR,                $CTR_CHECK,
    $hkey_offset, $aesout_offset, $ghashin_offset, $SHUF_MASK,   $T0,                 $T1,
    $T2,          $T3,            $T4,             $T5,          $T6,                 $T7,
    $T8,          $T9,            $T10,            $T11,         $T12,                $T13,
    $T14,         $T15,           $T16,            $T17,         $T18,                $T19,
    $T20,         $T21,           $T22,            $ADDBE_4x4,   $ADDBE_1234,         $GL,
    $GH,          $GM,            "first_time",    $ENC_DEC,     $data_in_out_offset, "no_ghash_in",
    $GCM128_CTX,  $IA0);

  if (($NBLOCKS - $DEPTH_BLK) > 16) {
    foreach (1 .. int(($NBLOCKS - $DEPTH_BLK - 16) / 16)) {
      $ghashin_offset += (16 * 16);
      $hkey_offset -= 16;
      $aesout_offset      += (16 * 16);
      $data_in_out_offset += (16 * 16);

      # ;; mid 16 blocks - stitched
      &GHASH_16_ENCRYPT_16_PARALLEL(
        $AES_EXPKEYS, $OUT,           $IN,             $DATA_OFFSET, $CTR,                $CTR_CHECK,
        $hkey_offset, $aesout_offset, $ghashin_offset, $SHUF_MASK,   $T0,                 $T1,
        $T2,          $T3,            $T4,             $T5,          $T6,                 $T7,
        $T8,          $T9,            $T10,            $T11,         $T12,                $T13,
        $T14,         $T15,           $T16,            $T17,         $T18,                $T19,
        $T20,         $T21,           $T22,            $ADDBE_4x4,   $ADDBE_1234,         $GL,
        $GH,          $GM,            "no_reduction",  $ENC_DEC,     $data_in_out_offset, "no_ghash_in",
        $GCM128_CTX,  $IA0);
    }
  }
  $code .= "add               \$`($NBLOCKS * 16)`,$DATA_OFFSET\n";
}

# ;;; ===========================================================================
# ;;; GHASH the last 16 blocks of cipher text (last part of by 32/64/128 code)
sub GHASH_LAST_Nx16 {
  my $GCM128_CTX = $_[0];     # [in] pointer to context
  my $GHASH      = $_[1];     # [out] ghash output
  my $T1         = $_[2];     # [clobbered] temporary ZMM
  my $T2         = $_[3];     # [clobbered] temporary ZMM
  my $T3         = $_[4];     # [clobbered] temporary ZMM
  my $T4         = $_[5];     # [clobbered] temporary ZMM
  my $T5         = $_[6];     # [clobbered] temporary ZMM
  my $T6         = $_[7];     # [clobbered] temporary ZMM
  my $T7         = $_[8];     # [clobbered] temporary ZMM
  my $T8         = $_[9];     # [clobbered] temporary ZMM
  my $T9         = $_[10];    # [clobbered] temporary ZMM
  my $T10        = $_[11];    # [clobbered] temporary ZMM
  my $T11        = $_[12];    # [clobbered] temporary ZMM
  my $T12        = $_[13];    # [clobbered] temporary ZMM
  my $T13        = $_[14];    # [clobbered] temporary ZMM
  my $T14        = $_[15];    # [clobbered] temporary ZMM
  my $T15        = $_[16];    # [clobbered] temporary ZMM
  my $T16        = $_[17];    # [clobbered] temporary ZMM
  my $GH         = $_[18];    # [in/cloberred] ghash sum (high)
  my $GL         = $_[19];    # [in/cloberred] ghash sum (low)
  my $GM         = $_[20];    # [in/cloberred] ghash sum (medium)
  my $LOOP_BLK   = $_[21];    # [in] numerical number of blocks handled by the loop
  my $DEPTH_BLK  = $_[22];    # [in] numerical number, pipeline depth (ghash vs aes)

  my $T0H  = $T1;
  my $T0L  = $T2;
  my $T0M1 = $T3;
  my $T0M2 = $T4;

  my $T1H  = $T5;
  my $T1L  = $T6;
  my $T1M1 = $T7;
  my $T1M2 = $T8;

  my $T2H  = $T9;
  my $T2L  = $T10;
  my $T2M1 = $T11;
  my $T2M2 = $T12;

  my $BLK1 = $T13;
  my $BLK2 = $T14;

  my $HK1 = $T15;
  my $HK2 = $T16;

  my $hashk      = $DEPTH_BLK;
  my $cipher_blk = ($STACK_LOCAL_OFFSET + (($LOOP_BLK - $DEPTH_BLK) * 16));
  $code .= <<___;
        # ;; load cipher blocks and ghash keys
        vmovdqa64         `$cipher_blk`(%rsp),$BLK1
        vmovdqa64         `$cipher_blk + 64`(%rsp),$BLK2
        vmovdqu64         @{[HashKeyByIdx($hashk,"%rsp")]},$HK1
        vmovdqu64         @{[HashKeyByIdx($hashk-4,"%rsp")]},$HK2
        # ;; ghash blocks 0-3
        vpclmulqdq        \$0x11,$HK1,$BLK1,$T0H      # ; $TH = a1*b1
        vpclmulqdq        \$0x00,$HK1,$BLK1,$T0L      # ; $TL = a0*b0
        vpclmulqdq        \$0x01,$HK1,$BLK1,$T0M1     # ; $TM1 = a1*b0
        vpclmulqdq        \$0x10,$HK1,$BLK1,$T0M2     # ; $TM2 = a0*b1
        # ;; ghash blocks 4-7
        vpclmulqdq        \$0x11,$HK2,$BLK2,$T1H      # ; $TTH = a1*b1
        vpclmulqdq        \$0x00,$HK2,$BLK2,$T1L      # ; $TTL = a0*b0
        vpclmulqdq        \$0x01,$HK2,$BLK2,$T1M1     # ; $TTM1 = a1*b0
        vpclmulqdq        \$0x10,$HK2,$BLK2,$T1M2     # ; $TTM2 = a0*b1
        vpternlogq        \$0x96,$GH,$T1H,$T0H        # ; T0H = T0H + T1H + GH
        vpternlogq        \$0x96,$GL,$T1L,$T0L        # ; T0L = T0L + T1L + GL
        vpternlogq        \$0x96,$GM,$T1M1,$T0M1      # ; T0M1 = T0M1 + T1M1 + GM
        vpxorq            $T1M2,$T0M2,$T0M2           # ; T0M2 = T0M2 + T1M2
___
  foreach (1 .. int(($DEPTH_BLK - 8) / 8)) {
    $hashk -= 8;
    $cipher_blk += 128;
    $code .= <<___;
        # ;; remaining blocks
        # ;; load next 8 cipher blocks and corresponding ghash keys
        vmovdqa64         `$cipher_blk`(%rsp),$BLK1
        vmovdqa64         `$cipher_blk + 64`(%rsp),$BLK2
        vmovdqu64         @{[HashKeyByIdx($hashk,"%rsp")]},$HK1
        vmovdqu64         @{[HashKeyByIdx($hashk-4,"%rsp")]},$HK2
        # ;; ghash blocks 0-3
        vpclmulqdq        \$0x11,$HK1,$BLK1,$T1H      # ; $TH = a1*b1
        vpclmulqdq        \$0x00,$HK1,$BLK1,$T1L      # ; $TL = a0*b0
        vpclmulqdq        \$0x01,$HK1,$BLK1,$T1M1     # ; $TM1 = a1*b0
        vpclmulqdq        \$0x10,$HK1,$BLK1,$T1M2     # ; $TM2 = a0*b1
        # ;; ghash blocks 4-7
        vpclmulqdq        \$0x11,$HK2,$BLK2,$T2H      # ; $TTH = a1*b1
        vpclmulqdq        \$0x00,$HK2,$BLK2,$T2L      # ; $TTL = a0*b0
        vpclmulqdq        \$0x01,$HK2,$BLK2,$T2M1     # ; $TTM1 = a1*b0
        vpclmulqdq        \$0x10,$HK2,$BLK2,$T2M2     # ; $TTM2 = a0*b1
        # ;; update sums
        vpternlogq        \$0x96,$T2H,$T1H,$T0H       # ; TH = T0H + T1H + T2H
        vpternlogq        \$0x96,$T2L,$T1L,$T0L       # ; TL = T0L + T1L + T2L
        vpternlogq        \$0x96,$T2M1,$T1M1,$T0M1    # ; TM1 = T0M1 + T1M1 xor T2M1
        vpternlogq        \$0x96,$T2M2,$T1M2,$T0M2    # ; TM2 = T0M2 + T1M1 xor T2M2
___
  }
  $code .= <<___;
        # ;; integrate TM into TH and TL
        vpxorq            $T0M2,$T0M1,$T0M1
        vpsrldq           \$8,$T0M1,$T1M1
        vpslldq           \$8,$T0M1,$T1M2
        vpxorq            $T1M1,$T0H,$T0H
        vpxorq            $T1M2,$T0L,$T0L
___

  # ;; add TH and TL 128-bit words horizontally
  &VHPXORI4x128($T0H, $T2M1);
  &VHPXORI4x128($T0L, $T2M2);

  # ;; reduction
  $code .= "vmovdqa64         POLY2(%rip),$HK1\n";
  &VCLMUL_REDUCE($GHASH, $HK1, $T0H, $T0L, $T0M1, $T0M2);
}

# ;;; ===========================================================================
# ;;; Encrypt & ghash multiples of 16 blocks
sub GHASH_ENCRYPT_Nx16_PARALLEL {
  my $IN          = $_[0];     # [in] input buffer
  my $OUT         = $_[1];     # [in] output buffer
  my $AES_EXPKEYS = $_[2];     # [in] pointer to expanded keys
  my $DATA_OFFSET = $_[3];     # [in/out] data offset
  my $CTR_BE      = $_[4];     # [in/out] ZMM last counter block
  my $SHFMSK      = $_[5];     # [in] ZMM with byte swap mask for pshufb
  my $ZT0         = $_[6];     # [clobered] temporary ZMM register
  my $ZT1         = $_[7];     # [clobered] temporary ZMM register
  my $ZT2         = $_[8];     # [clobered] temporary ZMM register
  my $ZT3         = $_[9];     # [clobered] temporary ZMM register
  my $ZT4         = $_[10];    # [clobered] temporary ZMM register
  my $ZT5         = $_[11];    # [clobered] temporary ZMM register
  my $ZT6         = $_[12];    # [clobered] temporary ZMM register
  my $ZT7         = $_[13];    # [clobered] temporary ZMM register
  my $ZT8         = $_[14];    # [clobered] temporary ZMM register
  my $ZT9         = $_[15];    # [clobered] temporary ZMM register
  my $ZT10        = $_[16];    # [clobered] temporary ZMM register
  my $ZT11        = $_[17];    # [clobered] temporary ZMM register
  my $ZT12        = $_[18];    # [clobered] temporary ZMM register
  my $ZT13        = $_[19];    # [clobered] temporary ZMM register
  my $ZT14        = $_[20];    # [clobered] temporary ZMM register
  my $ZT15        = $_[21];    # [clobered] temporary ZMM register
  my $ZT16        = $_[22];    # [clobered] temporary ZMM register
  my $ZT17        = $_[23];    # [clobered] temporary ZMM register
  my $ZT18        = $_[24];    # [clobered] temporary ZMM register
  my $ZT19        = $_[25];    # [clobered] temporary ZMM register
  my $ZT20        = $_[26];    # [clobered] temporary ZMM register
  my $ZT21        = $_[27];    # [clobered] temporary ZMM register
  my $ZT22        = $_[28];    # [clobered] temporary ZMM register
  my $GTH         = $_[29];    # [in/out] ZMM GHASH sum (high)
  my $GTL         = $_[30];    # [in/out] ZMM GHASH sum (low)
  my $GTM         = $_[31];    # [in/out] ZMM GHASH sum (medium)
  my $ADDBE_4x4   = $_[32];    # [in] ZMM 4x128bits with value 4 (big endian)
  my $ADDBE_1234  = $_[33];    # [in] ZMM 4x128bits with values 1, 2, 3 & 4 (big endian)
  my $GHASH       = $_[34];    # [clobbered] ZMM with intermediate GHASH value
  my $ENC_DEC     = $_[35];    # [in] ENC (encrypt) or DEC (decrypt) selector
  my $NUM_BLOCKS  = $_[36];    # [in] number of blocks to process in the loop
  my $DEPTH_BLK   = $_[37];    # [in] pipeline depth in blocks
  my $CTR_CHECK   = $_[38];    # [in/out] counter to check byte overflow
  my $GCM128_CTX  = $_[39];    # [in] pointer to context
  my $IA0         = $_[40];    # [clobbered] temporary GPR

  my $aesout_offset  = ($STACK_LOCAL_OFFSET + (0 * 16));
  my $ghashin_offset = ($STACK_LOCAL_OFFSET + (($NUM_BLOCKS - $DEPTH_BLK) * 16));
  my $hkey_offset    = $DEPTH_BLK;
  my $data_in_out_offset = 0;

  # ;; mid 16 blocks
  if ($DEPTH_BLK > 16) {
    foreach (1 .. int(($DEPTH_BLK - 16) / 16)) {
      &GHASH_16_ENCRYPT_16_PARALLEL(
        $AES_EXPKEYS, $OUT,           $IN,             $DATA_OFFSET, $CTR_BE,             $CTR_CHECK,
        $hkey_offset, $aesout_offset, $ghashin_offset, $SHFMSK,      $ZT0,                $ZT1,
        $ZT2,         $ZT3,           $ZT4,            $ZT5,         $ZT6,                $ZT7,
        $ZT8,         $ZT9,           $ZT10,           $ZT11,        $ZT12,               $ZT13,
        $ZT14,        $ZT15,          $ZT16,           $ZT17,        $ZT18,               $ZT19,
        $ZT20,        $ZT21,          $ZT22,           $ADDBE_4x4,   $ADDBE_1234,         $GTL,
        $GTH,         $GTM,           "no_reduction",  $ENC_DEC,     $data_in_out_offset, "no_ghash_in",
        $GCM128_CTX,  $IA0);

      $aesout_offset  += (16 * 16);
      $ghashin_offset += (16 * 16);
      $hkey_offset -= 16;
      $data_in_out_offset += (16 * 16);
    }
  }

  # ;; 16 blocks with reduction
  &GHASH_16_ENCRYPT_16_PARALLEL(
    $AES_EXPKEYS, $OUT,           $IN,               $DATA_OFFSET, $CTR_BE,             $CTR_CHECK,
    16,           $aesout_offset, $ghashin_offset,   $SHFMSK,      $ZT0,                $ZT1,
    $ZT2,         $ZT3,           $ZT4,              $ZT5,         $ZT6,                $ZT7,
    $ZT8,         $ZT9,           $ZT10,             $ZT11,        $ZT12,               $ZT13,
    $ZT14,        $ZT15,          $ZT16,             $ZT17,        $ZT18,               $ZT19,
    $ZT20,        $ZT21,          $ZT22,             $ADDBE_4x4,   $ADDBE_1234,         $GTL,
    $GTH,         $GTM,           "final_reduction", $ENC_DEC,     $data_in_out_offset, "no_ghash_in",
    $GCM128_CTX,  $IA0);

  $aesout_offset      += (16 * 16);
  $data_in_out_offset += (16 * 16);
  $ghashin_offset = ($STACK_LOCAL_OFFSET + (0 * 16));
  $hkey_offset    = $NUM_BLOCKS;

  # ;; === xor cipher block 0 with GHASH (ZT4)
  $code .= "vmovdqa64         $ZT4,$GHASH\n";

  # ;; start the pipeline again
  &GHASH_16_ENCRYPT_16_PARALLEL(
    $AES_EXPKEYS, $OUT,           $IN,             $DATA_OFFSET, $CTR_BE,             $CTR_CHECK,
    $hkey_offset, $aesout_offset, $ghashin_offset, $SHFMSK,      $ZT0,                $ZT1,
    $ZT2,         $ZT3,           $ZT4,            $ZT5,         $ZT6,                $ZT7,
    $ZT8,         $ZT9,           $ZT10,           $ZT11,        $ZT12,               $ZT13,
    $ZT14,        $ZT15,          $ZT16,           $ZT17,        $ZT18,               $ZT19,
    $ZT20,        $ZT21,          $ZT22,           $ADDBE_4x4,   $ADDBE_1234,         $GTL,
    $GTH,         $GTM,           "first_time",    $ENC_DEC,     $data_in_out_offset, $GHASH,
    $GCM128_CTX,  $IA0);

  if (($NUM_BLOCKS - $DEPTH_BLK) > 16) {
    foreach (1 .. int(($NUM_BLOCKS - $DEPTH_BLK - 16) / 16)) {
      $aesout_offset      += (16 * 16);
      $data_in_out_offset += (16 * 16);
      $ghashin_offset     += (16 * 16);
      $hkey_offset -= 16;

      &GHASH_16_ENCRYPT_16_PARALLEL(
        $AES_EXPKEYS, $OUT,           $IN,             $DATA_OFFSET, $CTR_BE,             $CTR_CHECK,
        $hkey_offset, $aesout_offset, $ghashin_offset, $SHFMSK,      $ZT0,                $ZT1,
        $ZT2,         $ZT3,           $ZT4,            $ZT5,         $ZT6,                $ZT7,
        $ZT8,         $ZT9,           $ZT10,           $ZT11,        $ZT12,               $ZT13,
        $ZT14,        $ZT15,          $ZT16,           $ZT17,        $ZT18,               $ZT19,
        $ZT20,        $ZT21,          $ZT22,           $ADDBE_4x4,   $ADDBE_1234,         $GTL,
        $GTH,         $GTM,           "no_reduction",  $ENC_DEC,     $data_in_out_offset, "no_ghash_in",
        $GCM128_CTX,  $IA0);
    }
  }

  $code .= "add               \$`($NUM_BLOCKS * 16)`,$DATA_OFFSET\n";
}

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;; Functions definitions
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

$code .= ".text\n";

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;void gcm_init_avx512(u128 Htable[16],
# ;                     const uint64_t Xi[2]);
# ;
# ; Precomputes hashkey table for GHASH optimization.
#
# ; Leaf function (does not allocate stack space, does not use non-volatile registers).
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl gcm_init_avx512
.hidden gcm_init_avx512
.type gcm_init_avx512,\@abi-omnipotent
.align 32
gcm_init_avx512:
.cfi_startproc
        endbranch
___
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check Htable != NULL
        test               $arg1, $arg1
jz      .Labort_init

        # ;; Check Xi != NULL
        test               $arg2, $arg2
jz      .Labort_init
___
}
$code .= <<___;
        vmovdqu64         ($arg2),%xmm16
        vpalignr           \$8,%xmm16,%xmm16,%xmm16
        # ;;;;; PRECOMPUTATION of HashKey<<1 mod poly from the HashKey ;;;;;
        vmovdqa64         %xmm16,%xmm2
        vpsllq            \$1,%xmm16,%xmm16
        vpsrlq            \$63,%xmm2,%xmm2
        vmovdqa           %xmm2,%xmm1
        vpslldq           \$8,%xmm2,%xmm2
        vpsrldq           \$8,%xmm1,%xmm1
        vporq             %xmm2,%xmm16,%xmm16
        # ;reduction
        vpshufd           \$0b00100100,%xmm1,%xmm2
        vpcmpeqd          TWOONE(%rip),%xmm2,%xmm2
        vpand             POLY(%rip),%xmm2,%xmm2
        vpxorq            %xmm2,%xmm16,%xmm16                  # ; xmm16 holds the HashKey<<1 mod poly
        # ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
        vmovdqu64         %xmm16,@{[HashKeyByIdx(1,$arg1)]} # ; store HashKey<<1 mod poly
___
&PRECOMPUTE("$arg1", "%xmm16", "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm17", "%xmm18");
if ($CLEAR_SCRATCH_REGISTERS) {
  &clear_scratch_gps_asm();
  &clear_scratch_zmms_asm();
} else {
  $code .= "vzeroupper\n";
}
$code .= <<___;
.Labort_init:
ret
.cfi_endproc
.size gcm_init_avx512, .-gcm_init_avx512
___

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;void gcm_gmult_avx512(uint64_t Xi[2],
# ;                      const u128 Htable[16])
# ;
# ; Leaf function (does not allocate stack space, does not use non-volatile registers).
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl gcm_gmult_avx512
.hidden gcm_gmult_avx512
.type gcm_gmult_avx512,\@abi-omnipotent,
.align 32
gcm_gmult_avx512:
.cfi_startproc
        endbranch
___
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check Xi != NULL
        test               $arg1, $arg1
jz      .Labort_gmult

        # ;; Check Htable != NULL
        test               $arg2, $arg2
jz      .Labort_gmult
___
}
$code .= "vmovdqu64         ($arg1),%xmm1\n";

# ; GHASH_MUL works with reflected inputs, so shuffle current hash
$code .= "vpshufb           SHUF_MASK(%rip),%xmm1,%xmm1\n";
$code .= "vmovdqu64         @{[HashKeyByIdx(1,$arg2)]},%xmm2\n";

&GHASH_MUL("%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm16", "%xmm17");

$code .= "vpshufb           SHUF_MASK(%rip),%xmm1,%xmm1\n";
$code .= "vmovdqu64         %xmm1,($arg1)\n";
if ($CLEAR_SCRATCH_REGISTERS) {
  &clear_scratch_gps_asm();
  &clear_scratch_zmms_asm();
} else {
  $code .= "vzeroupper\n";
}
$code .= <<___;
.Labort_gmult:
ret
.cfi_endproc
.size gcm_gmult_avx512, .-gcm_gmult_avx512
___

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;void gcm_ghash_avx512(uint64_t Xi[2],
# ;                      const u128 Htable[16],
# ;                      const uint8_t *in,
# ;                      size_t len)
# ;
# ; Updates AAD hash.
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl gcm_ghash_avx512
.hidden gcm_ghash_avx512
.type gcm_ghash_avx512,\@abi-omnipotent
.align 32
gcm_ghash_avx512:
.cfi_startproc
.Lghash_seh_begin:
        endbranch
___
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check Xi != NULL
        test               $arg1, $arg1
jz      .Labort_ghash

        # ;; Check Htable != NULL
        test               $arg2, $arg2
jz      .Labort_ghash

        # ;; Check in != NULL
        test               $arg3, $arg3
jz      .Labort_ghash
___
}

# ; NOTE: code before PROLOG() must not modify any registers
&PROLOG(
  1,    # allocate stack space for hkeys,
  0,    # do not allocate stack space for AES blocks
  "ghash");
$code .= "vmovdqu64         ($arg1),%xmm14               # ; load current hash\n";
$code .= "vpshufb           SHUF_MASK(%rip),%xmm14,%xmm14\n";

&CALC_AAD_HASH(
  "$arg3",  "$arg4",  "%xmm14", "$arg2",  "%zmm1",  "%zmm11", "%zmm3",  "%zmm4",  "%zmm5",  "%zmm6",
  "%zmm7",  "%zmm8",  "%zmm9",  "%zmm10", "%zmm12", "%zmm13", "%zmm15", "%zmm16", "%zmm17", "%zmm18",
  "%zmm19", "%zmm20", "%r10",   "%r11",   "%r12",   "%k1");

$code .= <<___;
        vpshufb           SHUF_MASK(%rip),%xmm14,%xmm14
        vmovdqu64         %xmm14,($arg1)               # ; save current hash
.Labort_ghash:
___
&EPILOG(
  1,    # hkeys were allocated
  $arg4);
$code .= <<___;
ret
.Lghash_seh_end:
.cfi_endproc
.size gcm_ghash_avx512, .-gcm_ghash_avx512
___

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;void gcm_setiv_avx512 (const AES_KEY *key,
# ;                       const GCM128_CONTEXT *ctx,
# ;                       const uint8_t *iv,
# ;                       size_t ivlen);
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl gcm_setiv_avx512
.hidden gcm_setiv_avx512
.type gcm_setiv_avx512,\@abi-omnipotent
.align 32
gcm_setiv_avx512:
.cfi_startproc
.Lsetiv_seh_begin:
        endbranch
___
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check key != NULL
        test               $arg1,$arg1
jz      .Labort_setiv

        # ;; Check ctx != NULL
        test               $arg2,$arg2
jz      .Labort_setiv

        # ;; Check iv != 0
        test               $arg3,$arg3
jz      .Labort_setiv
___
}

# ; NOTE: code before PROLOG() must not modify any registers
&PROLOG(
  1,    # allocate stack space for hkeys
  0,    # do not allocate stack space for AES blocks
  "setiv");
&GCM_INIT_IV(
  "$arg1",  "$arg2",  "$arg3",  "$arg4",  "%r10",   "%r11",   "%r12",  "%k1",   "%xmm2",  "%zmm1",
  "%zmm11", "%zmm3",  "%zmm4",  "%zmm5",  "%zmm6",  "%zmm7",  "%zmm8", "%zmm9", "%zmm10", "%zmm12",
  "%zmm13", "%zmm15", "%zmm16", "%zmm17", "%zmm18", "%zmm19", "%zmm20");
&EPILOG(1, $arg4);
$code .= <<___;
.Labort_setiv:
ret
.Lsetiv_seh_end:
.cfi_endproc
.size gcm_setiv_avx512, .-gcm_setiv_avx512
___

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; void aes_gcm_encrypt_avx512(const AES_KEY *key,
# ;                             const GCM128_CONTEXT *ctx,
# ;                             unsigned *pblocklen,
# ;                             const uint8_t *in,
# ;                             size_t len,
# ;                             uint8_t *out);
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl aes_gcm_encrypt_avx512
.hidden aes_gcm_encrypt_avx512
.type aes_gcm_encrypt_avx512,\@abi-omnipotent,
.align 32
aes_gcm_encrypt_avx512:
.cfi_startproc
.Lencrypt_seh_begin:
#ifdef BORINGSSL_DISPATCH_TEST
.extern     BORINGSSL_function_hit
        movb              \$1,BORINGSSL_function_hit+6(%rip)
#endif
        endbranch
___

# ; NOTE: code before PROLOG() must not modify any registers
&PROLOG(
  1,    # allocate stack space for hkeys
  1,    # allocate stack space for AES blocks
  "encrypt");
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check key != NULL
        test               $arg1,$arg1
jz      .Lexit_gcm_encrypt

        # ;; Check ctx != NULL
        test               $arg2,$arg2
jz      .Lexit_gcm_encrypt

        # ;; Check pblocklen != 0
        test               $arg3,$arg3
jz      .Lexit_gcm_encrypt

        # ;; Check in != 0
        test               $arg4,$arg4
jz      .Lexit_gcm_encrypt

        # ;; Check out != 0
        cmpq              \$0,$arg6
jz      .Lexit_gcm_encrypt
___
}
$code .= <<___;
        # ; load number of rounds from AES_KEY structure (offset in bytes is
        # ; size of the |rd_key| buffer)
        mov             `4*15*4`($arg1),%eax
        cmp             \$9,%eax
        je              .Laes_gcm_encrypt_128_avx512
        cmp             \$11,%eax
        je              .Laes_gcm_encrypt_192_avx512
        cmp             \$13,%eax
        je              .Laes_gcm_encrypt_256_avx512
        xor             %eax,%eax
        jmp             .Lexit_gcm_encrypt
___
for my $keylen (sort keys %aes_rounds) {
  $NROUNDS = $aes_rounds{$keylen};
  $code .= <<___;
.align 32
.Laes_gcm_encrypt_${keylen}_avx512:
___
  &GCM_ENC_DEC("$arg1", "$arg2", "$arg3", "$arg4", "$arg5", "$arg6", "ENC", "multi_call");
  $code .= "jmp .Lexit_gcm_encrypt\n";
}
$code .= ".Lexit_gcm_encrypt:\n";
&EPILOG(1, $arg5);
$code .= <<___;
ret
.Lencrypt_seh_end:
.cfi_endproc
.size aes_gcm_encrypt_avx512, .-aes_gcm_encrypt_avx512
___

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ; void aes_gcm_decrypt_avx512(const AES_KEY *key,
# ;                             const GCM128_CONTEXT *ctx,
# ;                             unsigned *pblocklen,
# ;                             const uint8_t *in,
# ;                             size_t len,
# ;                             uint8_t *out);
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
$code .= <<___;
.globl aes_gcm_decrypt_avx512
.hidden aes_gcm_decrypt_avx512
.type aes_gcm_decrypt_avx512,\@abi-omnipotent,
.align 32
aes_gcm_decrypt_avx512:
.cfi_startproc
.Ldecrypt_seh_begin:
        endbranch
___

# ; NOTE: code before PROLOG() must not modify any registers
&PROLOG(
  1,    # allocate stack space for hkeys
  1,    # allocate stack space for AES blocks
  "decrypt");
if ($CHECK_FUNCTION_ARGUMENTS) {
  $code .= <<___;
        # ;; Check key != NULL
        test               $arg1,$arg1
jz      .Lexit_gcm_decrypt

        # ;; Check ctx != NULL
        test               $arg2,$arg2
jz      .Lexit_gcm_decrypt

        # ;; Check pblocklen != 0
        test               $arg3,$arg3
jz      .Lexit_gcm_decrypt

        # ;; Check in != 0
        test               $arg4,$arg4
jz      .Lexit_gcm_decrypt

        # ;; Check out != 0
        cmpq              \$0,$arg6
jz      .Lexit_gcm_decrypt
___
}
$code .= <<___;
        # ; load number of rounds from AES_KEY structure (offset in bytes is
        # ; size of the |rd_key| buffer)
        mov             `4*15*4`($arg1),%eax
        cmp             \$9,%eax
        je              .Laes_gcm_decrypt_128_avx512
        cmp             \$11,%eax
        je              .Laes_gcm_decrypt_192_avx512
        cmp             \$13,%eax
        je              .Laes_gcm_decrypt_256_avx512
        xor             %eax,%eax
        jmp             .Lexit_gcm_decrypt
___
for my $keylen (sort keys %aes_rounds) {
  $NROUNDS = $aes_rounds{$keylen};
  $code .= <<___;
.align 32
.Laes_gcm_decrypt_${keylen}_avx512:
___
  &GCM_ENC_DEC("$arg1", "$arg2", "$arg3", "$arg4", "$arg5", "$arg6", "DEC", "multi_call");
  $code .= "jmp .Lexit_gcm_decrypt\n";
}
$code .= ".Lexit_gcm_decrypt:\n";
&EPILOG(1, $arg5);
$code .= <<___;
ret
.Ldecrypt_seh_end:
.cfi_endproc
.size aes_gcm_decrypt_avx512, .-aes_gcm_decrypt_avx512
___

if ($win64) {

  # Add unwind metadata for SEH.

  # See https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-160
  my $UWOP_PUSH_NONVOL = 0;
  my $UWOP_ALLOC_LARGE = 1;
  my $UWOP_SET_FPREG   = 3;
  my $UWOP_SAVE_XMM128 = 8;
  my %UWOP_REG_NUMBER  = (
    rax => 0,
    rcx => 1,
    rdx => 2,
    rbx => 3,
    rsp => 4,
    rbp => 5,
    rsi => 6,
    rdi => 7,
    map(("r$_" => $_), (8 .. 15)));

  $code .= <<___;
.section    .pdata
.align  4
    .rva    .Lghash_seh_begin
    .rva    .Lghash_seh_end
    .rva    .Lghash_seh_info

    .rva    .Lsetiv_seh_begin
    .rva    .Lsetiv_seh_end
    .rva    .Lsetiv_seh_info

    .rva    .Lencrypt_seh_begin
    .rva    .Lencrypt_seh_end
    .rva    .Lencrypt_seh_info

    .rva    .Ldecrypt_seh_begin
    .rva    .Ldecrypt_seh_end
    .rva    .Ldecrypt_seh_info

.section    .xdata
___

  foreach my $func_name ("ghash", "setiv", "encrypt", "decrypt") {
    $code .= <<___;
.align  8
.L${func_name}_seh_info:
    .byte   1   # version 1, no flags
    .byte   .L${func_name}_seh_prolog_end-.L${func_name}_seh_begin
    .byte   31 # num_slots = 1*8 + 2 + 1 + 2*10
    # FR = rbp; Offset from RSP = $XMM_STORAGE scaled on 16
    .byte   @{[$UWOP_REG_NUMBER{rbp} | (($XMM_STORAGE / 16 ) << 4)]}
___

    # Metadata for %xmm15-%xmm6
    # Occupy 2 slots each
    for (my $reg_idx = 15; $reg_idx >= 6; $reg_idx--) {

      # Scaled-by-16 stack offset
      my $xmm_reg_offset = ($reg_idx - 6);
      $code .= <<___;
    .byte   .L${func_name}_seh_save_xmm${reg_idx}-.L${func_name}_seh_begin
    .byte   @{[$UWOP_SAVE_XMM128 | (${reg_idx} << 4)]}
    .value  $xmm_reg_offset
___
    }

    $code .= <<___;
    # Frame pointer (occupy 1 slot)
    .byte   .L${func_name}_seh_setfp-.L${func_name}_seh_begin
    .byte   $UWOP_SET_FPREG

    # Occupy 2 slots, as stack allocation < 512K, but > 128 bytes
    .byte   .L${func_name}_seh_allocstack_xmm-.L${func_name}_seh_begin
    .byte   $UWOP_ALLOC_LARGE
    .value  `($XMM_STORAGE + 8) / 8`
___

    # Metadata for GPR regs
    # Occupy 1 slot each
    foreach my $reg ("rsi", "rdi", "r15", "r14", "r13", "r12", "rbp", "rbx") {
      $code .= <<___;
    .byte   .L${func_name}_seh_push_${reg}-.L${func_name}_seh_begin
    .byte   @{[$UWOP_PUSH_NONVOL | ($UWOP_REG_NUMBER{$reg} << 4)]}
___
    }
  }
}

$code .= <<___;
.data
.align 16
POLY:   .quad     0x0000000000000001, 0xC200000000000000

.align 64
POLY2:
        .quad     0x00000001C2000000, 0xC200000000000000
        .quad     0x00000001C2000000, 0xC200000000000000
        .quad     0x00000001C2000000, 0xC200000000000000
        .quad     0x00000001C2000000, 0xC200000000000000

.align 16
TWOONE: .quad     0x0000000000000001, 0x0000000100000000

# ;;; Order of these constants should not change.
# ;;; More specifically, ALL_F should follow SHIFT_MASK, and ZERO should follow ALL_F
.align 64
SHUF_MASK:
        .quad     0x08090A0B0C0D0E0F, 0x0001020304050607
        .quad     0x08090A0B0C0D0E0F, 0x0001020304050607
        .quad     0x08090A0B0C0D0E0F, 0x0001020304050607
        .quad     0x08090A0B0C0D0E0F, 0x0001020304050607

.align 16
SHIFT_MASK:
        .quad     0x0706050403020100, 0x0f0e0d0c0b0a0908

ALL_F:
        .quad     0xffffffffffffffff, 0xffffffffffffffff

ZERO:
        .quad     0x0000000000000000, 0x0000000000000000

.align 16
ONE:
        .quad     0x0000000000000001, 0x0000000000000000

.align 16
TWO:
        .quad     0x0000000000000002, 0x0000000000000000

.align 16
ONEf:
        .quad     0x0000000000000000, 0x0100000000000000

.align 16
TWOf:
        .quad     0x0000000000000000, 0x0200000000000000

.align 64
ddq_add_1234:
        .quad  0x0000000000000001, 0x0000000000000000
        .quad  0x0000000000000002, 0x0000000000000000
        .quad  0x0000000000000003, 0x0000000000000000
        .quad  0x0000000000000004, 0x0000000000000000

.align 64
ddq_add_5678:
        .quad  0x0000000000000005, 0x0000000000000000
        .quad  0x0000000000000006, 0x0000000000000000
        .quad  0x0000000000000007, 0x0000000000000000
        .quad  0x0000000000000008, 0x0000000000000000

.align 64
ddq_add_4444:
        .quad  0x0000000000000004, 0x0000000000000000
        .quad  0x0000000000000004, 0x0000000000000000
        .quad  0x0000000000000004, 0x0000000000000000
        .quad  0x0000000000000004, 0x0000000000000000

.align 64
ddq_add_8888:
        .quad  0x0000000000000008, 0x0000000000000000
        .quad  0x0000000000000008, 0x0000000000000000
        .quad  0x0000000000000008, 0x0000000000000000
        .quad  0x0000000000000008, 0x0000000000000000

.align 64
ddq_addbe_1234:
        .quad  0x0000000000000000, 0x0100000000000000
        .quad  0x0000000000000000, 0x0200000000000000
        .quad  0x0000000000000000, 0x0300000000000000
        .quad  0x0000000000000000, 0x0400000000000000

.align 64
ddq_addbe_5678:
        .quad  0x0000000000000000, 0x0500000000000000
        .quad  0x0000000000000000, 0x0600000000000000
        .quad  0x0000000000000000, 0x0700000000000000
        .quad  0x0000000000000000, 0x0800000000000000

.align 64
ddq_addbe_4444:
        .quad  0x0000000000000000, 0x0400000000000000
        .quad  0x0000000000000000, 0x0400000000000000
        .quad  0x0000000000000000, 0x0400000000000000
        .quad  0x0000000000000000, 0x0400000000000000

.align 64
ddq_addbe_8888:
        .quad  0x0000000000000000, 0x0800000000000000
        .quad  0x0000000000000000, 0x0800000000000000
        .quad  0x0000000000000000, 0x0800000000000000
        .quad  0x0000000000000000, 0x0800000000000000

.align 64
byte_len_to_mask_table:
        .quad      0x0007000300010000
        .quad      0x007f003f001f000f
        .quad      0x07ff03ff01ff00ff
        .quad      0x7fff3fff1fff0fff
        .quad      0x000000000000ffff

.align 64
byte64_len_to_mask_table:
        .quad      0x0000000000000000, 0x0000000000000001
        .quad      0x0000000000000003, 0x0000000000000007
        .quad      0x000000000000000f, 0x000000000000001f
        .quad      0x000000000000003f, 0x000000000000007f
        .quad      0x00000000000000ff, 0x00000000000001ff
        .quad      0x00000000000003ff, 0x00000000000007ff
        .quad      0x0000000000000fff, 0x0000000000001fff
        .quad      0x0000000000003fff, 0x0000000000007fff
        .quad      0x000000000000ffff, 0x000000000001ffff
        .quad      0x000000000003ffff, 0x000000000007ffff
        .quad      0x00000000000fffff, 0x00000000001fffff
        .quad      0x00000000003fffff, 0x00000000007fffff
        .quad      0x0000000000ffffff, 0x0000000001ffffff
        .quad      0x0000000003ffffff, 0x0000000007ffffff
        .quad      0x000000000fffffff, 0x000000001fffffff
        .quad      0x000000003fffffff, 0x000000007fffffff
        .quad      0x00000000ffffffff, 0x00000001ffffffff
        .quad      0x00000003ffffffff, 0x00000007ffffffff
        .quad      0x0000000fffffffff, 0x0000001fffffffff
        .quad      0x0000003fffffffff, 0x0000007fffffffff
        .quad      0x000000ffffffffff, 0x000001ffffffffff
        .quad      0x000003ffffffffff, 0x000007ffffffffff
        .quad      0x00000fffffffffff, 0x00001fffffffffff
        .quad      0x00003fffffffffff, 0x00007fffffffffff
        .quad      0x0000ffffffffffff, 0x0001ffffffffffff
        .quad      0x0003ffffffffffff, 0x0007ffffffffffff
        .quad      0x000fffffffffffff, 0x001fffffffffffff
        .quad      0x003fffffffffffff, 0x007fffffffffffff
        .quad      0x00ffffffffffffff, 0x01ffffffffffffff
        .quad      0x03ffffffffffffff, 0x07ffffffffffffff
        .quad      0x0fffffffffffffff, 0x1fffffffffffffff
        .quad      0x3fffffffffffffff, 0x7fffffffffffffff
        .quad      0xffffffffffffffff

.align 64
mask_out_top_block:
        .quad      0xffffffffffffffff, 0xffffffffffffffff
        .quad      0xffffffffffffffff, 0xffffffffffffffff
        .quad      0xffffffffffffffff, 0xffffffffffffffff
        .quad      0x0000000000000000, 0x0000000000000000
___
} else {
# Fallback for old assembler.
# Should not be reachable as |avx512vaes| flag is set to 1 explicitly.
$code .= <<___;
.globl gcm_init_avx512
.globl gcm_ghash_avx512
.globl gcm_gmult_avx512
.globl gcm_setiv_avx512
.globl aes_gcm_encrypt_avx512
.globl aes_gcm_decrypt_avx512

.hidden gcm_init_avx512
.hidden gcm_ghash_avx512
.hidden gcm_gmult_avx512
.hidden gcm_setiv_avx512
.hidden aes_gcm_encrypt_avx512
.hidden aes_gcm_decrypt_avx512

.type gcm_init_avx512,\@abi-omnipotent
gcm_ghash_avx512:
gcm_gmult_avx512:
gcm_setiv_avx512:
aes_gcm_encrypt_avx512:
aes_gcm_decrypt_avx512:
    .byte   0x0f,0x0b    # ud2
    ret
.size   gcm_init_avx512, .-gcm_init_avx512
___
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT or die "error closing STDOUT: $!";
