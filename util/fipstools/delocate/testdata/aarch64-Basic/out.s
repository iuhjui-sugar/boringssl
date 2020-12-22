.text
.file 1 "inserted_by_delocate.c"
.loc 1 1 0
BORINGSSL_bcm_text_start:
	.type foo, %function
	.globl foo
.Lfoo_local_target:
foo:
	# GOT load
// WAS adrp x0, :got:stderr
// WAS ldr x1, [x0, :got_lo12:stderr]
	stp x0, lr, [sp, #-16]!
	bl .Lboringssl_loadgot_stderr
	mov x1, x0
	ldp x0, lr, [sp], #16

	# GOT load to x0
// WAS adrp x1, :got:stderr
// WAS ldr x0, [x1, :got_lo12:stderr]
	stp x0, lr, [sp, #-16]!
	bl .Lboringssl_loadgot_stderr
	ldp xzr, lr, [sp], #16

	# Address load
// WAS adrp x0, .Llocal_data
// WAS add x1, x0, :lo12:.Llocal_data
	adr x1, .Llocal_data
// WAS add x1, x0, :lo12:.Llocal_data+16
	adr x1, .Llocal_data+16

	# armcap
// WAS adrp x1, OPENSSL_armcap_P
	stp x0, lr, [sp, #-16]!
	bl .LOPENSSL_armcap_P_load
	mov w2, w0
	ldp x0, lr, [sp], #16

	# armcap to w0
// WAS adrp x1, OPENSSL_armcap_P
	stp x0, lr, [sp, #-16]!
	bl .LOPENSSL_armcap_P_load
	ldp xzr, lr, [sp], #16

	# Load from local symbol
// WAS adrp x10, .Llocal_data2
// WAS ldr q0, [x10, :lo12:.Llocal_data2]
	adr x10, .Llocal_data2
	ldr q0, [x10]

// WAS bl local_function
	bl	.Llocal_function_local_target

// WAS bl remote_function
	bl	bcm_redirector_remote_function

.Llocal_function_local_target:
local_function:
.text
.loc 1 2 0
BORINGSSL_bcm_text_end:
.p2align 2
.hidden bcm_redirector_remote_function
.type bcm_redirector_remote_function, @function
bcm_redirector_remote_function:
.cfi_startproc
	b remote_function
.cfi_endproc
.size bcm_redirector_remote_function, .-bcm_redirector_remote_function
.p2align 2
.hidden .Lboringssl_loadgot_stderr
.type .Lboringssl_loadgot_stderr, @function
.Lboringssl_loadgot_stderr:
.cfi_startproc
	adrp x0, :got:stderr
	ldr x0, [x0, :got_lo12:stderr]
	ret
.cfi_endproc
.size .Lboringssl_loadgot_stderr, .-.Lboringssl_loadgot_stderr
.p2align 2
.hidden .LOPENSSL_armcap_P_load
.type .LOPENSSL_armcap_P_load, @function
.LOPENSSL_armcap_P_load:
.cfi_startproc
	adrp x0, OPENSSL_armcap_P
	ldr w0, [x0, :lo12:OPENSSL_armcap_P]
	ret
.cfi_endproc
.size .LOPENSSL_armcap_P_load, .-.LOPENSSL_armcap_P_load
.type BORINGSSL_bcm_text_hash, @object
.size BORINGSSL_bcm_text_hash, 64
BORINGSSL_bcm_text_hash:
.byte 0xae
.byte 0x2c
.byte 0xea
.byte 0x2a
.byte 0xbd
.byte 0xa6
.byte 0xf3
.byte 0xec
.byte 0x97
.byte 0x7f
.byte 0x9b
.byte 0xf6
.byte 0x94
.byte 0x9a
.byte 0xfc
.byte 0x83
.byte 0x68
.byte 0x27
.byte 0xcb
.byte 0xa0
.byte 0xa0
.byte 0x9f
.byte 0x6b
.byte 0x6f
.byte 0xde
.byte 0x52
.byte 0xcd
.byte 0xe2
.byte 0xcd
.byte 0xff
.byte 0x31
.byte 0x80
.byte 0xa2
.byte 0xd4
.byte 0xc3
.byte 0x66
.byte 0xf
.byte 0xc2
.byte 0x6a
.byte 0x7b
.byte 0xf4
.byte 0xbe
.byte 0x39
.byte 0xa2
.byte 0xd7
.byte 0x25
.byte 0xdb
.byte 0x21
.byte 0x98
.byte 0xe9
.byte 0xd5
.byte 0x53
.byte 0xbf
.byte 0x5c
.byte 0x32
.byte 0x6
.byte 0x83
.byte 0x34
.byte 0xc
.byte 0x65
.byte 0x89
.byte 0x52
.byte 0xbd
.byte 0x1f
