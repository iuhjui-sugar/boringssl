	.type foo, %function
	.globl foo
foo:
	# GOT load
	adrp x0, :got:stderr
	ldr x1, [x0, :got_lo12:stderr]

	# GOT load to x0
	adrp x1, :got:stderr
	ldr x0, [x1, :got_lo12:stderr]

	# Address load
	adrp x0, .Llocal_data
	add x1, x0, :lo12:.Llocal_data
	add x1, x0, :lo12:.Llocal_data+16

	# armcap
	adrp x1, OPENSSL_armcap_P
	ldr w2, [x1, :lo12:OPENSSL_armcap_P]

	# armcap to w0
	adrp x1, OPENSSL_armcap_P
	ldr w0, [x1, :lo12:OPENSSL_armcap_P]

	# Load from local symbol
	adrp x10, .Llocal_data2
	ldr q0, [x10, :lo12:.Llocal_data2]

	bl local_function

	bl remote_function

local_function:
