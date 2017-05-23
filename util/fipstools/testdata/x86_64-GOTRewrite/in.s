	.text
foo:
	# leaq of OPENSSL_ia32cap_P is supported.
	leaq OPENSSL_ia32cap_P(%rip), %r11

	# As is the equivalent GOTPCREL movq.
	movq OPENSSL_ia32cap_P@GOTPCREL(%rip), %r12

	# Test that GOTPCREL accesses get translated. They are handled
	# differently for local and external symbols.

	# pushq stderr@GOTPCREL(%rip) # FIXME
	pushq foo@GOTPCREL(%rip)

	movq stderr@GOTPCREL(%rip), %r11
	movq foo@GOTPCREL(%rip), %r11

	# vmovq stderr@GOTPCREL(%rip), %xmm0 # FIXME
	vmovq foo@GOTPCREL(%rip), %xmm0

	cmoveq stderr@GOTPCREL(%rip), %r11
	cmoveq foo@GOTPCREL(%rip), %r11
	cmovneq stderr@GOTPCREL(%rip), %r11
	cmovneq foo@GOTPCREL(%rip), %r11

	# Synthesized symbols do not use the GOT.
	movq BORINGSSL_bcm_text_start@GOTPCREL(%rip), %r11
	movq foobar_bss_get@GOTPCREL(%rip), %r11
	movq OPENSSL_ia32cap_get@GOTPCREL(%rip), %r11

.comm foobar,64,32
