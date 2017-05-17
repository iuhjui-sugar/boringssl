.text
BORINGSSL_bcm_text_start:
	.text
.Lfoo_local_target:
foo:
	# TOC references may have offsets.
# WAS addis 3, 2, 5+foo@toc@ha
	addi 1, 1, -288
	std 4, -8(1)
	mflr 4
	std 4, -16(1)
	std 2, -24(1)
	std 3, -32(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_5
	mr 4, 3
	ld 3, -32(1)
	ld 2, -24(1)
	add	3, 2, 4
	ld 4, -16(1)
	mtlr 4
	ld 4, -8(1)
	addi 1, 1, 288
# WAS addi 3, 3, 10+foo@toc@l
	addi 1, 1, -288
	std 4, -8(1)
	mflr 4
	std 4, -16(1)
	std 2, -24(1)
	std 3, -32(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_10
	mr 4, 3
	ld 3, -32(1)
	ld 2, -24(1)
	add	3, 3, 4
	ld 4, -16(1)
	mtlr 4
	ld 4, -8(1)
	addi 1, 1, 288

# WAS addis 3, 2, 15+foo@toc@ha
	addi 1, 1, -288
	std 4, -8(1)
	mflr 4
	std 4, -16(1)
	std 2, -24(1)
	std 3, -32(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_15
	mr 4, 3
	ld 3, -32(1)
	ld 2, -24(1)
	add	3, 2, 4
	ld 4, -16(1)
	mtlr 4
	ld 4, -8(1)
	addi 1, 1, 288
# WAS addi 3, 3, 20+foo@toc@l
	addi 1, 1, -288
	std 4, -8(1)
	mflr 4
	std 4, -16(1)
	std 2, -24(1)
	std 3, -32(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_20
	mr 4, 3
	ld 3, -32(1)
	ld 2, -24(1)
	add	3, 3, 4
	ld 4, -16(1)
	mtlr 4
	ld 4, -8(1)
	addi 1, 1, 288

# WAS addis 4, 2, foo@toc@ha
	addi 1, 1, -288
	std 3, -8(1)
	mflr 3
	std 3, -16(1)
	std 2, -24(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha
	ld 2, -24(1)
	add	4, 2, 3
	ld 3, -16(1)
	mtlr 3
	ld 3, -8(1)
	addi 1, 1, 288
# WAS addi 4, 4, foo@toc@l
	addi 1, 1, -288
	std 3, -8(1)
	mflr 3
	std 3, -16(1)
	std 2, -24(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l
	ld 2, -24(1)
	add	4, 4, 3
	ld 3, -16(1)
	mtlr 3
	ld 3, -8(1)
	addi 1, 1, 288

# WAS addis 5, 2, 5+foo@toc@ha
	addi 1, 1, -288
	std 3, -8(1)
	mflr 3
	std 3, -16(1)
	std 2, -24(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_5
	ld 2, -24(1)
	add	5, 2, 3
	ld 3, -16(1)
	mtlr 3
	ld 3, -8(1)
	addi 1, 1, 288
# WAS ld 5, 10+foo@toc@l(5)
	addi 1, 1, -288
	std 3, -8(1)
	mflr 3
	std 3, -16(1)
	std 2, -24(1)
	bl .Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_10
	ld 2, -24(1)
	add 3, 3, 5
	ld 5, 0(3)
	ld 3, -16(1)
	mtlr 3
	ld 3, -8(1)
	addi 1, 1, 288
.text
BORINGSSL_bcm_text_end:
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha:
	addi 2, 0, 0
	addi 3, 0, 0
	addis 3, 2, .Lfoo_local_target@toc@ha
	blr
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_15, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_15:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_15:
	addi 2, 0, 0
	addi 3, 0, 0
	addis 3, 2, .Lfoo_local_target@toc@ha+15
	blr
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_5, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_5:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_ha_offset_5:
	addi 2, 0, 0
	addi 3, 0, 0
	addis 3, 2, .Lfoo_local_target@toc@ha+5
	blr
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l:
	addi 2, 0, 0
	addi 3, 2, .Lfoo_local_target@toc@l
	blr
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_10, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_10:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_10:
	addi 2, 0, 0
	addi 3, 2, .Lfoo_local_target@toc@l+10
	blr
.type bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_20, @function
bcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_20:
.Lbcm_loadtoc__dot_Lfoo_local_target_at_toc_at_l_offset_20:
	addi 2, 0, 0
	addi 3, 2, .Lfoo_local_target@toc@l+20
	blr
BORINGSSL_bcm_set_toc:
.LBORINGSSL_bcm_set_toc:
	mflr 2
	std 12, -8(1)
	bcl 20,31,$+4
0:
	mflr 12
	mtlr 2
	addis 2,12,.TOC.-0b@ha
	addi 2,2,.TOC.-0b@l
	ld 12, -8(1)
	blr
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
