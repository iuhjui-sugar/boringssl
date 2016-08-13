// Copyright (c) 2016, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"fmt"
	"math/big"
	"strings"
)

func bigFromHex(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic(s)
	}
	return x
}

type curve struct {
	name  string
	nid   string
	field *big.Int
	a, b  *big.Int
	x, y  *big.Int
	order *big.Int
}

var curves = []curve{
	{
		"P224",
		"NID_secp224r1",
		bigFromHex("ffffffffffffffffffffffffffffffff000000000000000000000001"),
		bigFromHex("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
		bigFromHex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
		bigFromHex("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
		bigFromHex("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
		bigFromHex("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"),
	},
	{
		"P256",
		"NID_X9_62_prime256v1",
		bigFromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
		bigFromHex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
		bigFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
		bigFromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		bigFromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
		bigFromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	},
	{
		"P384",
		"NID_secp384r1",
		bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
		bigFromHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc"),
		bigFromHex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
		bigFromHex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
		bigFromHex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
		bigFromHex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
	},
	{
		"P521",
		"NID_secp521r1",
		bigFromHex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		bigFromHex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc"),
		bigFromHex("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
		bigFromHex("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
		bigFromHex("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),
		bigFromHex("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),
	},
}

func printBignumData(name string, x *big.Int) {
	if x.Sign() < 0 {
		panic("x is negative")
	}

	mask := new(big.Int).SetUint64(1<<64 - 1)

	fmt.Printf("  static const BN_ULONG %s[] = {\n", name)
	x = new(big.Int).Set(x)
	for x.Sign() > 0 {
		// Extract the least-significant uint64 from |x|.
		word := new(big.Int).And(x, mask).Uint64()
		x = x.Rsh(x, 64)

		if word < 1<<32 && x.Sign() == 0 {
			// If the final word is under 1<<32, emit it directly
			// rather than use TOBN so it is correct in both 32-bit
			// and 64-bit builds.
			fmt.Printf("      0x%08x,\n", word)
		} else {
			fmt.Printf("      TOBN(0x%08x, 0x%08x),\n", word>>32, word&(1<<32-1))
		}
	}
	fmt.Printf("  };\n\n")
}

func getMontgomeryR(n *big.Int, bits uint) *big.Int {
	if n.Sign() <= 0 {
		panic("n must be positive")
	}
	if n.Bits()[0]&1 == 0 {
		panic("n must be odd")
	}

	r := new(big.Int).SetUint64(1)
	return r.Lsh(r, (uint(n.BitLen())+bits-1)/bits*bits)
}

func modMul(a, b, n *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	return r.Mod(r, n)
}

func printMontgomery(name string, r, n *big.Int, bits uint) {
	printBignumData(name+"MontgomeryR2", modMul(r, r, n))

	// Compute -N^-1 (mod R).
	n0 := new(big.Int).Neg(n)
	n0.Mod(n0, r)
	n0.ModInverse(n0, r)

	// Retain only the bottom word of n0.
	mask := new(big.Int).SetUint64(1<<64 - 1)
	n0.And(n0, mask)
	n0Word := n0.Uint64()

	fmt.Printf("  static const BN_MONT_CTX %sMontgomery = {\n", name)
	fmt.Printf("      STATIC_BIGNUM(%sMontgomeryR2),\n", name)
	fmt.Printf("      STATIC_BIGNUM(%s),\n", name)
	if bits == 32 {
		fmt.Printf("      {0x%08x, 0x%08x}\n", n0Word&((1<<32)-1), n0Word>>32)
	} else {
		fmt.Printf("      {UINT64_C(0x%016x), 0}\n", n0Word)
	}
	fmt.Printf("  };\n\n")
}

func printCurve(curve curve) {
	// a is always -3 for built-in curves.
	fieldMinusThree := new(big.Int).Sub(curve.field, new(big.Int).SetUint64(3))
	if fieldMinusThree.Cmp(curve.a) != 0 {
		panic("a is not -3 (mod p).")
	}

	fmt.Printf("const EC_GROUP *EC_%s(void) {\n", strings.ToLower(curve.name))

	// Print data for the field and order.
	printBignumData("kField", curve.field)
	printBignumData("kOrder", curve.order)

	// Print data for a, b, x, y, one, and the associated Montgomery
	// context, if any.
	fmt.Printf("#if defined(EC_%s_NO_MONTGOMERY)\n\n", curve.name)
	{
		printBignumData("kA", curve.a)
		printBignumData("kB", curve.b)
		printBignumData("kX", curve.x)
		printBignumData("kY", curve.y)
		printBignumData("kOne", new(big.Int).SetUint64(1))
	}
	fmt.Printf("#else /* NO_MONTGOMERY */\n\n")
	{
		// The Montgomery values may depend on bittedness.
		fmt.Printf("#if BN_BITS2 == 32\n\n")
		{
			r := getMontgomeryR(curve.field, 32)
			printMontgomery("kField", r, curve.field, 32)
			printBignumData("kA", modMul(curve.a, r, curve.field))
			printBignumData("kB", modMul(curve.b, r, curve.field))
			printBignumData("kX", modMul(curve.x, r, curve.field))
			printBignumData("kY", modMul(curve.y, r, curve.field))
			printBignumData("kOne", new(big.Int).Mod(r, curve.field))
		}
		fmt.Printf("#elif BN_BITS2 == 64\n\n")
		{
			r := getMontgomeryR(curve.field, 64)
			printMontgomery("kField", r, curve.field, 64)
			printBignumData("kA", modMul(curve.a, r, curve.field))
			printBignumData("kB", modMul(curve.b, r, curve.field))
			printBignumData("kX", modMul(curve.x, r, curve.field))
			printBignumData("kY", modMul(curve.y, r, curve.field))
			printBignumData("kOne", new(big.Int).Mod(r, curve.field))
		}
		fmt.Printf("#endif /* BN_BITS2 */\n\n")
	}
	fmt.Printf("#endif /* NO_MONTGOMERY */\n\n")

	// Print the Montgomery context for the order, used in ECDSA.
	fmt.Printf("#if BN_BITS2 == 32\n\n")
	printMontgomery("kOrder", getMontgomeryR(curve.order, 32), curve.order, 32)
	fmt.Printf("#elif BN_BITS2 == 64\n\n")
	printMontgomery("kOrder", getMontgomeryR(curve.order, 64), curve.order, 64)
	fmt.Printf("#endif /* BN_BITS2 */\n\n")

	fmt.Printf("  static const EC_POINT kGenerator = {\n")
	fmt.Printf("      EC_METHOD_%s,\n", curve.name)
	fmt.Printf("      STATIC_BIGNUM(kX),\n")
	fmt.Printf("      STATIC_BIGNUM(kY),\n")
	fmt.Printf("      STATIC_BIGNUM(kOne),\n")
	fmt.Printf("  };\n\n")

	fmt.Printf("  static const EC_GROUP kGroup = {\n")
	fmt.Printf("      EC_METHOD_%s,\n", curve.name)
	fmt.Printf("      (EC_POINT *)&kGenerator,\n")
	fmt.Printf("      STATIC_BIGNUM(kOrder),\n")
	fmt.Printf("      %s,\n", curve.nid)
	fmt.Printf("      (BN_MONT_CTX *)&kOrderMontgomery,\n")
	fmt.Printf("      STATIC_BIGNUM(kField),\n")
	fmt.Printf("      STATIC_BIGNUM(kA),\n")
	fmt.Printf("      STATIC_BIGNUM(kB),\n")
	fmt.Printf("      1 /* a_is_minus_three */,\n")
	fmt.Printf("#if defined(EC_%s_NO_MONTGOMERY)\n", curve.name)
	fmt.Printf("      NULL,\n")
	fmt.Printf("#else\n")
	fmt.Printf("      (BN_MONT_CTX *)&kFieldMontgomery,\n")
	fmt.Printf("#endif\n")
	fmt.Printf("      STATIC_BIGNUM(kOne),\n")
	fmt.Printf("  };\n\n")

	fmt.Printf("  return &kGroup;\n")
	fmt.Printf("}\n\n")
}

func main() {
	fmt.Printf(`/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* This file was generated by generate_built_in_curves.go. */

#include <openssl/ec.h>

#include <openssl/bn.h>
#include <openssl/nid.h>

#include "../bn/internal.h"
#include "internal.h"


`)
	for _, curve := range curves {
		printCurve(curve)
	}
}
