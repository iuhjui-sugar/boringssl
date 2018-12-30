/* Copyright (c) 2018, Google Inc.
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

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

var (
	p256                  elliptic.Curve
	zero, one, p, R, Rinv *big.Int
	deterministicRand     io.Reader
)

type coordinates int

const (
	affine coordinates = iota
	jacobian
)

func init() {
	p256 = elliptic.P256()

	zero = new(big.Int)
	one = new(big.Int).SetInt64(1)

	p = p256.Params().P

	R = new(big.Int)
	R.SetBit(R, 256, 1)
	R.Mod(R, p)

	Rinv = new(big.Int).ModInverse(R, p)

	deterministicRand = newDeterministicRand()
}

func modMul(z, x, y *big.Int) *big.Int {
	z.Mul(x, y)
	return z.Mod(z, p)
}

func toMontgomery(z, x *big.Int) *big.Int {
	return modMul(z, x, R)
}

func fromMontgomery(z, x *big.Int) *big.Int {
	return modMul(z, x, Rinv)
}

func isAffineInfinity(x, y *big.Int) bool {
	// Infinity, in affine coordinates, is represented as (0, 0) by
	// both Go and p256-x86_64-asm.pl.
	return x.Sign() == 0 && y.Sign() == 0
}

func randNonZeroInt(max *big.Int) *big.Int {
	for {
		r, err := rand.Int(deterministicRand, max)
		if err != nil {
			panic(err)
		}
		if r.Sign() != 0 {
			return r
		}
	}
}

func randPoint() (x, y *big.Int) {
	k := randNonZeroInt(p256.Params().N)
	return p256.ScalarBaseMult(k.Bytes())
}

func toJacobian(xIn, yIn *big.Int) (x, y, z *big.Int) {
	if isAffineInfinity(xIn, yIn) {
		// The Jacobian representation of infinity is z = 0 with
		// randomized x and y.
		x = randNonZeroInt(p)
		y = randNonZeroInt(p)
		z = zero
		return
	}

	z = randNonZeroInt(p)

	// x = x*z^2
	y = modMul(new(big.Int), z, z)
	x = modMul(new(big.Int), xIn, y)

	// y = y*z^3
	modMul(y, y, z)
	modMul(y, y, yIn)
	return
}

func printMontgomery(name string, a *big.Int) {
	a = toMontgomery(new(big.Int), a)
	fmt.Printf("%s = %064x\n", name, a)
}

func printTestCase(ax, ay *big.Int, aCoord coordinates, bx, by *big.Int, bCoord coordinates) {
	rx, ry := p256.Add(ax, ay, bx, by)

	var az *big.Int
	if aCoord == jacobian {
		ax, ay, az = toJacobian(ax, ay)
	} else if isAffineInfinity(ax, ay) {
		az = zero
	} else {
		az = one
	}

	var bz *big.Int
	if bCoord == jacobian {
		bx, by, bz = toJacobian(bx, by)
	} else if isAffineInfinity(bx, by) {
		bz = zero
	} else {
		bz = one
	}

	fmt.Printf("Test = PointAdd\n")
	printMontgomery("A.X", ax)
	printMontgomery("A.Y", ay)
	printMontgomery("A.Z", az)
	printMontgomery("B.X", bx)
	printMontgomery("B.Y", by)
	printMontgomery("B.Z", bz)
	printMontgomery("Result.X", rx)
	printMontgomery("Result.Y", ry)
	fmt.Printf("\n")
}

func main() {
	fmt.Printf("# ∞ + ∞ = ∞.\n")
	printTestCase(zero, zero, affine, zero, zero, affine)

	fmt.Printf("# ∞ + ∞ = ∞, with an alternate representation of ∞.\n")
	printTestCase(zero, zero, jacobian, zero, zero, jacobian)

	gx, gy := p256.Params().Gx, p256.Params().Gy
	fmt.Printf("# g + ∞ = g.\n")
	printTestCase(gx, gy, affine, zero, zero, affine)

	fmt.Printf("# g + ∞ = g, with an alternate representation of ∞.\n")
	printTestCase(gx, gy, affine, zero, zero, jacobian)

	fmt.Printf("# g + -g = ∞.\n")
	minusGy := new(big.Int).Sub(p, gy)
	printTestCase(gx, gy, affine, gx, minusGy, affine)

	fmt.Printf("# Test some random Jacobian sums.\n")
	for i := 0; i < 4; i++ {
		ax, ay := randPoint()
		bx, by := randPoint()
		printTestCase(ax, ay, jacobian, bx, by, jacobian)
	}

	fmt.Printf("# Test some random Jacobian doublings.\n")
	for i := 0; i < 4; i++ {
		ax, ay := randPoint()
		printTestCase(ax, ay, jacobian, ax, ay, jacobian)
	}

	fmt.Printf("# Test some random affine sums.\n")
	for i := 0; i < 4; i++ {
		ax, ay := randPoint()
		bx, by := randPoint()
		printTestCase(ax, ay, affine, bx, by, affine)
	}

	fmt.Printf("# Test some random affine doublings.\n")
	for i := 0; i < 4; i++ {
		ax, ay := randPoint()
		printTestCase(ax, ay, affine, ax, ay, affine)
	}
}

type deterministicRandom struct {
	stream cipher.Stream
}

func newDeterministicRand() io.Reader {
	block, err := aes.NewCipher(make([]byte, 128/8))
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, make([]byte, block.BlockSize()))
	return &deterministicRandom{stream}
}

func (r *deterministicRandom) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}
	r.stream.XORKeyStream(b, b)
	return len(b), nil
}
