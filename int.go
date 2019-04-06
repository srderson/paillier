package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var one = big.NewInt(1)
var negOne = big.NewInt(-1)

// Int represents and encrypted integer using the Paillier cryptosystem. The public key used to encrypt the integer is
// also included.
// A notable feature of the Paillier cryptosystem is its homomorphic properties along with its non-deterministic
// encryption.
type Int struct {
	Cipher    *big.Int
	PublicKey *PublicKey
}

// NewInt returns the encryption of x using the given public key.
func NewInt(publicKey *PublicKey, x *big.Int) *Int {

	r, err := rand.Prime(rand.Reader, publicKey.Length)
	if err != nil {
		panic(err)
	}

	if publicKey.N.Cmp(x) < 1 {
		panic(fmt.Sprintf("public key length %d is too small to encrypt %d", publicKey.Length, x))
	}

	z := &Int{
		Cipher: new(big.Int),
	}

	// g^m * r^n mod n^2
	z.Cipher.Exp(publicKey.G, x, publicKey.NSq)
	rn := new(big.Int).Exp(r, publicKey.N, publicKey.NSq)
	z.Cipher.Mul(z.Cipher, rn).Mod(z.Cipher, publicKey.NSq)
	z.PublicKey = publicKey

	return z
}

// Decrypt returns the decrypted value of z using the given private key.
// If z.PublicKey != privateKey.PublicKey, a pubic-keys-not-equal run-time panic occurs.
func (z *Int) Decrypt(privateKey *PrivateKey) *big.Int {

	requirePublicKeysEqual(z.PublicKey, privateKey.PublicKey)

	if privateKey.PublicKey.NSq.Cmp(z.Cipher) < 1 {
		panic(fmt.Sprintf("public key length %d is too small to decrypt cipher %d",
			privateKey.PublicKey.Length, z.Cipher.Bytes()))
	}

	// ((z.Cipher^privateKey.L mod n^2) / n) * u mod n
	z.Cipher.Exp(z.Cipher, privateKey.L, privateKey.PublicKey.NSq).Sub(z.Cipher, one).Div(z.Cipher,
		privateKey.PublicKey.N).Mod(z.Cipher.Mul(z.Cipher, privateKey.U), privateKey.PublicKey.N)

	// check if m is negative
	if z.Cipher.Cmp(privateKey.Threshold) == 1 {
		// m = m - n
		z.Cipher.Sub(z.Cipher, privateKey.PublicKey.N)
	}

	return z.Cipher
}

// Add sets z to the encrypted sum x+y and returns z.
// If x.PublicKey != y.PublicKey, a pubic-keys-not-equal run-time panic occurs.
func (z *Int) Add(x, y *Int) *Int {

	requirePublicKeysEqual(x.PublicKey, y.PublicKey)
	z.init()

	// x * y mod n^2
	z.Cipher.Mul(x.Cipher, y.Cipher).Mod(z.Cipher, x.PublicKey.NSq)
	z.PublicKey = x.PublicKey

	return z
}

// Sub sets z to the encrypted difference x-y and returns z.
// If x.PublicKey != y.PublicKey, a pubic-keys-not-equal run-time panic occurs.
func (z *Int) Sub(x, y *Int) *Int {

	requirePublicKeysEqual(x.PublicKey, y.PublicKey)
	z.init()

	// x * -y mod n^2
	z.Cipher.Mul(x.Cipher, z.MulPlaintext(y, negOne).Cipher).Mod(z.Cipher, x.PublicKey.NSq)
	z.PublicKey = x.PublicKey

	return z
}

// AddPlaintext sets z to the encrypted sum x+y and returns z.
func (z *Int) AddPlaintext(x *Int, y *big.Int) *Int {

	z.init()

	// x * g^y mod n^2
	z.Cipher.Exp(x.PublicKey.G, y, x.PublicKey.NSq).Mul(x.Cipher, z.Cipher).Mod(z.Cipher, x.PublicKey.NSq)
	z.PublicKey = x.PublicKey

	return z
}

// MulPlaintext sets z to the encrypted product x*y and returns z.
func (z *Int) MulPlaintext(x *Int, y *big.Int) *Int {

	z.init()

	// x^y mod n^2
	z.Cipher.Exp(x.Cipher, y, x.PublicKey.NSq)
	z.PublicKey = x.PublicKey

	return z
}

// DivPlaintext sets z to the encrypted quotient x/y and returns z.
// If y == 0, a division-by-zero run-time panic occurs.
// DivPlaintext will return an invalid result in cases where y does not divide x.
func (z *Int) DivPlaintext(x *Int, y *big.Int) *Int {

	z.init()

	if y.Int64() == 0 {
		panic("division by 0")
	}

	// x^(y^-1 mod n) mod n^2
	z.Cipher.ModInverse(y, x.PublicKey.N).Exp(x.Cipher, z.Cipher, x.PublicKey.NSq)
	z.PublicKey = x.PublicKey

	return z

}

func (z *Int) init() {
	if z.Cipher == nil {
		z.Cipher = new(big.Int)
	}
}
