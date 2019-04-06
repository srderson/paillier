package paillier

import (
	"crypto/rand"
	"math/big"
)

// PublicKey is the key that may be shared
type PublicKey struct {
	Length int
	N      *big.Int
	NSq    *big.Int
	G      *big.Int
}

// PrivateKey must be kept secret
type PrivateKey struct {
	Length    int
	PublicKey *PublicKey
	L         *big.Int
	U         *big.Int
	Threshold *big.Int
}

// NewKeyPair generates a new public and private key. The key length must be large enough to encrypt the message. The
// threshold should be greater than the maximum integer that will be encrypted.
func NewKeyPair(keyLength, threshold int) (*PublicKey, *PrivateKey, error) {

	p1, err := rand.Prime(rand.Reader, keyLength)
	if err != nil {
		return nil, nil, err
	}
	p2, err := rand.Prime(rand.Reader, keyLength)
	if err != nil {
		return nil, nil, err
	}

	n := new(big.Int).Mul(p1, p2)

	publicKey := &PublicKey{
		Length: keyLength,
		N:      n,
		NSq:    new(big.Int).Mul(n, n),
		G:      new(big.Int).Add(n, one),
	}

	// (prime1 - 1) * (prime2 - 1)
	l := new(big.Int).Mul(p1.Sub(p1, one), p2.Sub(p2, one))

	privateKey := &PrivateKey{
		Length:    keyLength,
		PublicKey: publicKey,
		L:         l,
		U:         new(big.Int).ModInverse(l, n),
		Threshold: big.NewInt(int64(threshold)),
	}

	return publicKey, privateKey, nil
}

func requirePublicKeysEqual(x, y *PublicKey) {
	if x.Length == y.Length && x.N.Cmp(y.N) == 0 && x.NSq.Cmp(y.NSq) == 0 && x.G.Cmp(y.G) == 0 {
		return
	}
	panic("public keys not equal")
}
