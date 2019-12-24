# Paillier

Homomorphic encryption using the [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) implemented in Go

The following operations are supported
- Addition of two encrypted integers
- Subtraction of two encrypted integers
- Addition of an encrypted and plaintext integer
- Multiplication of an encrypted and plaintext integer
- Division of an encrypted integer by a plaintext integer in cases where x mod y == 0

See [int_test.go](https://github.com/srderson/paillier/blob/master/int_test.go) for example usage.
