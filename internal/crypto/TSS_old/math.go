package crypto

import (
	"crypto/rand"
	"math/big"
)

func randScalar(N *big.Int) (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, N) // using crypto/rand, more secure than math/rand
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

func modAdd(a, b, N *big.Int) *big.Int {
	x := new(big.Int).Add(a, b)
	x.Mod(x, N)
	return x
}

func modMul(a, b, N *big.Int) *big.Int {
	x := new(big.Int).Mul(a, b)
	x.Mod(x, N)
	return x
}

func powInt(i, j int, N *big.Int) *big.Int {
	return new(big.Int).Exp(
		big.NewInt(int64(i)),
		big.NewInt(int64(j)),
		N,
	)
}
