package crypto

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// Share represents a Shamir secret share (i, s_i).
type Share struct {
	Index int    `json:"index"`
	Value []byte `json:"value"` // scalar, fixed length
}

// Commitment is a Feldman commitment C_j = a_j * G.
type Commitment struct {
	Point []byte `json:"point"`
}

// Signature is a standard Schnorr signature (R, z).
type Signature struct {
	R []byte `json:"R"` // uncompressed EC point
	Z []byte `json:"z"` // scalar
}

// CurveCtx bundles curve parameters.
type CurveCtx struct {
	Curve elliptic.Curve
	N     *big.Int
}

// NewCurveCtx returns a P-256 context.
func NewCurveCtx() *CurveCtx {
	c := elliptic.P256()
	return &CurveCtx{
		Curve: c,
		N:     new(big.Int).Set(c.Params().N),
	}
}

// ScalarFromBytes parses a scalar mod N.
func (c *CurveCtx) ScalarFromBytes(b []byte) (*big.Int, error) {
	if len(b) == 0 {
		return nil, errors.New("empty scalar")
	}
	x := new(big.Int).SetBytes(b)
	x.Mod(x, c.N)
	if x.Sign() == 0 {
		return nil, errors.New("scalar is zero mod N")
	}
	return x, nil
}

// ScalarToBytes serializes a scalar to fixed 32 bytes.
func (c *CurveCtx) ScalarToFixedBytes(x *big.Int) ([]byte, error) {
	if x == nil {
		return nil, errors.New("nil scalar")
	}

	if x.Sign() < 0 {
		return nil, errors.New("negative scalar")
	}

	// scalari devono stare in [1, N-1]
	if x.Cmp(c.N) >= 0 { // because >= is not accepted for BigInt
		return nil, errors.New("scalar >= group order")
	}

	out := make([]byte, 32) // creating a slice of 32 bytes made of zeros
	xb := x.Bytes()

	if len(xb) > len(out) {
		return nil, errors.New("scalar too large to encode")
	}

	copy(out[len(out)-len(xb):], xb) // padding with zeros (in the first places)
	return out, nil
}
