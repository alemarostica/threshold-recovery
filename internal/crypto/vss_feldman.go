package crypto

import (
	"crypto/elliptic"
	"errors"
	"math/big"
)

// SplitVSS splits a secret using Shamir and produces Feldman commitments.
func SplitVSS(ctx *CurveCtx, secret []byte, n, k int) ([]Share, []Commitment, error) {
	if k < 2 || n < k {
		return nil, nil, errors.New("invalid (n,k)")
	}

	//creation of the secret s (a0)
	s, err := ctx.ScalarFromBytes(secret)
	if err != nil {
		return nil, nil, err
	}

	// Polynomial coefficients
	coeffs := make([]*big.Int, k)
	coeffs[0] = s
	for j := 1; j < k; j++ {
		coeffs[j], err = randScalar(ctx.N) // random coefficients a1,...ak-1
		if err != nil {
			return nil, nil, err
		}
	}

	// Commitments
	comms := make([]Commitment, k)
	for j := range k {
		x, y := ctx.Curve.ScalarBaseMult(coeffs[j].Bytes()) // (x,y) = aj*G (G=Base Point)
		pointBytes := elliptic.Marshal(ctx.Curve, x, y)
		comms[j] = pointBytes
	}

	// Shares
	shares := make([]Share, n)
	for i := 1; i <= n; i++ {
		y := coeffs[0]

		// Evaluate Shamir polynomial at x = i
		for j := 1; j < k; j++ {
			y = modAdd(y, modMul(coeffs[j], powInt(i, j, ctx.N), ctx.N), ctx.N)
		}
		val, err := ctx.ScalarToFixedBytes(y)
		if err != nil {
			return nil, nil, err
		}

		shares[i-1] = Share{
			ID: i,   // i
			Value: val, // f(i)
		}

	}

	return shares, comms, nil
}

// VerifyShareFeldman checks share correctness.
func VerifyShareFeldman(ctx *CurveCtx, sh Share, comms []Commitment) bool {
	si := new(big.Int).SetBytes(sh.Value) // turn sh into an integer value
	si.Mod(si, ctx.N)
	if si.Sign() == 0 {
		return false
	}

	// LHS
	lx, ly := ctx.Curve.ScalarBaseMult(si.Bytes()) //(x,y) = si*G (i.e. g^si)

	// RHS
	var rx, ry *big.Int
	for j, c := range comms {
		cx, cy := elliptic.Unmarshal(ctx.Curve, c)  // point corresponding to commitment
		w := powInt(sh.ID, j, ctx.N)                   //i^j mod ctx.N
		tx, ty := ctx.Curve.ScalarMult(cx, cy, w.Bytes()) // (tx,ty)=i^j(aj*G)
		if rx == nil {
			rx, ry = tx, ty
		} else {
			rx, ry = ctx.Curve.Add(rx, ry, tx, ty) // sum the poit T to the total
		}
	}

	return lx.Cmp(rx) == 0 && ly.Cmp(ry) == 0 //LHS==RHS (si*G)==(sum aj*i^j)*G
}
