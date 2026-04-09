package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
	"sort"
)

// ============================
// Helpers: indices / validation
// ============================

// NormalizeIndices returns a sorted copy of indices and ensures they are unique and non-empty.
func NormalizeIndices(indices []int) ([]int, error) {
	if len(indices) == 0 {
		return nil, errors.New("empty index set")
	}
	cp := append([]int(nil), indices...)
	sort.Ints(cp) // in order to sort the list
	for i := 1; i < len(cp); i++ {
		if cp[i] == cp[i-1] {
			return nil, errors.New("duplicate index in set") // if there are two equals indexes (ow the denominator of lagrange could be zero)
		}
	}
	return cp, nil
}

// ValidatePointBytes checks that b is an uncompressed EC point on the given curve.
// For P-256 this is 65 bytes: 0x04 || X(32) || Y(32).
func ValidatePointBytes(curve elliptic.Curve, b []byte) (*big.Int, *big.Int, error) {
	if curve == nil {
		return nil, nil, errors.New("nil curve")
	}

	pLen := 1 + 2*((curve.Params().BitSize+7)/8)
	if len(b) != pLen || b[0] != 4 {
		return nil, nil, errors.New("invalid point encoding")
	}

	x, y := elliptic.Unmarshal(curve, b)
	if x == nil || y == nil {
		return nil, nil, errors.New("invalid point (unmarshal failed)")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("point not on curve")
	}

	return x, y, nil
}

// ============================
// Challenge functions
// ============================

// ChallengeStandard computes e = H(R || P || msg) mod N.
func ChallengeStandard(ctx *CurveCtx, R, P, msg []byte) (*big.Int, error) {
	if ctx == nil {
		return nil, errors.New("nil ctx")
	}
	h := sha256.New()
	h.Write(R)
	h.Write(P)
	h.Write(msg)

	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, ctx.N)
	if e.Sign() == 0 {
		// Optional hardening: reject e=0
		return nil, errors.New("challenge is zero")
	}
	return e, nil
}

// ChallengeSessionBound computes e = H(R || P || msg || sess.ID || sess.IndexHash) mod N.
func ChallengeSessionBound(ctx *CurveCtx, sess *Session, R, P, msg []byte) (*big.Int, error) {
	if ctx == nil {
		return nil, errors.New("nil ctx")
	}
	if sess == nil || len(sess.ID) == 0 || len(sess.IndexHash) == 0 {
		return nil, errors.New("nil/invalid session")
	}

	h := sha256.New()
	h.Write(R)
	h.Write(P)
	h.Write(msg)
	h.Write(sess.ID)
	h.Write(sess.IndexHash)

	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, ctx.N)
	if e.Sign() == 0 {
		// Optional hardening: reject e=0
		return nil, errors.New("challenge is zero")
	}
	return e, nil
}

// ============================
// Lagrange coefficients
// ============================

// LagrangeCoefficients returns lambda_i for reconstruction at x=0 using the given indices.
func LagrangeCoefficients(ctx *CurveCtx, indices []int) (map[int]*big.Int, error) {
	if ctx == nil {
		return nil, errors.New("nil ctx")
	}

	ids, err := NormalizeIndices(indices) // in order to normalize the list of indices (ex to cancel duplicates)
	if err != nil {
		return nil, err
	}

	l := make(map[int]*big.Int, len(ids))
	for _, i := range ids {
		num := big.NewInt(1)
		den := big.NewInt(1)

		// lambda_i = Π_{j!=i} (-j)/(i-j) mod N
		for _, j := range ids {
			if i == j {
				continue
			}
			num = modMul(num, big.NewInt(int64(-j)), ctx.N)
			den = modMul(den, big.NewInt(int64(i-j)), ctx.N)
		}

		denInv := new(big.Int).ModInverse(den, ctx.N)
		if denInv == nil {
			return nil, errors.New("non-invertible denominator (bad indices?)")
		}
		l[i] = modMul(num, denInv, ctx.N)
	}

	return l, nil
}

// ============================
// Combine R
// ============================

// CombineRStrict sums R_i for all signers and returns R = Σ R_i, with validation.
func CombineRStrict(ctx *CurveCtx, reveals map[int][]byte, signers []int) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil ctx")
	}

	ids, err := NormalizeIndices(signers)
	if err != nil {
		return nil, err
	}

	var rx, ry *big.Int
	for _, i := range ids {
		Ri, ok := reveals[i]
		if !ok {
			return nil, errors.New("missing reveal for signer")
		}

		x, y, err := ValidatePointBytes(ctx.Curve, Ri)
		if err != nil {
			return nil, err
		}

		if rx == nil {
			rx, ry = x, y
		} else {
			rx, ry = ctx.Curve.Add(rx, ry, x, y)

			// Hardening: some implementations may return (nil,nil) for the point at infinity
			// or for invalid intermediate states (defensive check).
			if rx == nil || ry == nil {
				return nil, errors.New("invalid aggregated R (point at infinity)")
			}
			if !ctx.Curve.IsOnCurve(rx, ry) {
				return nil, errors.New("invalid aggregated R (not on curve)")
			}
		}
	}

	// Defensive final check
	if rx == nil || ry == nil {
		return nil, errors.New("invalid aggregated R")
	}

	return elliptic.Marshal(ctx.Curve, rx, ry), nil
}

// ============================
// Partial signature
// ============================

// PartialSignStrict computes z_i = r_i + e*lambda_i*s_i mod N, returned as fixed 32-byte scalar.
// Requires sh.Index == ns.Index and uses ctx.ScalarFromBytes / ctx.ScalarToFixedBytes for consistency.
func PartialSignStrict(ctx *CurveCtx, sh Share, ns *NonceShare, lambda, e *big.Int) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil ctx")
	}
	if ns == nil {
		return nil, errors.New("nil nonce share")
	}
	if sh.Index != ns.Index {
		return nil, errors.New("index mismatch")
	}
	if lambda == nil || e == nil {
		return nil, errors.New("nil lambda or challenge")
	}

	// Parse s_i and reject zero.
	si, err := ctx.ScalarFromBytes(sh.Value)
	if err != nil {
		return nil, err
	}

	// z_i = r_i + e*lambda*s_i mod N
	term := modMul(modMul(e, lambda, ctx.N), si, ctx.N)
	z := modAdd(ns.ri, term, ctx.N)

	return ctx.ScalarToFixedBytes(z)
}

// ============================
// Combine signature
// ============================

// CombineSignatureStrict sums partial signatures z_i for signers and returns (R, z).
func CombineSignatureStrict(ctx *CurveCtx, R []byte, partials map[int][]byte, signers []int) (Signature, error) {
	if ctx == nil {
		return Signature{}, errors.New("nil ctx")
	}

	ids, err := NormalizeIndices(signers)
	if err != nil {
		return Signature{}, err
	}

	// Validate R
	if _, _, err := ValidatePointBytes(ctx.Curve, R); err != nil {
		return Signature{}, err
	}

	z := big.NewInt(0)
	for _, i := range ids {
		ziBytes, ok := partials[i]
		if !ok {
			return Signature{}, errors.New("missing partial signature for signer")
		}

		// Accept any scalar mod N (reject zero to be strict; you can loosen if needed)
		zi, err := ctx.ScalarFromBytes(ziBytes)
		if err != nil {
			return Signature{}, err
		}

		z = modAdd(z, zi, ctx.N)
	}

	if z.Sign() == 0 {
		return Signature{}, errors.New("invalid signature scalar (z = 0)")
	}

	zb, err := ctx.ScalarToFixedBytes(z)
	if err != nil {
		return Signature{}, err
	}

	return Signature{R: R, Z: zb}, nil
}

// ============================
// Verify signature
// ============================

// VerifySignatureStandard verifies zG = R + eP where e = H(R||P||msg) (for challenge standard)
func VerifySignatureStandard(ctx *CurveCtx, P, msg []byte, sig Signature) bool {
	if ctx == nil {
		return false
	}

	Rx, Ry, err := ValidatePointBytes(ctx.Curve, sig.R)
	if err != nil {
		return false
	}
	Px, Py, err := ValidatePointBytes(ctx.Curve, P)
	if err != nil {
		return false
	}

	z, err := ctx.ScalarFromBytes(sig.Z)
	if err != nil {
		return false
	}
	zb, err := ctx.ScalarToFixedBytes(z)
	if err != nil {
		return false
	}

	e, err := ChallengeStandard(ctx, sig.R, P, msg)
	if err != nil {
		return false
	}

	// LHS: z*G
	lx, ly := ctx.Curve.ScalarBaseMult(zb)

	// RHS: R + e*P
	eb, err := ctx.ScalarToFixedBytes(e)
	if err != nil {
		// errore interno / violazione delle assunzioni
		return false
	}

	ex, ey := ctx.Curve.ScalarMult(Px, Py, eb)
	rx, ry := ctx.Curve.Add(Rx, Ry, ex, ey)

	return lx.Cmp(rx) == 0 && ly.Cmp(ry) == 0
}

// VerifySignatureSessionBound verifies zG = R + eP where e = H(R||P||msg||sess.ID||sess.IndexHash).
func VerifySignatureSessionBound(ctx *CurveCtx, sess *Session, P, msg []byte, sig Signature) bool {
	if ctx == nil || sess == nil {
		return false
	}

	Rx, Ry, err := ValidatePointBytes(ctx.Curve, sig.R)
	if err != nil {
		return false
	}
	Px, Py, err := ValidatePointBytes(ctx.Curve, P)
	if err != nil {
		return false
	}

	z, err := ctx.ScalarFromBytes(sig.Z)
	if err != nil {
		return false
	}
	zb, err := ctx.ScalarToFixedBytes(z)
	if err != nil {
		return false
	}

	e, err := ChallengeSessionBound(ctx, sess, sig.R, P, msg)
	if err != nil {
		return false
	}

	// LHS: z*G
	lx, ly := ctx.Curve.ScalarBaseMult(zb)

	// RHS: R + e*P
	eb, err := ctx.ScalarToFixedBytes(e)
	if err != nil {
		// errore interno / violazione delle assunzioni
		return false
	}

	ex, ey := ctx.Curve.ScalarMult(Px, Py, eb)
	rx, ry := ctx.Curve.Add(Rx, Ry, ex, ey)

	return lx.Cmp(rx) == 0 && ly.Cmp(ry) == 0
}
