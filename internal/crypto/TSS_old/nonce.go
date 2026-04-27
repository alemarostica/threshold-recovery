package crypto

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"math/big"
)

type NonceShare struct {
	Index int
	ri    *big.Int
	Ri    []byte
	ci    []byte
}

// commitNonce calcola H(sess.ID || sess.IndexHash || index || Ri).
// Include index per evitare "swap" tra partecipanti.
// Include session ID per evitare i replay attacks
// Include session Index per  garantire domain separation
func commitNonce(sess *Session, index int, Ri []byte) []byte {
	h := sha256.New()
	h.Write(sess.ID)
	h.Write(sess.IndexHash)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(index))
	h.Write(tmp[:])

	h.Write(Ri)
	return h.Sum(nil)
}

func NewNonceShare(ctx *CurveCtx, sess *Session, index int) (*NonceShare, error) {
	ri, err := randScalar(ctx.N)
	if err != nil {
		return nil, err
	}

	// serializzazione canonica e validazione range ([1, N-1])
	k, err := ctx.ScalarToFixedBytes(ri)
	if err != nil {
		return nil, err
	}

	// Ri = ri*G
	x, y := ctx.Curve.ScalarBaseMult(k)
	Ri := elliptic.Marshal(ctx.Curve, x, y)

	ci := commitNonce(sess, index, Ri)

	return &NonceShare{
		Index: index,
		ri:    ri,
		Ri:    Ri,
		ci:    ci,
	}, nil
}

// creates a copy of ci and returns it (the copy protects original data)
func (n *NonceShare) Commit() []byte {
	out := make([]byte, len(n.ci))
	copy(out, n.ci)
	return out
}

// creates a copy of Ri and returns it
func (n *NonceShare) Reveal() []byte {
	out := make([]byte, len(n.Ri))
	copy(out, n.Ri)
	return out
}

func VerifyNonce(ctx *CurveCtx, sess *Session, index int, commit, Ri []byte) bool {
	// commit deve essere SHA-256
	if len(commit) != sha256.Size {
		return false
	}

	// Ri deve essere un punto valido sulla curva
	x, y := elliptic.Unmarshal(ctx.Curve, Ri)

	// Check nil first: Unmarshal may fail and return nil coordinates
	if x == nil || y == nil {
		return false
	}

	// error happens if Ri has wrong length or the first byte is not the one attended or...
	if !ctx.Curve.IsOnCurve(x, y) {
		return false
	}

	// ricalcola e confronta in constant-time
	sum := commitNonce(sess, index, Ri)
	return subtle.ConstantTimeCompare(sum, commit) == 1
}
