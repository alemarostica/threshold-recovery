package crypto

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"sort"

	"filippo.io/edwards25519"
)

// This file contains helper functions for signer-set normalization,
// Schnorr challenge computation, and final signature verification.

// NormalizeParticipantIDs sorts and validates a friend signer set.
//
// ServerID is not included here: this function only handles friend indices.
func NormalizeParticipantIDs(indices []ParticipantID, n int) ([]ParticipantID, error) {
	if len(indices) == 0 {
		return nil, errors.New("empty index set")
	}

	cp := append([]ParticipantID(nil), indices...)

	sort.Slice(cp, func(i, j int) bool {
		return cp[i] < cp[j]
	})

	for i := 0; i < len(cp); i++ {
		if cp[i] < 1 || int(cp[i]) > n {
			return nil, errors.New("participant index out of range")
		}

		if i > 0 && cp[i] == cp[i-1] {
			return nil, errors.New("duplicate participant index")
		}
	}

	return cp, nil
}

// Challenge computes the Schnorr challenge.
//
// The challenge is bound to:
//   - the aggregated nonce R,
//   - the public key P,
//   - the message,
//   - the session identifier,
//   - the active signer set hash.
//
// This prevents replaying partial signatures across different sessions or
// signer sets.
func Challenge(sess *Session, R *Point, P *Point, msg []byte) (Scalar, error) {

	if sess == nil {
		return Scalar{}, errors.New("Challenge failed: nil session")
	}
	if len(sess.id) == 0 || len(sess.indexHash) == 0 {
		return Scalar{}, errors.New("Challenge failed: invalid session")
	}
	if len(msg) == 0 {
		return Scalar{}, errors.New("Challenge failed: empty message")
	}

	// Reject invalid public points.
	if R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("Challenge failed: invalid R (identity)")
	}
	if P.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("Challenge failed: invalid public key")
	}

	// e = H(R || P || msg || sessionID || indexHash).
	// Need of sha512 for a suitable output length
	h := sha512.New()

	h.Write(R.Bytes())
	h.Write(P.Bytes())
	h.Write(msg)
	h.Write(sess.id)
	h.Write(sess.indexHash)

	sum := h.Sum(nil)

	var e Scalar
	if _, err := e.SetUniformBytes(sum); err != nil {
		return Scalar{}, err
	}

	var zero Scalar
	if e.Equal(&zero) == 1 {
		return Scalar{}, errors.New("Challenge failed: challenge is zero")
	}

	return e, nil
}

// VerifySignature verifies the final aggregated Schnorr signature.
//
// The signature is accepted iff:
//
//	Z*G = R + e*P,
//
// where e is recomputed from the same session-bound challenge.
func VerifySignature(P Point, msg []byte, sig Signature, sess Session) (bool, error) {

	fmt.Printf("verify R: %x\n", sig.R.Bytes())
	fmt.Printf("verify P: %x\n", P.Bytes())
	fmt.Printf("verify sess.id: %x\n", sess.GetID())
	fmt.Printf("verify sess.indexHash: %x\n", sess.GetIndexHash())

	// Basic input validation
	if len(sess.id) == 0 || len(sess.indexHash) == 0 {
		return false, errors.New("VerifySignature failed: session length is wrong")
	}

	if len(msg) == 0 {
		return false, errors.New("VerifySignature failed: message has length zero")
	}

	// Recompute the session-bound Schnorr challenge.
	e, err := Challenge(&sess, &sig.R, &P, msg)
	if err != nil {
		return false, fmt.Errorf("VerifySignature failed: %w", err)
	}

	// Left-hand side: Z*G.
	var zero Scalar
	if sig.Z.Equal(&zero) == 1 {
		return false, errors.New("VerifySignature failed: signature is zero")
	}

	var zG Point
	zG.ScalarBaseMult(&sig.Z)

	// Right-hand side: R + e*P.
	var eP Point
	eP.ScalarMult(&e, &P)

	var rhs Point
	rhs.Add(&sig.R, &eP)

	// Final check
	return zG.Equal(&rhs) == 1, nil
}

func combineSignatureAux(
	who string,
	indices []ParticipantID,
	R Point,
	parSig []PartialSignature,
) (Signature, error) {
	if len(parSig) != len(indices)+1 {
		return Signature{}, errors.New(who + ".CombineSignature failed: invalid number of partial signatures")
	}

	// Reject the identity point, which would make the Schnorr signature invalid.
	if R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Signature{}, errors.New(who + ".CombineSignature failed: invalid R (identity point)")
	}

	// indices contains only the k signing participants.
	// The server is required by the access policy, but it is not part of indices,
	// so we add ServerID explicitly.
	expected := make(map[ParticipantID]bool, len(indices)+1)

	expected[ServerID] = false

	for _, id := range indices {
		if id == ServerID {
			return Signature{}, errors.New(who + ".CombineSignature failed: server ID appears in participant set")
		}

		if _, ok := expected[id]; ok {
			return Signature{}, errors.New(who + ".CombineSignature failed: duplicate participant index in signer set")
		}

		expected[id] = false
	}

	var z Scalar

	for _, el := range parSig {
		if !el.setIndex || !el.setZ {
			return Signature{}, errors.New(who + ".CombineSignature failed: input is not complete")
		}

		seen, ok := expected[el.Index]
		if !ok {
			return Signature{}, errors.New(who + ".CombineSignature failed: unexpected partial signature index")
		}

		if seen {
			return Signature{}, errors.New(who + ".CombineSignature failed: duplicate partial signature index")
		}

		expected[el.Index] = true
		z.Add(&z, &el.Z)
	}

	for id, seen := range expected {
		if !seen {
			return Signature{}, fmt.Errorf("%s.CombineSignature failed: missing partial signature from index %d", who, id)
		}
	}

	var zero Scalar
	if z.Equal(&zero) == 1 {
		return Signature{}, errors.New(who + ".CombineSignature failed: invalid signature scalar z = 0")
	}

	return Signature{
		R: R,
		Z: z,
	}, nil
}
