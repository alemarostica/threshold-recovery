package lsss

import (
	"crypto/sha256"
	"errors"
	"sort"

	"filippo.io/edwards25519"
)

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

func CombineR(reveals map[ParticipantID]Point, signers []ParticipantID) (Point, error) {
	ids, err := NormalizeParticipantIDs(signers, len(reveals))
	if err != nil {
		return Point{}, err
	}

	R := edwards25519.NewIdentityPoint()

	for _, id := range ids {
		Ri, ok := reveals[id]
		if !ok {
			return Point{}, errors.New("missing reveal")
		}

		R.Add(R, &Ri)
	}

	return *R, nil
}

func Challenge(sess *Session, R Point, P Point, msg []byte) (Scalar, error) {
	if sess == nil {
		return Scalar{}, errors.New("nil session")
	}
	if len(sess.ID) == 0 || len(sess.IndexHash) == 0 {
		return Scalar{}, errors.New("invalid session")
	}
	if len(msg) == 0 {
		return Scalar{}, errors.New("empty message")
	}

	// (opzionale ma consigliato)
	if R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("invalid R (identity)")
	}
	if P.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("invalid public key")
	}

	h := sha256.New()

	h.Write(R.Bytes())
	h.Write(P.Bytes())
	h.Write(msg)
	h.Write(sess.ID)
	h.Write(sess.IndexHash)

	sum := h.Sum(nil)

	var e Scalar
	e.SetUniformBytes(sum)

	// hardening opzionale: evita e = 0
	var zero Scalar
	if e.Equal(&zero) == 1 {
		return Scalar{}, errors.New("challenge is zero")
	}

	return e, nil
}

func PartialSign(
	share Scalar,
	nonce NonceShare,
	lambda Scalar,
	e Scalar,
) (PartialSignature, error)

func CombineSignature(
	R Point,
	partials map[ParticipantID]PartialSignature,
	signers []ParticipantID,
) (Signature, error)

func VerifySignature(P Point, msg []byte, sig Signature, sess Session) bool
