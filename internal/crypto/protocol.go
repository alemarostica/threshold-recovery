package crypto

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
	share Scalar, // s_i (LSSS share)
	nonce NonceShare, // r_i + R_i
	lambda Scalar, // coeff LSSS
	e Scalar, // challenge Schnorr
) (WirePartialSignature, error) {

	// -------------------------
	// VALIDATION
	// -------------------------
	var zero Scalar
	if nonce.ri.Equal(&zero) == 1 {
		return WirePartialSignature{}, errors.New("zero nonce not allowed")
	}

	if lambda.Equal(&zero) == 1 {
		return WirePartialSignature{}, errors.New("zero lambda not allowed")
	}

	// -------------------------
	// COMPUTE TERM: e * lambda * s_i
	// -------------------------

	var term Scalar

	// term = lambda * s_i
	term.Multiply(&lambda, &share)

	// term = e * (lambda * s_i)
	term.Multiply(&term, &e)

	// -------------------------
	// FINAL z_i = r_i + term
	// -------------------------

	var zi Scalar
	zi.Add(&nonce.ri, &term)

	// -------------------------
	// OUTPUT
	// -------------------------

	return WirePartialSignature{
		Index: IntToBytes(int(nonce.Index)),
		Z:     zi.Bytes(),
	}, nil
}

func CombineSignature(
	R []byte,
	partials map[ParticipantID]WirePartialSignature,
	signers []ParticipantID,
) (WireSignature, error) {

	ids, err := NormalizeParticipantIDs(signers, len(partials))
	if err != nil {
		return WireSignature{}, err
	}

	// Decode R
	var Rpoint Point
	if _, err := Rpoint.SetBytes(R); err != nil {
		return WireSignature{}, errors.New("invalid R encoding")
	}

	if Rpoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return WireSignature{}, errors.New("invalid R (identity point)")
	}

	// Aggregate z
	var z Scalar

	seen := make(map[ParticipantID]bool)

	for _, id := range ids {

		if seen[id] {
			return WireSignature{}, errors.New("duplicate partial")
		}
		seen[id] = true

		ps, ok := partials[id]
		if !ok {
			return WireSignature{}, errors.New("missing partial signature")
		}

		idx, err := BytesToParticipantID(ps.Index)

		if idx < 1 || int(idx) > len(partials) {
			return WireSignature{}, errors.New("invalid participant id")
		}
		if err != nil {
			return WireSignature{}, err
		}

		if idx != id {
			return WireSignature{}, errors.New("partial signature index mismatch")
		}

		// decode scalar
		var zi Scalar
		if _, err := zi.SetCanonicalBytes(ps.Z); err != nil {
			return WireSignature{}, errors.New("invalid partial scalar encoding")
		}

		z.Add(&z, &zi)
	}

	// -------------------------
	// Final checks
	// -------------------------
	var zero Scalar
	if z.Equal(&zero) == 1 {
		return WireSignature{}, errors.New("invalid signature scalar (z = 0)")
	}

	return WireSignature{
		R: Rpoint.Bytes(),
		Z: z.Bytes(),
	}, nil
}

func VerifySignature(P []byte, msg []byte, sig WireSignature, sess Session) bool {

	// 1. controllo base input
	if len(sess.ID) == 0 || len(sess.IndexHash) == 0 {
		return false
	}

	if len(msg) == 0 {
		return false
	}

	var Rpoint Point
	if _, err := Rpoint.SetBytes(sig.R); err != nil {
		return false
	}

	if Rpoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}

	// 3. evita public key invalida
	var Ppoint Point
	if _, err := Ppoint.SetBytes(P); err != nil {
		return false
	}

	if Ppoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}

	// 4. ricalcolo challenge e
	e, err := Challenge(&sess, Rpoint, Ppoint, msg)
	if err != nil {
		return false
	}

	// 5. LHS: z * G
	var z Scalar
	var zero Scalar

	if z.Equal(&zero) == 1 {
		return false
	}

	if _, err := z.SetCanonicalBytes(sig.Z); err != nil {
		return false
	}

	var zG Point
	zG.ScalarBaseMult(&z)

	// 6. RHS: R + eP
	var eP Point
	eP.ScalarMult(&e, &Ppoint)

	var rhs Point
	rhs.Add(&Rpoint, &eP)

	// 7. confronto finale
	return zG.Equal(&rhs) == 1
}

/*
// ProtocolSignSessionBound executes the full threshold Schnorr protocol:
// commit → reveal → R → challenge → partial signatures → aggregation → verify.
func ProtocolSignSessionBound(
	p *Protocol,
	sess *Session,
	msg []byte,
	P Point,
	signers []ParticipantID,
	shares map[ParticipantID]Scalar,
) (Signature, error) {

	if p == nil || sess == nil {
		return Signature{}, errors.New("nil protocol/session")
	}

	// -------------------------
	// Normalize signer set
	// -------------------------
	ids, err := NormalizeParticipantIDs(signers, p.PP.N)
	if err != nil {
		return Signature{}, err
	}

	if len(ids) != p.PP.K {
		return Signature{}, errors.New("invalid number of signers")
	}

	// =========================================================
	// ROUND 1 — NONCE COMMIT
	// =========================================================
	nonces := make(map[ParticipantID]*NonceShare)
	commits := make(map[ParticipantID][]byte)
	reveals := make(map[ParticipantID]Point)

	for _, i := range ids {

		_ , ok := shares[i]
		if !ok {
			return Signature{}, errors.New("missing share")
		}

		ns, err := NewNonceShare(sess, i)
		if err != nil {
			return Signature{}, err
		}

		nonces[i] = ns
		commits[i] = ns.Commit()
	}

	// =========================================================
	// ROUND 2 — NONCE REVEAL + VERIFICATION
	// =========================================================
	for _, i := range ids {

		Ri := nonces[i].Reveal()
		reveals[i] = Ri

		if !VerifyNonce(sess, i, commits[i], Ri) {
			return Signature{}, errors.New("nonce verification failed")
		}
	}

	// =========================================================
	// COMPUTE R
	// =========================================================
	R, err := CombineR(reveals, ids)
	if err != nil {
		return Signature{}, err
	}

	// =========================================================
	// CHALLENGE (session-bound)
	// =========================================================
	e, err := Challenge(sess, R, P, msg)
	if err != nil {
		return Signature{}, err
	}

	// =========================================================
	// LAGRANGE COEFFICIENTS (LSSS binding)
	// =========================================================
	lambdas := CoefficientsForSecret(p.PP.M, p.PP.N, ids)

	// =========================================================
	// ROUND 3 — PARTIAL SIGNATURES
	// =========================================================
	partials := make(map[ParticipantID]PartialSignature)

	for _, i := range ids {

		share := shares[i]

		ps, err := PartialSign(
			share,
			*nonces[i],
			lambdas[i-1], // NB: assume aligned ordering OR adapt mapping
			e,
		)
		if err != nil {
			return Signature{}, err
		}

		partials[i] = ps
	}

	// =========================================================
	// FINAL AGGREGATION
	// =========================================================
	sig, err := CombineSignature(R, partials, ids)
	if err != nil {
		return Signature{}, err
	}

	// =========================================================
	// FINAL VERIFICATION (sanity check)
	// =========================================================
	if !VerifySignature(P, msg, sig, *sess) {
		return Signature{}, errors.New("final signature verification failed")
	}

	return sig, nil
}


*/
