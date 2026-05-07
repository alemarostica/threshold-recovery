package crypto

import (
	"slices"
	"crypto/sha256"
	"errors"

	"filippo.io/edwards25519"
)

func NormalizeParticipantIDs(indices []ParticipantID, n int) ([]ParticipantID, error) {
	if len(indices) == 0 {
		return nil, errors.New("empty index set")
	}

	cp := append([]ParticipantID(nil), indices...)

	slices.Sort(cp)

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

func Challenge(sess *Session, R Point, P Point, msg []byte) (Scalar, error) {
	if sess == nil {
		return Scalar{}, errors.New("nil session")
	}
	if len(sess.id) == 0 || len(sess.indexHash) == 0 {
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
	h.Write(sess.id)
	h.Write(sess.indexHash)

	sum := h.Sum(nil)

	var e Scalar
	if _, err := e.SetUniformBytes(sum); err != nil {
		return Scalar{}, err
	}

	// hardening opzionale: evita e = 0
	var zero Scalar
	if e.Equal(&zero) == 1 {
		return Scalar{}, errors.New("challenge is zero")
	}

	return e, nil
}

func (ps *ParticipantSigner) PartialSign(msg []byte) error {

	var zero Scalar

	share := ps.p.GetShare()
	lambda := ps.p.GetLagrangeCoefficient()

	ri, err := ps.n.Getri()
	if err != nil {
		return err
	}

	if share.Equal(&zero) == 1 {
		return errors.New("missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ps.sess, ps.R, ps.P, msg)
	if err != nil {
		return err
	}

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ps.partialSig = WirePartialSignature{
		Index: IntToBytes(int(ps.p.GetID())),
		Z:     z.Bytes(),
	}

	return nil
}

func (ss *ServerSigner) PartialSign(msg []byte) error {

	var zero Scalar

	share := ss.s.GetShare()
	lambda := ss.s.GetLagrangeCoefficient()

	ri, err := ss.n.Getri()
	if err != nil {
		return err
	}

	if share.Equal(&zero) == 1 {
		return errors.New("missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ss.sess, ss.R, ss.P, msg)
	if err != nil {
		return err
	}

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ss.partialSig = WirePartialSignature{
		Index: IntToBytes(int(ServerID)),
		Z:     z.Bytes(),
	}

	return nil
}

func (ps *ParticipantSigner) CombineSignature(
	partials map[ParticipantID]WirePartialSignature,
	signers []ParticipantID,
) error {

	// da togliere?
	if len(signers) != len(partials) {
		return errors.New("incomplete signer set")
	}

	Rpoint := ps.GetR()

	// Reject identity point
	if Rpoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("invalid R (identity point)")
	}

	// Aggregate all partial z values
	var z Scalar

	seen := make(map[ParticipantID]bool)

	for _, id := range signers {

		// Duplicate signer check
		if seen[id] {
			return errors.New("duplicate partial signature")
		}
		seen[id] = true

		psig, ok := partials[id]
		if !ok {
			return errors.New("missing partial signature")
		}

		idx, err := BytesToParticipantID(psig.Index)
		if err != nil {
			return err
		}

		if idx != id {
			return errors.New("partial signature index mismatch")
		}

		// Decode scalar z_i
		var zi Scalar
		if _, err := zi.SetCanonicalBytes(psig.Z); err != nil {
			return errors.New("invalid partial scalar encoding")
		}

		// z = z + z_i
		z.Add(&z, &zi)
	}

	var zero Scalar
	if z.Equal(&zero) == 1 {
		return errors.New("invalid signature scalar (z = 0)")
	}

	// Set the signature
	ps.finalSig = WireSignature{
		R: Rpoint.Bytes(),
		Z: z.Bytes(),
	}

	return nil
}

func (ss *ServerSigner) CombineSignature(
	partials map[ParticipantID]WirePartialSignature,
	signers []ParticipantID,
) error {

	// da togliere?
	if len(signers) != len(partials) {
		return errors.New("incomplete signer set")
	}

	Rpoint := ss.GetR()

	// Reject identity point
	if Rpoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("invalid R (identity point)")
	}

	// Aggregate all partial z values
	var z Scalar

	seen := make(map[ParticipantID]bool)

	for _, id := range signers {

		// Duplicate signer check
		if seen[id] {
			return errors.New("duplicate partial signature")
		}
		seen[id] = true

		// Check partial exists
		psig, ok := partials[id]
		if !ok {
			return errors.New("missing partial signature")
		}

		idx, err := BytesToParticipantID(psig.Index)
		if err != nil {
			return err
		}

		if idx != id {
			return errors.New("partial signature index mismatch")
		}

		// Decode scalar z_i
		var zi Scalar
		if _, err := zi.SetCanonicalBytes(psig.Z); err != nil {
			return errors.New("invalid partial scalar encoding")
		}

		// z = z + z_i
		z.Add(&z, &zi)
	}

	// Reject zero final scalar
	var zero Scalar
	if z.Equal(&zero) == 1 {
		return errors.New("invalid signature scalar (z = 0)")
	}

	// Set the signature
	ss.finalSig = WireSignature{
		R: Rpoint.Bytes(),
		Z: z.Bytes(),
	}

	return nil
}

// se la vogliamo lasciare come funzione è ok
func VerifySignature(P []byte, msg []byte, sig WireSignature, sess Session) bool {

	// Basic input validation
	if len(sess.id) == 0 || len(sess.indexHash) == 0 {
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

	var Ppoint Point
	if _, err := Ppoint.SetBytes(P); err != nil {
		return false
	}

	if Ppoint.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}

	// Recompute challenge
	e, err := Challenge(&sess, Rpoint, Ppoint, msg)
	if err != nil {
		return false
	}

	// LHS: z * G
	var z Scalar
	var zero Scalar

	if _, err := z.SetCanonicalBytes(sig.Z); err != nil {
		return false
	}

	if z.Equal(&zero) == 1 {
		return false
	}

	var zG Point
	zG.ScalarBaseMult(&z)

	// RHS: R + eP
	var eP Point
	eP.ScalarMult(&e, &Ppoint)

	var rhs Point
	rhs.Add(&Rpoint, &eP)

	// Final check
	return zG.Equal(&rhs) == 1
}

// se la vogliammo scrivere come metodo (per ora su ParticipantSigner)
// nel caso: fare anche il setter se vogliamo aggiungere l'output alle struct
/*
func (ps *ParticipantSigner) VerifySignature(msg []byte) bool {
	// 1. controlli base
	if len(msg) == 0 {
		return false
	}

	if ps.finalSig.R == nil || ps.finalSig.Z == nil {
		return false
	}

	// 2. ricostruzione punti/scalari
	var Rpoint Point
	if _, err := Rpoint.SetBytes(ps.finalSig.R); err != nil {
		return false
	}

	var z Scalar
	if _, err := z.SetCanonicalBytes(ps.finalSig.Z); err != nil {
		return false
	}

	// 3. recupero public key dalla session
	Pbytes := ps.session.GetP()

	var Ppoint Point
	if _, err := Ppoint.SetBytes(Pbytes); err != nil {
		return false
	}

	// 4. ricostruzione challenge
	e, err := Challenge(ps.session, Rpoint, Ppoint, msg)
	if err != nil {
		return false
	}

	// 5. verifica equazione: zG ?= R + eP
	var zG Point
	zG.ScalarBaseMult(&z)

	var eP Point
	eP.ScalarMult(&e, &Ppoint)

	var rhs Point
	rhs.Add(&Rpoint, &eP)

	// 6. confronto finale
	return zG.Equal(&rhs) == 1
}

*/
