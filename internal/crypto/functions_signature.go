package crypto

import (
	"crypto/sha512"
	"errors"
	"fmt"
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

	// (opzionale ma consigliato)
	if R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("Challenge failed: invalid R (identity)")
	}
	if P.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return Scalar{}, errors.New("Challenge failed: invalid public key")
	}

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

	// hardening opzionale: evita e = 0
	var zero Scalar
	if e.Equal(&zero) == 1 {
		return Scalar{}, errors.New("Challenge failed: challenge is zero")
	}

	return e, nil
}

// se la vogliamo lasciare come funzione è ok
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

	// Recompute challenge
	e, err := Challenge(&sess, &sig.R, &P, msg)
	if err != nil {
		return false, fmt.Errorf("VerifySignature failed: %w", err)
	}

	// LHS: z * G
	var zero Scalar
	if sig.Z.Equal(&zero) == 1 {
		return false, errors.New("VerifySignature failed: signature is zero")
	}

	var zG Point
	zG.ScalarBaseMult(&sig.Z)

	// RHS: R + eP
	var eP Point
	eP.ScalarMult(&e, &P)

	var rhs Point
	rhs.Add(&sig.R, &eP)

	fmt.Printf("zG:  %x\n", zG.Bytes())
	fmt.Printf("rhs: %x\n", rhs.Bytes())
	fmt.Println("equal:", zG.Equal(&rhs) == 1)
	// Final check
	return zG.Equal(&rhs) == 1, nil
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
