package crypto

import "filippo.io/edwards25519"

type Point = edwards25519.Point

type Commitments struct {
	Points []Point // C1,...,Ck+1
}

func (p *Protocol) GenerateCommitments(v SecretVector) Commitments {
	coeffs := make([]Scalar, p.PP.K+1)
	coeffs[0].Set(&v.S)
	coeffs[1].Set(&v.R2)
	for i := 1; i < p.PP.K; i++ {
		coeffs[i+1].Set(&v.T[i-1])
	}

	points := make([]Point, p.PP.K+1)

	for i := 0; i <= p.PP.K; i++ {
		var point Point
		point.ScalarBaseMult(&coeffs[i])
		points[i].Set(&point)
	}

	return Commitments{Points: points}
}

func (p *Protocol) VerifyShare(participantID ParticipantID, share Scalar, commitments Commitments) bool {
	if int(participantID) < 1 || int(participantID) > p.PP.N {
		return false
	}
	if len(commitments.Points) != p.PP.K+1 {
		return false
	}

	col := int(participantID) // se participantID è 1..n

	lhs := edwards25519.NewIdentityPoint()

	for j := 0; j < p.PP.K+1; j++ {
		var term Point
		term.ScalarMult(&p.PP.M[j][col], &commitments.Points[j])
		lhs.Add(lhs, &term)
	}

	var rhs Point
	rhs.ScalarBaseMult(&share)

	return lhs.Equal(&rhs) == 1
}
