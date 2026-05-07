package crypto

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Types & variables
type Point = edwards25519.Point
type Scalar = edwards25519.Scalar
type ParticipantID int

const ServerID ParticipantID = 0

///////////////////////////////////////////////////////////////

// useful structs
type SecretVector struct {
	s  Scalar // secret
	r2 Scalar
	t  []Scalar // t1,...,t_{k-1}
}

func (sv *SecretVector) SetSecretVector(s Scalar, k int) error {
	sv.s = s
	err := generateRandomScalar(&sv.r2)
	if err != nil {
		return fmt.Errorf("sv.SetSecretVector failed: %w", err)
	}
	sv.t = make([]Scalar, k-1)
	err = generateRandomScalars(sv.t)
	if err != nil {
		return fmt.Errorf("sv.SetSecretVector failed: %w", err)
	}
	return nil
}

type ThresholdParams struct {
	K int // threshold
	N int // number of participants
}

type Commitment []Point

func (c *Commitment) SetNumPoints(K int) error {
	if K < 2 {
		return errors.New("c.SetNumPoints failed: K must be at least 2")
	}
	*c = make([]Point, K+1)
	return nil
}

type Shares struct {
	ServerShare       Scalar   // beta1
	ParticipantShares []Scalar // gamma_1,...,gamma_n
}

// Dealer
type Dealer struct {
	parameters ThresholdParams
	secret     Scalar
	commitment Commitment
	shares     Shares
	friends    []string
}

func (d *Dealer) SetTsParameters(N int, K int) error {
	if K > N {
		return errors.New("d.SetTsParameters failed: K must be less than or equal to N")
	}
	if K < 2 {
		return errors.New("d.SetTsParameters failed: K must be at least 2")
	}
	d.parameters.N = N
	d.parameters.K = K
	return nil
}

func (d *Dealer) GetTsParameters() ThresholdParams {
	return d.parameters
}

func (d *Dealer) SetSecret() error {
	err := generateRandomScalar(&d.secret)
	if err != nil {
		return fmt.Errorf("d.SetSecret failed: %w", err)
	}

	return nil
}

func (d *Dealer) GetSecret() Scalar {
	return d.secret
}

func (d *Dealer) SetFriends(friends []string) error {
	if len(friends) != d.parameters.N {
		return errors.New("d.SetFriends failed: N is not equal to the number of friends")
	}
	d.friends = friends
	return nil
}

func (d *Dealer) GetFriends() []string {
	return d.friends
}

func (d *Dealer) SetCommAndShares() error {
	if d.parameters.K == 0 {
		return errors.New("d.SetCommAndShares failed: K is not set")
	}

	if d.parameters.N == 0 {
		return errors.New("d.SetCommAndShares failed: N is not set")
	}

	if d.secret.Equal(&Scalar{}) == 1 {
		return errors.New("d.SetCommAndShares failed: secret is not set")
	}

	// Building of the secret vector (s, r2, t1,...,t_{k-1})
	secVec := SecretVector{}
	err := secVec.SetSecretVector(d.secret, d.parameters.K)
	if err != nil {
		return fmt.Errorf("d.SetCommAndShares failed: %w", err)
	}

	// Building of Commitment
	err = d.commitment.SetNumPoints(d.parameters.K)
	if err != nil {
		return fmt.Errorf("d.SetCommAndShares failed: %w", err)
	}

	d.commitment[0].ScalarBaseMult(&secVec.s)
	d.commitment[1].ScalarBaseMult(&secVec.r2)

	for i := 0; i < d.parameters.K-1; i++ {
		d.commitment[i+2].ScalarBaseMult(&secVec.t[i])
	}

	// Building of shares
	d.shares.ServerShare.Add(&secVec.s, &secVec.r2) //beta_1 = s + r2
	d.shares.ParticipantShares = make([]Scalar, d.parameters.N)

	// gamma_i = beta2 + t_1*alpha^(i-1) + t_2*alpha^(2(i-1)) + ... + t_{k-1}*alpha^((k-1)(i-1))
	var beta2 Scalar
	beta2.MultiplyAdd(&secVec.r2, &alpha, &secVec.s) // beta2 = s + r2*alpha

	var share Scalar
	share.Set(&beta2)
	for i := 1; i < d.parameters.K; i++ {
		share.Add(&share, &secVec.t[i-1]) // share += t_{i}
	}
	d.shares.ParticipantShares[0].Set(&share)

	var aus1, aus2 Scalar
	aus1.Set(&alpha) // aus1 = alpha^1
	aus2.Set(&alpha) // aus2 = alpha
	for i := 1; i < d.parameters.N; i++ {
		share.Set(&beta2)
		for j := 1; j < d.parameters.K; j++ {
			share.MultiplyAdd(&secVec.t[j-1], &aus2, &share) // share += t_{j}*alpha^{i*j}
			aus2.Multiply(&aus1, &aus2)                      // aus2 = alpha^{i*(j+1)}
		}
		d.shares.ParticipantShares[i].Set(&share)
		aus1.Multiply(&aus1, &alpha) // aus1 = alpha^{i}
		aus2.Set(&aus1)              // aus2 = alpha^{i}
	}
	// Zeroization
	secVec.s = Scalar{}
	secVec.r2 = Scalar{}
	clear(secVec.t)
	return nil
}

func (d *Dealer) GetComm() *Commitment {
	return &d.commitment
}

func (d *Dealer) GetParticipantShares(n int) Scalar {
	return d.shares.ParticipantShares[n]
}

func (d *Dealer) GetServerShare() Scalar {
	return d.shares.ServerShare
}

// Participant (user)
type Participant struct {
	id                  ParticipantID
	name                string
	share               Scalar
	lagrangeCoefficient Scalar
}

func (p *Participant) SetID(id ParticipantID) error {
	if id <= 0 {
		return errors.New("p.SetID failed: invalid participant ID")
	}
	p.id = id
	return nil
}

func (p *Participant) GetID() ParticipantID {
	return p.id
}

func (p *Participant) SetName(name string) {
	p.name = name
}

func (p *Participant) GetName() string {
	return p.name
}

func (p *Participant) SetShare(share Scalar) {
	p.share = share
}

func (p *Participant) GetShare() Scalar {
	return p.share
}

func (p *Participant) VerifyConsistency(comm Commitment) (bool, error) {
	if p.id == 0 {
		return false, errors.New("p.VerifyConsistency failed: participant ID is not set")
	}

	if p.name == "" {
		return false, errors.New("p.VerifyConsistency failed: participant name is not set")
	}

	if p.share.Equal(&Scalar{}) == 1 {
		return false, errors.New("p.VerifyConsistency failed: participant share is not set")
	}

	if comm == nil {
		return false, errors.New("p.VerifyConsistency failed: invalid commitment")
	}

	if p.id == 1 {
		lhs := comm[1]
		lhs.ScalarMult(&alpha, &lhs) // lhs = comm[1]^alpha
		lhs.Add(&lhs, &comm[0])      // lhs = comm[1]^alpha + comm[0]
		for i := 2; i < len(comm); i++ {
			lhs.Add(&lhs, &comm[i])
		}
		rhs := edwards25519.NewIdentityPoint()
		rhs.ScalarBaseMult(&p.share)
		if lhs.Equal(rhs) == 1 {
			return true, nil
		} else {
			return false, nil
		}
	} else {
		lhs := comm[1]
		lhs.ScalarMult(&alpha, &lhs) // lhs = comm[1]^alpha
		lhs.Add(&lhs, &comm[0])      // lhs = comm[1]^alpha + comm[0]
		var aus1 Scalar
		var aus2 Point

		// x = alpha^(p.id-1)
		var x Scalar
		ScalarPow(&alpha, uint8(p.id-1), &x)

		// aus1 = x = alpha^(p.id-1)
		aus1.Set(&x)

		// primo termine: comm[2] * alpha^(p.id-1)
		aus2.ScalarMult(&aus1, &comm[2])
		lhs.Add(&lhs, &aus2)

		for i := 3; i < len(comm); i++ {
			// aus1 = aus1 * x
			// quindi:
			// comm[3] usa x^2 = alpha^(2(p.id-1))
			// comm[4] usa x^3 = alpha^(3(p.id-1))
			// ecc.
			aus1.Multiply(&aus1, &x)

			aus2.ScalarMult(&aus1, &comm[i])
			lhs.Add(&lhs, &aus2)
		}

		rhs := edwards25519.NewIdentityPoint()
		rhs.ScalarBaseMult(&p.share)

		if lhs.Equal(rhs) == 1 {
			return true, nil
		} else {
			return false, nil
		}
	}
}

func (p *Participant) SetLagrangeCoefficient(ids []ParticipantID) {
	// if p.id is not in ids, then p.lagrangeCoefficient = 0
	m := map[ParticipantID]bool{}
	for _, id := range ids {
		m[id] = true
	}
	// if p.id is not in ids, then p.lagrangeCoefficient = 0,
	// because p does not participate in the reconstruction and therefore
	// his share does not contribute to the reconstruction of the secret

	if !m[p.id] {
		p.lagrangeCoefficient = Scalar{}
		return
	}
	var aus Scalar
	p.lagrangeCoefficient.Set(&One)                              // coeff = one
	aus.Set(&One)                                                // aus = one
	aus.Subtract(&aus, &alpha)                                   // aus = 1-alpha
	aus.Invert(&aus)                                             // aus = 1/(1-alpha)
	p.lagrangeCoefficient.Multiply(&p.lagrangeCoefficient, &aus) // coeff = alpha / (1 - alpha)

	var term Scalar
	term.Set(&One) // term = one
	for _, id := range ids {
		if id == p.id {
			continue
		} else {
			var aus2 Scalar
			var aus3 Scalar
			aus2.Set(&One)
			ScalarPow(&alpha, uint8(id-1), &aus2)
			aus3.Set(&One)
			ScalarPow(&alpha, uint8(p.id-1), &aus3)
			aus3.Subtract(&aus3, &aus2) // aus3 = alpha^{id-1} - alpha^{p.id-1}
			aus3.Invert(&aus3)          // aus3 = 1/(alpha^{id-1} - alpha^{p.id-1})
			aus2.Multiply(&aus2, &aus3) // aus2 = alpha^{id-1} / (alpha^{id-1} - alpha^{p.id-1})
			term.Multiply(&term, &aus2)
		}
	}
	p.lagrangeCoefficient.Multiply(&p.lagrangeCoefficient, &term) // coeff = alpha / (1 - alpha) * product_{j!=i} (alpha^{id-1} / (alpha^{id-1} - alpha^{p.id-1}))
}

func (p *Participant) GetLagrangeCoefficient() Scalar {
	return p.lagrangeCoefficient
}

// Server
type Server struct {
	share               Scalar
	lagrangeCoefficient Scalar
}

func (s *Server) SetShare(share Scalar) {
	s.share = share
}

func (s *Server) GetShare() Scalar {
	return s.share
}

func (s *Server) SetLagrangeCoefficient([]ParticipantID) {
	var aus Scalar
	s.lagrangeCoefficient.Set(&alpha)                            // coeff = alpha
	aus.Set(&alpha)                                              // aus = alpha
	aus.Subtract(&aus, &One)                                     // aus = alpha - 1
	aus.Invert(&aus)                                             // aus = 1/(alpha - 1)
	s.lagrangeCoefficient.Multiply(&s.lagrangeCoefficient, &aus) // coeff = alpha / (alpha - 1)
}

func (s *Server) GetLagrangeCoefficient() Scalar {
	return s.lagrangeCoefficient
}

func (s *Server) VerifyConsistency(comm *Commitment) (bool, error) {
	if s.share.Equal(&Scalar{}) == 1 {
		return false, errors.New("s.VerifyConsistency failed: server share is not set")
	}

	if comm == nil {
		return false, errors.New("s.VerifyConsistency failed: invalid commitment")
	}
	lhs := (*comm)[1]
	lhs.Add(&lhs, &(*comm)[0]) // lhs = comm[1] + comm[0]
	rhs := edwards25519.NewIdentityPoint()
	rhs.ScalarBaseMult(&s.share)
	if lhs.Equal(rhs) == 1 {
		return true, nil
	} else {
		return false, nil
	}
}
