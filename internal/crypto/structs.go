package crypto

import (
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// This file implements the share-generation and share-verification logic for
// our LSSS-based recovery policy.
//
// The access policy is the threshold access tree described in the report:
// the server leaf is combined with a (K,N)-threshold node over the friends
// through a root (2,2)-threshold gate, as in the following scheme
//	   (2,2)
//       |
//       /\
//  (1,1)  (n,k)
//
// Following the LSSS notation of the paper mentioned in the repor, shares are obtained
// as v · M_i, where v is the secret/randomness vector and M_i is the column associated
// with a party. For efficiency, the matrix M is never materialized: the code
// evaluates the required entries directly using powers of alpha.

// Types & variables
type Point = edwards25519.Point   // Edwards25519 group element.
type Scalar = edwards25519.Scalar // Element of Z_l, the scalar field.
type ParticipantID int            // Party index: 0 is reserved for the server.

const ServerID ParticipantID = 0

///////////////////////////////////////////////////////////////

// Useful structs

// SecretVector is the LSSS vector v used in the product v · M.
// In our construction:
//
//	v = (s, r2, t_1, ..., t_{K-1})
//
// where s is the dealer's secret and the remaining entries are random scalars.

type SecretVector struct {
	s  Scalar   // Secret s
	r2 Scalar   // Random scalar r_2
	t  []Scalar // Random scalars t_1, ..., t_{K-1}.
}

func (sv *SecretVector) SetSecretVector(s Scalar, k int) error {
	sv.s = s
	err := GenerateRandomScalar(&sv.r2)
	if err != nil {
		return fmt.Errorf("sv.SetSecretVector failed: %w", err)
	}
	sv.t = make([]Scalar, k-1)
	err = GenerateRandomScalars(sv.t)
	if err != nil {
		return fmt.Errorf("sv.SetSecretVector failed: %w", err)
	}
	return nil
}

// ThresholdParams stores the parameters of the friends' (K,N)-threshold node.
type ThresholdParams struct {
	K int // threshold
	N int // number of participants
}

// Commitment stores commitments to the entries of the LSSS vector v.
// c = (C_0, ..., C_K), where:
//
//	C_0 = sG,
//	C_1 = r2G,
//	C_j = t_{j-1}G for j = 2, ..., K.
//
// These commitments are used to verify that a share equals v · M_i.
type Commitment []Point

// SetNumPoints allocates K+1 commitments, one for each entry of v.
func (c *Commitment) SetNumPoints(K int) error {
	if K < 2 {
		return errors.New("c.SetNumPoints failed: K must be at least 2")
	}
	*c = make([]Point, K+1)
	return nil
}

// Shares stores the output of v · M.
// ServerShare is the share associated with the server column of M.
// ParticipantShares contains the shares associated with the friends' columns.
type Shares struct {
	ServerShare       Scalar   // s_0 = s + r2
	ParticipantShares []Scalar // s_1,... s_n
}

// Dealer
// Dealer samples v, commits to its entries, and computes the shares v · M_i.
type Dealer struct {
	parameters ThresholdParams
	secret     Scalar
	commitment Commitment
	shares     Shares
	friends    []string
}

// SetTsParameters sets the parameters of the friends' (K,N)-threshold node.
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

// SetSecret samples the dealer's secret s.
func (d *Dealer) SetSecret() error {
	err := GenerateRandomScalar(&d.secret)
	if err != nil {
		return fmt.Errorf("d.SetSecret failed: %w", err)
	}

	return nil
}

func (d *Dealer) GetSecret() Scalar {
	return d.secret
}

// SetFriends assigns one name to each friend leaf of the access tree.
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

// SetCommAndShares computes commitments and shares for the LSSS instance.
// The method implements the products v · M_i for the specific matrix M induced
// by our access tree. The matrix is not stored explicitly: its entries are
// evaluated on the fly using powers of alpha.
// You can find in the report which are the entries of the matrix M (Section 3)

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

	// Build the LSSS vector v = (s, r2, t_1, ..., t_{K-1})
	secVec := SecretVector{}
	err := secVec.SetSecretVector(d.secret, d.parameters.K)
	if err != nil {
		return fmt.Errorf("d.SetCommAndShares failed: %w", err)
	}

	// Commit to the entries of v
	err = d.commitment.SetNumPoints(d.parameters.K)
	if err != nil {
		return fmt.Errorf("d.SetCommAndShares failed: %w", err)
	}

	d.commitment[0].ScalarBaseMult(&secVec.s)  // C_0 = sG
	d.commitment[1].ScalarBaseMult(&secVec.r2) // C_1 = r2G

	for i := 0; i < d.parameters.K-1; i++ {
		d.commitment[i+2].ScalarBaseMult(&secVec.t[i]) // C_{i+2} = t_{i+1}G
	}

	// Server column of M gives s_0 = s + r2
	d.shares.ServerShare.Add(&secVec.s, &secVec.r2) //s_0 = s + r2
	d.shares.ParticipantShares = make([]Scalar, d.parameters.N)

	// Common term in all friend shares: s + r2*alpha.
	var beta2 Scalar
	beta2.MultiplyAdd(&secVec.r2, &alpha, &secVec.s) // beta2 = s + r2*alpha

	// First friend column: all alpha^{j(i-1)} terms are 1.
	var share Scalar
	share.Set(&beta2)
	for i := 1; i < d.parameters.K; i++ {
		share.Add(&share, &secVec.t[i-1]) // share += t_{i}
	}
	d.shares.ParticipantShares[0].Set(&share)

	// Remaining friend columns of M are evaluated without materializing M.
	// For friend i+1, this computes:
	//     s_{i+1} = s + r2*alpha + sum_j t_j * alpha^{j*i}.
	var aus1, aus2 Scalar
	aus1.Set(&alpha) // aus1 = alpha^1
	aus2.Set(&alpha) // aus2 = alpha
	for i := 1; i < d.parameters.N; i++ {
		share.Set(&beta2)
		for j := 1; j < d.parameters.K; j++ {
			// Add t_j * alpha^{i*j}.
			share.MultiplyAdd(&secVec.t[j-1], &aus2, &share)
			// Update alpha^{i*j} to alpha^{i*(j+1)}.
			aus2.Multiply(&aus1, &aus2)
		}
		d.shares.ParticipantShares[i].Set(&share)
		// Move from alpha^i to alpha^{i+1}.
		aus1.Multiply(&aus1, &alpha)
		aus2.Set(&aus1)
	}
	// Clear temporary secret/randomness values after share generation.
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
// Participant represents a friend leaf (with index >0) in the access tree.
type Participant struct {
	id    ParticipantID
	name  string
	share Scalar
}

// SetID sets the friend index. ID 0 is reserved for the server.
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

// SetShare stores the participant's LSSS share s_i.
func (p *Participant) SetShare(share Scalar) {
	p.share = share
}

func (p *Participant) GetShare() Scalar {
	return p.share
}

// VerifyConsistency checks the Feldman-style relation for the share v · M_i.
// Instead of recomputing v · M_i from secret values, the participant evaluates
// the same linear combination over the public commitments to v.
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

	// For i = 1, all powers alpha^{j(i-1)} are equal to 1.
	if p.id == 1 {
		lhs := comm[1]
		lhs.ScalarMult(&alpha, &lhs) // lhs = alpha*C_1.
		lhs.Add(&lhs, &comm[0])      // lhs = c// C_0 + alpha*C_1.
		for i := 2; i < len(comm); i++ {
			lhs.Add(&lhs, &comm[i]) // Add lo lhs C_2 + ... + C_K.
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
		lhs.ScalarMult(&alpha, &lhs)
		lhs.Add(&lhs, &comm[0])
		var aus1 Scalar
		var aus2 Point

		// General friend column: use x = alpha^{id-1}.
		var x Scalar
		ScalarPow(&alpha, uint8(p.id-1), &x)

		// First t-term: x*C_2.
		aus1.Set(&x)
		aus2.ScalarMult(&aus1, &comm[2])
		lhs.Add(&lhs, &aus2)

		for i := 3; i < len(comm); i++ {
			// Update x^{j-1} to x^j and add x^j*C_{j+1}.
			aus1.Multiply(&aus1, &x)

			aus2.ScalarMult(&aus1, &comm[i])
			lhs.Add(&lhs, &aus2)
		}

		// Compare the commitment-side evaluation with s_i*G.
		rhs := edwards25519.NewIdentityPoint()
		rhs.ScalarBaseMult(&p.share)

		if lhs.Equal(rhs) == 1 {
			return true, nil
		} else {
			return false, nil
		}
	}
}

// Server
// Server represents the mandatory server leaf of the access tree.
type Server struct {
	share  Scalar
	params ThresholdParams
}

func (s *Server) SetParams(par *ThresholdParams) {
	s.params = *par
}

func (s *Server) GetParams() ThresholdParams {
	return s.params
}

func (s *Server) SetShare(share Scalar) {
	s.share = share
}

func (s *Server) GetShare() Scalar {
	return s.share
}

// VerifyConsistency checks the server column of M.
// Since the server share is s_0 = s + r2, the check is:
//
//	s_0G == C_0 + C_1.
func (s *Server) VerifyConsistency(comm *Commitment) (bool, error) {
	if s.share.Equal(&Scalar{}) == 1 {
		return false, errors.New("s.VerifyConsistency failed: server share is not set")
	}

	if comm == nil {
		return false, errors.New("s.VerifyConsistency failed: invalid commitment")
	}
	lhs := (*comm)[1]
	lhs.Add(&lhs, &(*comm)[0]) // C_0 + C_1.
	rhs := edwards25519.NewIdentityPoint()
	rhs.ScalarBaseMult(&s.share) // s_0G.
	if lhs.Equal(rhs) == 1 {
		return true, nil
	} else {
		return false, nil
	}
}
