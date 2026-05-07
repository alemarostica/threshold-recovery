package crypto

import (
	"errors"
)

type WirePartialSignature struct {
	Index []byte
	Z     []byte
}

type WireSignature struct {
	R []byte
	Z []byte
}

type ReconstructionSet struct {
	Indices []ParticipantID
	Shares  []Scalar
}

// Nonce
type NonceShare struct {
	index ParticipantID
	ri    Scalar
	Ri    []byte
	ci    []byte
}

func (n *NonceShare) SetIndex(index ParticipantID) error {
	if index < 0 {
		return errors.New("n.SetIndex failed: index must be non-negative")
	}
	n.index = index
	return nil
}

func (n *NonceShare) GetIndex() ParticipantID {
	return n.index
}

func (n *NonceShare) Setri() error {
	err := generateRandomScalar(&n.ri)
	if err != nil {
		return err
	}
	return nil
}

func (n *NonceShare) Getri() (Scalar, error) {
	return n.ri, nil
}

func (n *NonceShare) SetRi() error {
	var ki *Scalar
	err := generateRandomScalar(ki)
	if err != nil {
		return err
	}
	var Ri *Point
	Ri = Ri.ScalarBaseMult(ki)
	n.Ri = Ri.Bytes()
	return nil
}

func (n *NonceShare) GetRi() ([]byte, error) {
	if n.Ri == nil {
		return nil, errors.New("n.GetRi failed: Ri is not set")
	}
	out := make([]byte, len(n.Ri))
	copy(out, n.Ri)
	return out, nil
}

func (n *NonceShare) SetCommit(sess *Session) {
	n.ci = commitNonce(sess, n.index, n.Ri)
}

func (n *NonceShare) GetCommit() ([]byte, error) {
	if n.ci == nil {
		return nil, errors.New("n.GetCommit failed: ci is not set")
	}
	out := make([]byte, len(n.ci))
	copy(out, n.ci)
	return out, nil
}

func (n *NonceShare) VerifyNonce(sess *Session) bool {
	return VerifyNonceAux(sess, n.index, n.ci, n.Ri)
}

// Session
type Session struct {
	id        []byte
	indices   []ParticipantID
	indexHash []byte
}

func (s *Session) HasParticipant(id ParticipantID) bool {
	for _, x := range s.indices {
		if x == id {
			return true
		}
	}
	return false
}

func (s *Session) GetID() []byte {
	return s.id
}

func (s *Session) SetID(id []byte) {
	s.id = id
}

func (s *Session) GetIndices() []ParticipantID {
	out := make([]ParticipantID, len(s.indices))
	copy(out, s.indices)
	return out
}

func (s *Session) SetIndices(indices []ParticipantID) {
	s.indices = indices
}

func (s *Session) GetIndexHash() []byte {
	out := make([]byte, len(s.indexHash))
	copy(out, s.indexHash)
	return out
}

func (s *Session) SetIndexHash(indexHash []byte) {
	s.indexHash = indexHash
}

func (s *Session) GetNumParticipants() int {
	return len(s.indices)
}

// Participant
type ParticipantSigner struct {
	p          Participant
	P          Point
	R          Point
	n          NonceShare
	sess       Session
	partialSig WirePartialSignature
	finalSig   WireSignature
}

func (ps *ParticipantSigner) SetParticipant(p Participant) {
	ps.p = p
}

func (ps *ParticipantSigner) GetParticipant() Participant {
	return ps.p
}

func (ps *ParticipantSigner) GetP() Point {
	return ps.P
}

func (ps *ParticipantSigner) SetP(P Point) {
	ps.P = P
}

func (ps *ParticipantSigner) SetR(r [][]byte, ids []ParticipantID) error {
	var R Point
	for _, rBytes := range r {
		var Ri *Point
		Ri, err := Ri.SetBytes(rBytes)
		if err != nil {
			return err
		}
		R.Add(&R, Ri)
	}
	ps.R = R
	return nil
}

func (ps *ParticipantSigner) GetR() Point {
	return ps.R
}

func (ps *ParticipantSigner) SetN(n NonceShare) {
	ps.n = n
}

func (ps *ParticipantSigner) GetN() NonceShare {
	return ps.n
}

// Server
type ServerSigner struct {
	s          Server
	P          Point
	R          Point
	n          NonceShare
	sess       Session
	partialSig WirePartialSignature
	finalSig   WireSignature
}

func (ss *ServerSigner) SetParticipant(s Server) {
	ss.s = s
}

func (ss *ServerSigner) GetParticipant() Server {
	return ss.s
}

func (ss *ServerSigner) GetS() Point {
	return ss.P
}

func (ss *ServerSigner) SetP(P Point) {
	ss.P = P
}

func (ss *ServerSigner) SetR(r [][]byte) error {
	var R Point
	for _, rBytes := range r {
		var Ri *Point
		Ri, err := Ri.SetBytes(rBytes)
		if err != nil {
			return err
		}
		R.Add(&R, Ri)
	}
	ss.R = R
	return nil
}

func (ss *ServerSigner) GetR() Point {
	return ss.R
}

func (ss *ServerSigner) SetN(n NonceShare) {
	ss.n = n
}

func (ss *ServerSigner) GetN() NonceShare {
	return ss.n
}

func (ps *ParticipantSigner) GetPartialSignature() WirePartialSignature {
	return ps.partialSig
}

func (ps *ParticipantSigner) SetPartialSignature(sig WirePartialSignature) {
	ps.partialSig = sig
}

func (ss *ServerSigner) GetPartialSignature() WirePartialSignature {
	return ss.partialSig
}

func (ss *ServerSigner) SetPartialSignature(sig WirePartialSignature) {
	ss.partialSig = sig
}
