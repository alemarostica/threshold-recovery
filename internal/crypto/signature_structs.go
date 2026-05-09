package crypto

import (
	"slices"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Session
type Session struct {
	id        []byte
	indices   []ParticipantID
	indexHash []byte
}

func (s *Session) HasParticipant(id ParticipantID) bool {
	return slices.Contains(s.indices, id)
}

func (s *Session) HasSigner(id ParticipantID) bool {
	if id == ServerID {
		return true
	}
	return s.HasParticipant(id)
}

// Spero questa cosa vada bene in go lmao
func (s *Session) SetID(id []byte) error {
	sid := make([]byte, 32)
	if id == nil {
		if _, err := rand.Read(sid); err != nil {
			return err
		}	
	} else {
		sid = id
	}
	
	s.id = sid
	return nil
}

func (s *Session) GetID() []byte {
	return s.id
}

func (s *Session) SetIndices(indices []ParticipantID) {
	s.indices = indices
}

func (s *Session) GetIndices() []ParticipantID {
	out := make([]ParticipantID, len(s.indices))
	copy(out, s.indices)
	return out
}

func (s *Session) SetIndexHash(ids []ParticipantID) {
	h := sha256.New()
	tmp := make([]byte, 4)

	for _, id := range ids {
		binary.BigEndian.PutUint32(tmp, uint32(id))
		h.Write(tmp)
	}
	s.indexHash = h.Sum(nil)
}

func (s *Session) GetIndexHash() []byte {
	return s.indexHash
}

func (s *Session) GetNumParticipants() int {
	return len(s.indices)
}

type PartialSignature struct {
	Index    ParticipantID
	setIndex bool
	Z        Scalar
	setZ     bool
}

func (ps *PartialSignature) SetIndex(ind *ParticipantID) {
	ps.Index = *ind
	ps.setIndex = true
}

func (ps *PartialSignature) GetIndex() ParticipantID {
	return ps.Index
}

func (ps *PartialSignature) SetZ(z *Scalar) {
	ps.Z = *z
	ps.setZ = true
}

func (ps *PartialSignature) GetZ() Scalar {
	return ps.Z
}

type Signature struct {
	R Point
	Z Scalar
}

// Nonce
type NonceShare struct {
	index  ParticipantID
	ri     Scalar
	set_ri bool
	Ri     Point
	setRi  bool
	ci     []byte
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
	err := GenerateRandomScalar(&n.ri)
	if err != nil {
		return err
	}
	n.set_ri = true
	return nil
}

func (n *NonceShare) Getri() Scalar {
	return n.ri
}

func (n *NonceShare) SetRi() error {
	if !n.set_ri {
		return errors.New("n.SetRi failed: ri is not set")
	}

	var Ri Point
	Ri.ScalarBaseMult(&n.ri)

	n.Ri = Ri
	n.setRi = true
	return nil
}

func (n *NonceShare) GetRi() (*Point, error) {
	if !n.setRi {
		return nil, errors.New("n.GetRi failed: Ri is not set")
	}
	return &n.Ri, nil
}

func (n *NonceShare) SetCommit(sess *Session) {
	n.ci = commitNonce(sess, n.index, n.Ri)
}

func (n *NonceShare) GetCommit() ([]byte, error) {
	if n.ci == nil {
		return nil, errors.New("n.GetCommit failed: ci is not set")
	}
	return n.ci, nil
}

// Material to send to others at first
type MaterialToSend1 struct {
	Index    ParticipantID
	setIndex bool
	ci       []byte
	setci    bool
}

func (m *MaterialToSend1) SetIndex(index ParticipantID) {
	m.Index = index
	m.setIndex = true
}

func (m *MaterialToSend1) GetIndex() ParticipantID {
	return m.Index
}

func (m *MaterialToSend1) SetCommit(ci []byte) {
	m.ci = ci
	m.setci = true
}

func (m *MaterialToSend1) GetCommit() []byte {
	return m.ci
}

type MaterialToSend2 struct {
	Index    ParticipantID
	setIndex bool
	Ri       Point
	setRi    bool
}

func (m *MaterialToSend2) SetIndex(index ParticipantID) {
	m.Index = index
	m.setIndex = true
}

func (m *MaterialToSend2) GetIndex() ParticipantID {
	return m.Index
}

func (m *MaterialToSend2) SetRi(Ri Point) {
	m.Ri = Ri
	m.setRi = true
}

func (m *MaterialToSend2) GetRi() Point {
	return m.Ri
}

// Participant
type ParticipantSigner struct {
	p                   Participant
	P                   Point
	indices             []ParticipantID
	indicesSet          bool
	lagrangeCoefficient Scalar
	R                   Point
	n                   NonceShare
	sess                Session
	materialToSend1     MaterialToSend1  // material to send to others at first
	materialToSend2     MaterialToSend2  // material to send to others at second
	partialSig          PartialSignature // material to send to others at third
	finalSig            Signature
}

func (ps *ParticipantSigner) SetLagrangeCoefficient() error {
	if !ps.indicesSet {
		return errors.New("ps.SetLagrangeCoefficient failed: indices not set")
	}

	psIsPresent := false
	for _, id := range ps.indices {
		if id == ps.p.id {
			psIsPresent = true
		}
	}

	if !psIsPresent {
		return errors.New("ps.SetLagrangeCoefficient failed: current participant is not a signer")
	}

	var aus Scalar
	ps.lagrangeCoefficient.Set(&One)                               // coeff = one
	aus.Set(&One)                                                  // aus = one
	aus.Subtract(&aus, &alpha)                                     // aus = 1-alpha
	aus.Invert(&aus)                                               // aus = 1/(1-alpha)
	ps.lagrangeCoefficient.Multiply(&ps.lagrangeCoefficient, &aus) // coeff = alpha / (1 - alpha)

	var term Scalar
	term.Set(&One) // term = one
	for _, id := range ps.indices {
		if id == ps.p.id {
			continue
		} else {
			var aus2 Scalar
			var aus3 Scalar
			aus2.Set(&One)
			ScalarPow(&alpha, uint8(id-1), &aus2)
			aus3.Set(&One)
			ScalarPow(&alpha, uint8(ps.p.id-1), &aus3)
			aus3.Subtract(&aus3, &aus2) // aus3 = alpha^{id-1} - alpha^{p.id-1}
			aus3.Invert(&aus3)          // aus3 = 1/(alpha^{id-1} - alpha^{p.id-1})
			aus2.Multiply(&aus2, &aus3) // aus2 = alpha^{id-1} / (alpha^{id-1} - alpha^{p.id-1})
			term.Multiply(&term, &aus2)
		}
	}
	ps.lagrangeCoefficient.Multiply(&ps.lagrangeCoefficient, &term) // coeff = alpha / (1 - alpha) * product_{j!=i} (alpha^{id-1} / (alpha^{id-1} - alpha^{p.id-1}))
	return nil
}

func (ps *ParticipantSigner) GetLagrangeCoefficient() Scalar {
	return ps.lagrangeCoefficient
}

// Server

func (ps *ParticipantSigner) SetParticipant(p *Participant) {
	if p == nil {
		return
	}
	ps.p = *p
}

func (ps *ParticipantSigner) GetParticipant() *Participant {
	return &ps.p
}

func (ps *ParticipantSigner) SetP(P Point) {
	ps.P = P
}

func (ps *ParticipantSigner) GetP() Point {
	return ps.P
}

func (ps *ParticipantSigner) SetIndices(inds []ParticipantID) {
	ps.indices = inds
	ps.indicesSet = true
}

func (ps *ParticipantSigner) GetIndices() []ParticipantID {
	return ps.indices
}

func (ps *ParticipantSigner) SetSession(sess *Session) error {
	if sess == nil {
		return errors.New("ps.SetSession failed: nil session")
	}
	ps.sess = *sess
	return nil
}

func (ps *ParticipantSigner) GetSession() Session {
	return ps.sess
}

func (ps *ParticipantSigner) SetN(n NonceShare) {
	ps.n = n
}

func (ps *ParticipantSigner) GetN() NonceShare {
	return ps.n
}

func (ps *ParticipantSigner) SetMaterialToSend1(m MaterialToSend1) {
	ps.materialToSend1 = m
}

func (ps *ParticipantSigner) GetMaterialToSend1() MaterialToSend1 {
	return ps.materialToSend1
}

func (ps *ParticipantSigner) SetMaterialToSend2(m MaterialToSend2) {
	ps.materialToSend2 = m
}

func (ps *ParticipantSigner) GetMaterialToSend2() MaterialToSend2 {
	return ps.materialToSend2
}

func (ps *ParticipantSigner) VerifyNonce(mat1 *MaterialToSend1, mat2 *MaterialToSend2) (bool, error) { // Verify the material received from another participant
	if !mat1.setIndex {
		return false, errors.New("ps.VerifyNonce failed: material index is not set")
	}
	if !mat1.setci {
		return false, errors.New("ps.VerifyNonce failed: material commit is not set")
	}
	if !mat2.setIndex {
		return false, errors.New("ps.VerifyNonce failed: material index is not set")
	}
	if !mat2.setRi {
		return false, errors.New("ps.VerifyNonce failed: material Ri is not set")
	}
	if mat1.GetIndex() != mat2.GetIndex() {
		return false, errors.New("ps.VerifyNonce failed: material indices do not match")
	}

	boolean, err := VerifyNonceAux(&ps.sess, mat1.Index, mat1.ci, mat2.Ri)
	if err != nil {
		return false, fmt.Errorf("ps.VerifyNonce failed: %w", err)
	}
	return boolean, nil
}

func (ps *ParticipantSigner) SetR(mat2 []MaterialToSend2) error {
	ps.R = *edwards25519.NewIdentityPoint()
	for _, riBytes := range mat2 {
		if !riBytes.setIndex || !riBytes.setRi {
			return errors.New("ps.SetR failed: the material is incomplete")
		}
		ps.R.Add(&ps.R, &riBytes.Ri)
	}
	return nil
}

func (ps *ParticipantSigner) GetR() Point {
	return ps.R
}

func (ps *ParticipantSigner) SetPartialSignature(msg []byte) error {

	var zero Scalar

	share := ps.p.GetShare()
	lambda := ps.GetLagrangeCoefficient()

	ri := ps.n.Getri()

	if share.Equal(&zero) == 1 {
		return errors.New("ps.SetPartialSignature failed: missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("ps.SetPartialSignature failed: missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("ps.SetPartialSignature failed: missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ps.sess, &ps.R, &ps.P, msg)
	if err != nil {
		return err
	}

	fmt.Printf("sign R: %x\n", ps.R.Bytes())
	fmt.Printf("sign P: %x\n", ps.P.Bytes())
	fmt.Printf("sign sess.id: %x\n", ps.sess.GetID())
	fmt.Printf("sign sess.indexHash: %x\n", ps.sess.GetIndexHash())

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ps.partialSig = PartialSignature{
		Index:    ps.p.GetID(),
		setIndex: true,
		Z:        z,
		setZ:     true,
	}

	return nil
}

func (ps *ParticipantSigner) GetPartialSignature() PartialSignature {
	return ps.partialSig
}

func (ps *ParticipantSigner) CombineSignature(parSig []PartialSignature) error {
	if len(parSig) != len(ps.indices) {
		return errors.New("ps.CombineSignature failed: invalid number of partial signatures")
	}

	// Reject identity point
	if ps.R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("ps.CombineSignature failed: invalid R (identity point)")
	}

	expected := make(map[ParticipantID]bool)
	for _, id := range ps.indices {
		expected[id] = false
	}

	ownID := ps.p.GetID()
	if _, ok := expected[ownID]; !ok {
		return errors.New("ps.CombineSignature failed: own ID is not in signer set")
	}
	expected[ownID] = true

	// Aggregate all partial z values
	z := ps.partialSig.Z

	for _, el := range parSig {
		if !el.setIndex || !el.setZ {
			return errors.New("ps.CombineSignature failed: input is not complete")
		}

		seen, ok := expected[el.Index]
		if !ok {
			return errors.New("ps.CombineSignature failed: unexpected partial signature index")
		}
		if seen {
			return errors.New("ps.CombineSignature failed: duplicate partial signature index")
		}

		expected[el.Index] = true
		z.Add(&z, &el.Z)
	}

	for id, seen := range expected {
		if !seen {
			return fmt.Errorf("ps.CombineSignature failed: missing partial signature from index %d", id)
		}
	}

	var zero Scalar
	if z.Equal(&zero) == 1 {
		return errors.New("ps.CombineSignature failed: invalid signature scalar z = 0")
	}

	ps.finalSig = Signature{
		R: ps.R,
		Z: z,
	}

	return nil
}

func (ps *ParticipantSigner) GetSignature() Signature {
	return ps.finalSig
}

// Server
type ServerSigner struct {
	s                   Server
	P                   Point
	lagrangeCoefficient Scalar
	R                   Point
	n                   NonceShare
	indices             []ParticipantID
	indicesSet          bool
	sess                Session
	materialToSend1     MaterialToSend1  // material to send to others at first
	materialToSend2     MaterialToSend2  // material to send to others at second
	partialSig          PartialSignature // material to send to others at third
	finalSig            Signature
}

func (ss *ServerSigner) SetServer(s Server) {
	ss.s = s
}

func (ss *ServerSigner) GetServer() Server {
	return ss.s
}

func (ss *ServerSigner) SetP(P Point) {
	ss.P = P
}

func (ss *ServerSigner) GetP() Point {
	return ss.P
}

func (ss *ServerSigner) SetLagrangeCoefficient() error {
	if !ss.indicesSet {
		return errors.New("ps.SetLagrangeCoefficient failed: indices not set")
	}
	var aus Scalar
	ss.lagrangeCoefficient.Set(&alpha)                             // coeff = alpha
	aus.Set(&alpha)                                                // aus = alpha
	aus.Subtract(&aus, &One)                                       // aus = alpha - 1
	aus.Invert(&aus)                                               // aus = 1/(alpha - 1)
	ss.lagrangeCoefficient.Multiply(&ss.lagrangeCoefficient, &aus) // coeff = alpha / (alpha - 1)
	return nil
}

func (ss *ServerSigner) GetLagrangeCoefficient() Scalar {
	return ss.lagrangeCoefficient
}

func (ss *ServerSigner) SetSession(sess *Session) error {
	if sess == nil {
		return errors.New("ss.SetSession failed: nil session")
	}
	ss.sess = *sess
	return nil
}

func (ss *ServerSigner) GetSession() Session {
	return ss.sess
}

func (ss *ServerSigner) SetNonce(n NonceShare) {
	ss.n = n
}

func (ss *ServerSigner) GetNonce() NonceShare {
	return ss.n
}

func (ss *ServerSigner) SetIndices(ind []ParticipantID) {
	ss.indices = ind
	ss.indicesSet = true
}

func (ss *ServerSigner) GetIndices() []ParticipantID {
	return ss.indices
}

func (ss *ServerSigner) SetMaterialToSend1(m MaterialToSend1) {
	ss.materialToSend1 = m
}

func (ss *ServerSigner) GetMaterialToSend1() MaterialToSend1 {
	return ss.materialToSend1
}

func (ss *ServerSigner) SetMaterialToSend2(m MaterialToSend2) {
	ss.materialToSend2 = m
}

func (ss *ServerSigner) GetMaterialToSend2() MaterialToSend2 {
	return ss.materialToSend2
}

func (ss *ServerSigner) VerifyNonce(mat *MaterialToSend1, Ri Point) (bool, error) { // Verify the material received from another participant
	boolean, err := VerifyNonceAux(&ss.sess, mat.Index, mat.ci, Ri)
	if err != nil {
		return false, fmt.Errorf("ss.VerifyNonce failed: %w", err)
	}
	return boolean, nil
}

func (ss *ServerSigner) SetR(mat2 []MaterialToSend2) error {
	ss.R = *edwards25519.NewIdentityPoint()
	for _, riBytes := range mat2 {
		if !riBytes.setIndex || !riBytes.setRi {
			return errors.New("ss.SetR failed: the material is incomplete")
		}
		ss.R.Add(&ss.R, &riBytes.Ri)
	}
	return nil
}

func (ss *ServerSigner) GetR() Point {
	return ss.R
}

func (ss *ServerSigner) SetPartialSignature(msg []byte) error {

	var zero Scalar

	share := ss.s.GetShare()
	lambda := ss.GetLagrangeCoefficient()

	ri := ss.n.Getri()

	if share.Equal(&zero) == 1 {
		return errors.New("ss.SetPartialSignature failed: missing share")
	}

	if lambda.Equal(&zero) == 1 {
		return errors.New("ss.SetPartialSignature failed: missing lambda")
	}

	if ri.Equal(&zero) == 1 {
		return errors.New("ss.SetPartialSignature failed: missing ri")
	}

	// Compute the challenge
	e, err := Challenge(&ss.sess, &ss.R, &ss.P, msg)
	if err != nil {
		return fmt.Errorf("Challenge failed: %w", err)
	}

	// compute term = e*lambda*share
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// compute z = ri + term
	var z Scalar
	z.Add(&ri, &term)

	ss.partialSig = PartialSignature{
		Index:    ServerID,
		setIndex: true,
		Z:        z,
		setZ:     true,
	}

	return nil
}

func (ss *ServerSigner) GetPartialSignature() PartialSignature {
	return ss.partialSig
}

func (ss *ServerSigner) CombineSignature(parSig []PartialSignature) error {
	if !ss.indicesSet {
		return errors.New("ss.CombineSignature failed: indices not set")
	}

	if len(parSig) != len(ss.indices) {
		return errors.New("ss.CombineSignature failed: invalid number of partial signatures")
	}

	if !ss.partialSig.setIndex || !ss.partialSig.setZ {
		return errors.New("ss.CombineSignature failed: own partial signature is not set")
	}

	if ss.partialSig.Index != ServerID {
		return errors.New("ss.CombineSignature failed: own partial signature has invalid server index")
	}

	if ss.R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("ss.CombineSignature failed: invalid R identity point")
	}

	expected := make(map[ParticipantID]bool)

	for _, id := range ss.indices {
		if expected[id] {
			return errors.New("ss.CombineSignature failed: duplicate index in signer set")
		}
		expected[id] = false
	}

	z := ss.partialSig.Z

	for _, el := range parSig {
		if !el.setIndex || !el.setZ {
			return errors.New("ss.CombineSignature failed: input partial signature is not complete")
		}

		seen, ok := expected[el.Index]
		if !ok {
			return fmt.Errorf("ss.CombineSignature failed: unexpected partial signature index %d", el.Index)
		}

		if seen {
			return fmt.Errorf("ss.CombineSignature failed: duplicate partial signature for index %d", el.Index)
		}

		expected[el.Index] = true
		z.Add(&z, &el.Z)
	}

	for id, seen := range expected {
		if !seen {
			return fmt.Errorf("ss.CombineSignature failed: missing partial signature from index %d", id)
		}
	}

	var zero Scalar
	if z.Equal(&zero) == 1 {
		return errors.New("ss.CombineSignature failed: invalid signature scalar z = 0")
	}

	ss.finalSig = Signature{
		R: ss.R,
		Z: z,
	}

	return nil
}

func (ss *ServerSigner) GetSignature() Signature {
	return ss.finalSig
}
