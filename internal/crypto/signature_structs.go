package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
)

// This file implements the threshold Schnorr signing phase.
//
// The LSSS share-generation phase gives each signer a share s_i = v · M_i.
// During signing, each active signer computes a reconstruction coefficient
// lambda_i for the selected signer set and produces a partial Schnorr signature:
//
//     z_i = r_i + e * lambda_i * s_i.
//
// The final signature is obtained by aggregating all partial values z_i.

// Session
// Session binds one signing execution to a signer set.
//
// The session identifier prevents replay across different signing attempts,
// while indexHash binds the challenge to the exact set of active signers.

type Session struct {
	id        []byte
	indices   []ParticipantID
	indexHash []byte
	usernames []string
}

// HasParticipant checks whether a friend belongs to the active signer set.
// Auxiliary function for the following one
func (s *Session) HasParticipant(id ParticipantID) bool {
	return slices.Contains(s.indices, id)
}

func (s *Session) GetUsernames() []string {
	return s.usernames
}

func (s *Session) AddUsername(username string) error {
	if len(username) == 0 {
		return errors.New("emtpy username")
	}
	s.usernames = append(s.usernames, username)
	return nil
}

// HasSigner checks whether id is an active signer.
//
// The server is mandatory in the access policy and is represented by ServerID.
func (s *Session) HasSigner(id ParticipantID) bool {
	if id == ServerID {
		return true
	}
	return s.HasParticipant(id)
}

// SetID samples a fresh identifier for this signing session.
// Does it work?
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

// SetIndices stores the friend indices participating in this session.
func (s *Session) SetIndices(indices []ParticipantID) {
	s.indices = indices
}

func (s *Session) GetIndices() []ParticipantID {
	out := make([]ParticipantID, len(s.indices))
	copy(out, s.indices)
	return out
}

// SetIndexHash hashes the ordered signer indices.
//
// This value is included in the Schnorr challenge to bind the signature to the
// selected reconstruction set.
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

// PartialSignature is the Schnorr partial signature produced by one signer.
//
// Z stores z_i = r_i + e * lambda_i * s_i.
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

// Signature is the final aggregated Schnorr signature.
//
// It satisfies:
//
//	Z*G = R + e*P.
type Signature struct {
	R Point
	Z Scalar
}

// NonceShare stores the nonce material of one signer.
//
// Each signer samples r_i, publishes R_i = r_i*G, and first commits to R_i
// before revealing it.
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

// Setri samples the private nonce r_i.
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

// SetRi computes the public nonce R_i = r_i*G.
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

// SetCommit computes the commitment c_i = H(session, i, R_i).
//
// This is the first round of the commit-and-reveal nonce exchange.
func (n *NonceShare) SetCommit(sess *Session) {
	n.ci = commitNonce(sess, n.index, n.Ri)
}

func (n *NonceShare) GetCommit() ([]byte, error) {
	if n.ci == nil {
		return nil, errors.New("n.GetCommit failed: ci is not set")
	}
	return n.ci, nil
}

// MaterialToSend1 is the first-round message.
//
// It contains only the nonce commitment c_i and the index i.
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

// MaterialToSend2 is the second-round message.
//
// It reveals the public nonce R_i previously committed to in MaterialToSend1.
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

// ParticipantSigner handles the signing state of a friend.
//
// The participant uses its LSSS share s_i and reconstruction coefficient
// lambda_i to produce a partial Schnorr signature.
type ParticipantSigner struct {
	p                   Participant     // Friend holding share s_i.
	P                   Point           // Dealer public key P = sG.
	indices             []ParticipantID // Active friend indices.
	indicesSet          bool
	lagrangeCoefficient Scalar // Reconstruction coefficient lambda_i.
	R                   Point  // Aggregated nonce R = sum R_i.
	n                   NonceShare
	sess                Session
	materialToSend1     MaterialToSend1  // Round 1: nonce commitment c_i.
	materialToSend2     MaterialToSend2  // Round 2: nonce opening R_i.
	partialSig          PartialSignature // Round 3: partial signature z_i.
	finalSig            Signature
}

// SetLagrangeCoefficient computes lambda_i for a friend signer.
//
// The coefficient reconstructs the secret from the active LSSS shares without
// explicitly reconstructing s. It is the coefficient used in:
//
//	z_i = r_i + e * lambda_i * s_i.
//
// The formula is the one derived in the report.
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
	ps.lagrangeCoefficient.Multiply(&ps.lagrangeCoefficient, &aus) // coeff = 1 / (1 - alpha)

	var term Scalar
	term.Set(&One)
	// Product over the other active friends:
	//     alpha^{j-1} / (alpha^{j-1} - alpha^{i-1}).
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
	// Final friend reconstruction coefficient lambda_i.
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

// VerifyNonce checks the commit-and-reveal consistency of another signer's nonce.
//
// It verifies that the revealed R_i matches the first-round commitment c_i for
// the same session and signer index.
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

// SetR aggregates the public nonces of all active signers:
// In the input must appear also mat2 of ps
//
//	R = sum_i R_i.
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

// SetPartialSignature computes the participant partial Schnorr signature.
// It first computes the challenge
//
//	e = H(R || P || msg || session),
//
// then computes:
//
//	z_i = r_i + e * lambda_i * s_i.
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

	// Compute the Schnorr challenge e.
	e, err := Challenge(&ps.sess, &ps.R, &ps.P, msg)
	if err != nil {
		return err
	}

	fmt.Printf("sign R: %x\n", ps.R.Bytes())
	fmt.Printf("sign P: %x\n", ps.P.Bytes())
	fmt.Printf("sign sess.id: %x\n", ps.sess.GetID())
	fmt.Printf("sign sess.indexHash: %x\n", ps.sess.GetIndexHash())

	// term = e * lambda_i * s_i.
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// z_i = r_i + term.
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

// CombineSignature aggregates the partial signatures.
//
// Given z_i values from all active signers, it computes:
//
//	Z = sum_i {z_i}.
//
// The resulting signature is (R, Z).
func (ps *ParticipantSigner) CombineSignature(parSig []PartialSignature) error {
	if len(parSig) != len(ps.indices) {
		return errors.New("ps.CombineSignature failed: invalid number of partial signatures")
	}

	// Reject the identity Point, which would make the Schnorr signature invalid.
	if ps.R.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("ps.CombineSignature failed: invalid R (identity point)")
	}

	// Track the expected signer indices to reject missing, duplicate, or unexpected
	// partial signatures.
	expected := make(map[ParticipantID]bool)
	for _, id := range ps.indices {
		expected[id] = false
	}

	ownID := ps.p.GetID()
	if _, ok := expected[ownID]; !ok {
		return errors.New("ps.CombineSignature failed: own ID is not in signer set")
	}
	expected[ownID] = true

	// Aggregate all partial z_i values.
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

// ServerSigner handles the signing state of the mandatory server.
//
// The server uses its share s_0 and coefficient lambda_0 to produce its partial
// Schnorr signature.

type ServerSigner struct {
	s                   Server
	P                   Point
	lagrangeCoefficient Scalar
	R                   Point
	n                   NonceShare
	indices             []ParticipantID
	indicesSet          bool
	sess                Session
	materialToSend1     MaterialToSend1  // Round 1: nonce commitment c_i.
	materialToSend2     MaterialToSend2  // Round 2: nonce opening R_i.
	partialSig          PartialSignature // Round 3: partial signature z_i.
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

// SetLagrangeCoefficient computes the server reconstruction coefficient.
//
// For the server share s_0, the report-derived coefficient is:
//
//	lambda_0 = alpha / (alpha - 1).
func (ss *ServerSigner) SetLagrangeCoefficient() error {
	if !ss.indicesSet {
		return errors.New("ps.SetLagrangeCoefficient failed: indices not set")
	}
	var aus Scalar
	ss.lagrangeCoefficient.Set(&alpha)                             // numerator = alpha
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

// VerifyNonce checks that a revealed nonce R_i matches its prior commitment.
func (ss *ServerSigner) VerifyNonce(mat1 *MaterialToSend1, mat2 *MaterialToSend2) (bool, error) { // Verify the material received from another participant
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

	boolean, err := VerifyNonceAux(&ss.sess, mat1.Index, mat1.ci, mat2.Ri)
	if err != nil {
		return false, fmt.Errorf("ps.VerifyNonce failed: %w", err)
	}
	return boolean, nil
}

// SetR aggregates all public nonces:
//
//	R = sum_i {R_i}.
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

// SetPartialSignature computes the server partial Schnorr signature:
//
//	z_0 = r_0 + e * lambda_0 * s_0.
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

	// Compute the Schnorr challenge e.
	e, err := Challenge(&ss.sess, &ss.R, &ss.P, msg)
	if err != nil {
		return fmt.Errorf("Challenge failed: %w", err)
	}

	// term = e * lambda_0 * s_0.
	var term Scalar
	term.Multiply(&lambda, &share)
	term.Multiply(&term, &e)

	// z_0 = r_0 + term.
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

// CombineSignature aggregates the server and participant partial signatures.
//
// The output is the final Schnorr signature (R, Z), where:
//
//	Z = z_0 + sum_i {z_i}.
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
