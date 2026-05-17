package test

import (
	"fmt"
	"testing"

	"threshold-recovery/internal/crypto"
)

func testSessionID(seed byte) []byte {
	id := make([]byte, 32)
	for i := range id {
		id[i] = seed
	}
	return id
}

// makeParticipantNonce generates and sets a participant nonce share.
func makeParticipantNonce(t *testing.T, ps *crypto.ParticipantSigner) crypto.NonceShare {
	t.Helper()

	var nonce crypto.NonceShare

	if err := nonce.SetIndex(ps.GetParticipant().GetID()); err != nil {
		t.Fatalf("failed to set participant nonce index: %v", err)
	}
	if err := nonce.Setri(); err != nil {
		t.Fatalf("failed to generate participant private nonce: %v", err)
	}
	if err := nonce.SetRi(); err != nil {
		t.Fatalf("failed to compute participant public nonce: %v", err)
	}

	sess := ps.GetSession()
	nonce.SetCommit(&sess)

	ps.SetN(nonce)

	return nonce
}

// makeServerNonce is analogous to makeParticipantNonce, but for the server nonce share.
func makeServerNonce(t *testing.T, ss *crypto.ServerSigner) crypto.NonceShare {
	t.Helper()

	var nonce crypto.NonceShare

	if err := nonce.SetIndex(crypto.ServerID); err != nil {
		t.Fatalf("failed to set server nonce index: %v", err)
	}
	if err := nonce.Setri(); err != nil {
		t.Fatalf("failed to generate server private nonce: %v", err)
	}
	if err := nonce.SetRi(); err != nil {
		t.Fatalf("failed to compute server public nonce: %v", err)
	}

	sess := ss.GetSession()
	nonce.SetCommit(&sess)

	ss.SetNonce(nonce)

	return nonce
}

// makeMaterial1 constructs the first protocol message containing participant index
// and nonce commitment.
func makeMaterial1(t *testing.T, n crypto.NonceShare) crypto.MaterialToSend1 {
	t.Helper()

	ci, err := n.GetCommit()
	if err != nil {
		t.Fatalf("failed to get nonce commitment: %v", err)
	}

	var m crypto.MaterialToSend1
	m.SetIndex(n.GetIndex())
	m.SetCommit(ci)

	return m
}

// makeMaterial2 constructs the second protocol message containing the participant index
// and public nonce value (Ri).
func makeMaterial2(t *testing.T, n crypto.NonceShare) crypto.MaterialToSend2 {
	t.Helper()

	Ri, err := n.GetRi()
	if err != nil {
		t.Fatalf("failed to get public nonce Ri: %v", err)
	}

	var m crypto.MaterialToSend2
	m.SetIndex(n.GetIndex())
	m.SetRi(*Ri)

	return m
}

// checkShareConsistency builds a participant and verifies that its share
// is consistent with the dealer's VSS commitment.
func checkShareConsistency(
	t *testing.T,
	name string,
	id crypto.ParticipantID,
	shareIndex int,
	dealer *crypto.Dealer,
) *crypto.Participant {
	t.Helper()

	p := new(crypto.Participant)

	if err := p.SetID(id); err != nil {
		t.Fatalf("failed to set %s ID: %v", name, err)
	}

	if err := p.SetName(name); err != nil {
		t.Fatalf("failed to set %s name: %v", name, err)
	}

	if err := p.SetShare(dealer.GetParticipantShares(shareIndex)); err != nil {
		t.Fatalf("failed to set %s share: %v", name, err)
	}

	ok, err := p.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		t.Fatalf("%s consistency verification failed: %v", name, err)
	}
	if !ok {
		t.Fatalf("%s's share is NOT consistent with the commitment", name)
	}

	logOK(t, name+"'s share is consistent with the commitment")

	return p
}

// initParticipantSigner initializes and configures a participant signer for LSSS reconstruction.
func initParticipantSigner(
	t *testing.T,
	name string,
	p *crypto.Participant,
	P crypto.Point,
	ids []crypto.ParticipantID,
	sess *crypto.Session,
) *crypto.ParticipantSigner {
	t.Helper()

	ps := new(crypto.ParticipantSigner)

	ps.SetParticipant(p)
	ps.SetP(P)
	if err := ps.SetIndices(ids); err != nil {
		t.Fatalf("failed to set %s signer indices: %v", name, err)
	}
	if err := ps.SetSession(sess); err != nil {
		t.Fatalf("failed to set %s signer session: %v", name, err)
	}

	if err := ps.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set %s Lagrange coefficient: %v", name, err)
	}

	logOK(t, name+" signer initialized")

	return ps
}

// verifyNonceFromParticipant verifies a participant's nonce commitment (server-side) using M1 and M2.
func verifyNonceFromParticipant(
	t *testing.T,
	server *crypto.ServerSigner,
	name string,
	ps *crypto.ParticipantSigner,
) {
	t.Helper()

	m1 := ps.GetMaterialToSend1()
	m2 := ps.GetMaterialToSend2()

	ok, err := server.VerifyNonce(&m1, &m2)
	if err != nil {
		t.Fatalf("server failed while verifying %s nonce: %v", name, err)
	}
	if !ok {
		t.Fatalf("server rejected %s nonce", name)
	}

	logOK(t, name+" nonce commitment verified")
}

// Test 1: TestLSSSFullSigningFlow verifies the complete execution of the
// LSSS + VSS + threshold Schnorr signing protocol.
func TestLSSSFullSigningFlow(t *testing.T) {
	logSection(t, "LSSS / VSS + Threshold Signing - Full Flow")

	n := 5
	k := 3

	// 1. Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}
	logOK(t, fmt.Sprintf("Threshold parameters set: n = %d, k = %d", n, k))

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate dealer secret: %v", err)
	}
	logOK(t, "Dealer secret generated")

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)
	logOK(t, "Public key P = secret * G computed")

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}
	logOK(t, fmt.Sprintf("Participants registered by dealer: %v", friends))

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate commitments and shares: %v", err)
	}
	logOK(t, "Dealer generated VSS commitments and distributed shares")

	// 2. Each participant verifies that their received share is
	// consistent with dealer's public commitment.

	logSection(t, "2. Share consistency verification")

	Gianni := checkShareConsistency(t, "Gianni", 3, 2, dealer)
	Pino := checkShareConsistency(t, "Pino", 1, 0, dealer)
	Gino := checkShareConsistency(t, "Gino", 2, 1, dealer)
	Cornelio := checkShareConsistency(t, "Cornelio", 4, 3, dealer)
	Beppe := checkShareConsistency(t, "Beppe", 5, 4, dealer)

	_ = Gino
	_ = Beppe

	logOK(t, "All received participant shares passed VSS consistency verification")

	// 3. Build the authorized signing group (server + k participants)
	// and initialize session data.

	logSection(t, "3. Server and signing session setup")

	S := new(crypto.Server)
	ServerS := new(crypto.ServerSigner)

	// ids contains only the signing participants,
	// ServerID is handled separately by the protocol.
	ids := []crypto.ParticipantID{1, 3, 4}
	logOK(t, fmt.Sprintf("Signing participant indices selected: %v", ids))
	logOK(t, "ServerID is not included in indices and is handled separately")

	ServerS.SetP(P)
	ServerS.SetIndices(ids)

	S.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	S.SetParams(&aux)

	ServerS.SetServer(*S)
	logOK(t, "Server share and public parameters assigned to ServerSigner")

	var sess crypto.Session
	id := testSessionID(0x01)
	if err := sess.SetID(id); err != nil {
		t.Fatalf("failed to set session ID: %v", err)
	}
	logOK(t, fmt.Sprintf("Signing session ID set: %x", id))

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)
	logOK(t, "Session indices and index hash set")

	ServerS.SetSession(&sess)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set server Lagrange coefficient: %v", err)
	}
	logOK(t, "Server Lagrange coefficient computed")

	PinoS := initParticipantSigner(t, "Pino", Pino, P, ids, &sess)
	GianniS := initParticipantSigner(t, "Gianni", Gianni, P, ids, &sess)
	CornelioS := initParticipantSigner(t, "Cornelio", Cornelio, P, ids, &sess)

	logOK(t, "Participant signers initialized with same public key, indices, and session")

	// 4. All signing parties generate nonce commitment and reveal
	// their public nonces.

	logSection(t, "4. Nonce commitment phase")

	nonceServer := makeServerNonce(t, ServerS)
	logOK(t, "Server generated private nonce r_server and public nonce R_server")

	noncePino := makeParticipantNonce(t, PinoS)
	logOK(t, "Pino generated private nonce r_i and public nonce R_i")

	nonceGianni := makeParticipantNonce(t, GianniS)
	logOK(t, "Gianni generated private nonce r_i and public nonce R_i")

	nonceCornelio := makeParticipantNonce(t, CornelioS)
	logOK(t, "Cornelio generated private nonce r_i and public nonce R_i")

	m1Server := makeMaterial1(t, nonceServer)
	m1Pino := makeMaterial1(t, noncePino)
	m1Gianni := makeMaterial1(t, nonceGianni)
	m1Cornelio := makeMaterial1(t, nonceCornelio)

	ServerS.SetMaterialToSend1(m1Server)
	PinoS.SetMaterialToSend1(m1Pino)
	GianniS.SetMaterialToSend1(m1Gianni)
	CornelioS.SetMaterialToSend1(m1Cornelio)

	logOK(t, "M1 messages created: nonce commitments for server and all signing participants")

	m2Server := makeMaterial2(t, nonceServer)
	m2Pino := makeMaterial2(t, noncePino)
	m2Gianni := makeMaterial2(t, nonceGianni)
	m2Cornelio := makeMaterial2(t, nonceCornelio)

	ServerS.SetMaterialToSend2(m2Server)
	PinoS.SetMaterialToSend2(m2Pino)
	GianniS.SetMaterialToSend2(m2Gianni)
	CornelioS.SetMaterialToSend2(m2Cornelio)

	logOK(t, "M2 messages created: public nonce openings for server and all signing participants")

	// Server checks that each revealed nonce matches its commitment.
	verifyNonceFromParticipant(t, ServerS, "Pino", PinoS)
	verifyNonceFromParticipant(t, ServerS, "Gianni", GianniS)
	verifyNonceFromParticipant(t, ServerS, "Cornelio", CornelioS)

	logOK(t, "Server verified that each participant's M2 opening matches its previous M1 commitment")

	// 5. All the authorized signers compute the same aggregate nonce R.

	logSection(t, "5. Aggregate nonce computation")

	allM2 := []crypto.MaterialToSend2{
		m2Server,
		m2Pino,
		m2Gianni,
		m2Cornelio,
	}

	logOK(t, fmt.Sprintf("Collected all M2 messages: server + %d participants", len(ids)))

	if err := ServerS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for server: %v", err)
	}
	logOK(t, "Server computed aggregate nonce R from all public nonces")

	if err := PinoS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Pino: %v", err)
	}
	logOK(t, "Pino computed the same aggregate nonce R")

	if err := GianniS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Gianni: %v", err)
	}
	logOK(t, "Gianni computed the same aggregate nonce R")

	if err := CornelioS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Cornelio: %v", err)
	}
	logOK(t, "Cornelio computed the same aggregate nonce R")

	logOK(t, "All signing parties are now bound to the same aggregate nonce R")

	// 6. Each signer produces its own partial Schnorr signature, using
	// its share, nonce, and session challenge.

	logSection(t, "6. Partial signature generation")

	msg := []byte("transaction made")
	logOK(t, fmt.Sprintf("Message to be signed set: %q", msg))

	if err := ServerS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute server partial signature: %v", err)
	}
	logOK(t, "Server computed its partial signature using server share and server nonce")

	if err := PinoS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Pino partial signature: %v", err)
	}
	logOK(t, "Pino computed his partial signature using participant share and nonce")

	if err := GianniS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Gianni partial signature: %v", err)
	}
	logOK(t, "Gianni computed his partial signature using participant share and nonce")

	if err := CornelioS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Cornelio partial signature: %v", err)
	}
	logOK(t, "Cornelio computed his partial signature using participant share and nonce")

	// 7. Partial signatures are combined into the final threshold signature.

	logSection(t, "7. Final signature combination")

	allPartials := []crypto.PartialSignature{
		ServerS.GetPartialSignature(),
		PinoS.GetPartialSignature(),
		GianniS.GetPartialSignature(),
		CornelioS.GetPartialSignature(),
	}

	logOK(t, fmt.Sprintf("Collected all partial signatures: server + %d participants", len(ids)))

	if err := ServerS.CombineSignature(allPartials); err != nil {
		t.Fatalf("server failed to combine threshold signature: %v", err)
	}
	sigServer := ServerS.GetSignature()
	logOK(t, "Server combined all partial signatures into the final threshold signature")

	if err := PinoS.CombineSignature(allPartials); err != nil {
		t.Fatalf("Pino failed to combine threshold signature: %v", err)
	}
	sigPino := PinoS.GetSignature()
	logOK(t, "Pino independently combined all partial signatures into the final threshold signature")

	if err := GianniS.CombineSignature(allPartials); err != nil {
		t.Fatalf("Gianni failed to combine threshold signature: %v", err)
	}
	sigGianni := GianniS.GetSignature()
	logOK(t, "Gianni independently combined all partial signatures into the final threshold signature")

	if err := CornelioS.CombineSignature(allPartials); err != nil {
		t.Fatalf("Cornelio failed to combine threshold signature: %v", err)
	}
	sigCornelio := CornelioS.GetSignature()
	logOK(t, "Cornelio independently combined all partial signatures into the final threshold signature")

	if sigServer.R.Equal(&sigPino.R) != 1 || sigServer.Z.Equal(&sigPino.Z) != 1 {
		t.Fatalf("server-combined and Pino-combined signatures are different")
	}
	logOK(t, "Server-combined and Pino-combined signatures are identical")

	if sigServer.R.Equal(&sigGianni.R) != 1 || sigServer.Z.Equal(&sigGianni.Z) != 1 {
		t.Fatalf("server-combined and Gianni-combined signatures are different")
	}
	logOK(t, "Server-combined and Gianni-combined signatures are identical")

	if sigServer.R.Equal(&sigCornelio.R) != 1 || sigServer.Z.Equal(&sigCornelio.Z) != 1 {
		t.Fatalf("server-combined and Cornelio-combined signatures are different")
	}
	logOK(t, "Server-combined and Cornelio-combined signatures are identical")

	//  8. Reconstruct the dealer secret from the authorized set
	// to confirm that shares and coefficients are correct.

	logSection(t, "8. Reconstruction sanity check")

	lambdaServer := ServerS.GetLagrangeCoefficient()
	lambdaPino := PinoS.GetLagrangeCoefficient()
	lambdaGianni := GianniS.GetLagrangeCoefficient()
	lambdaCornelio := CornelioS.GetLagrangeCoefficient()

	server := ServerS.GetServer()
	pino := PinoS.GetParticipant()
	gianni := GianniS.GetParticipant()
	cornelio := CornelioS.GetParticipant()

	shareServer := server.GetShare()
	sharePino := pino.GetShare()
	shareGianni := gianni.GetShare()
	shareCornelio := cornelio.GetShare()

	var rec crypto.Scalar
	var tmp crypto.Scalar

	tmp.Multiply(&lambdaServer, &shareServer)
	rec.Add(&rec, &tmp)
	logOK(t, "Added server weighted share to reconstruction check")

	tmp.Multiply(&lambdaPino, &sharePino)
	rec.Add(&rec, &tmp)
	logOK(t, "Added Pino weighted share to reconstruction check")

	tmp.Multiply(&lambdaGianni, &shareGianni)
	rec.Add(&rec, &tmp)
	logOK(t, "Added Gianni weighted share to reconstruction check")

	tmp.Multiply(&lambdaCornelio, &shareCornelio)
	rec.Add(&rec, &tmp)
	logOK(t, "Added Cornelio weighted share to reconstruction check")

	if rec.Equal(&secret) != 1 {
		t.Fatalf("reconstructed scalar does not match dealer secret")
	}
	logOK(t, "Weighted shares reconstruct the original dealer secret")

	var recP crypto.Point
	recP.ScalarBaseMult(&rec)

	var secretP crypto.Point
	secretP.ScalarBaseMult(&secret)

	if recP.Equal(&secretP) != 1 {
		t.Fatalf("reconstructed public key does not match dealer public key")
	}
	logOK(t, "Reconstructed scalar gives the same public key as the dealer secret")

	if P.Equal(&secretP) != 1 {
		t.Fatalf("dealer public key does not match secret-derived public key")
	}
	logOK(t, "Dealer public key matches the public key derived from the secret")

	// 9. Verify that the final signature is valid.
	// It is sufficient to verify the validity of the Server signature, since
	// it was previously verified that all signers have obtained the same Z.

	logSection(t, "9. Final signature verification")

	valid, err := crypto.VerifySignature(P, msg, sigServer, sess)
	if err != nil {
		t.Fatalf("server-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("server-combined final threshold signature is NOT valid")
	}
	logOK(t, "Final signature combined by the server verifies successfully")

	valid, err = crypto.VerifySignature(P, msg, sigPino, sess)
	if err != nil {
		t.Fatalf("Pino-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("Pino-combined final threshold signature is NOT valid")
	}
	logOK(t, "Final signature combined by Pino verifies successfully")

	valid, err = crypto.VerifySignature(P, msg, sigGianni, sess)
	if err != nil {
		t.Fatalf("Gianni-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("Gianni-combined final threshold signature is NOT valid")
	}
	logOK(t, "Final signature combined by Gianni verifies successfully")

	valid, err = crypto.VerifySignature(P, msg, sigCornelio, sess)
	if err != nil {
		t.Fatalf("Cornelio-combined signature verification returned error: %v", err)
	}
	if !valid {
		t.Fatalf("Cornelio-combined final threshold signature is NOT valid")
	}
	logOK(t, "Final signature combined by Cornelio verifies successfully")

	logSection(t, "Test completed successfully")
	logOK(t, "The full LSSS threshold signing flow is valid")
}

// Test 2: TestParticipantRejectsTamperedShare verifies that a participant
// rejects a tampered LSSS share even if the dealer commitment is unchanged.
func TestParticipantRejectsTamperedShare(t *testing.T) {
	logSection(t, "Security Test: Participant Rejects Tampered Share")

	n := 5
	k := 3

	// Dealer generates the secret, distributes valid shares,
	// and publishes commitment for verifiable secret sharing.
	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}
	logOK(t, fmt.Sprintf("Threshold parameters set: n = %d, k = %d", n, k))

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate dealer secret: %v", err)
	}
	logOK(t, "Dealer secret generated")

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}
	logOK(t, fmt.Sprintf("Participants registered by dealer: %v", friends))

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate commitment and shares: %v", err)
	}
	logOK(t, "Dealer generated VSS commitment and distributed valid shares")

	// Initialize a participant and retrieve the original assigned share.

	logSection(t, "2. Honest participant initialization")

	p := new(crypto.Participant)

	if err := p.SetID(1); err != nil {
		t.Fatalf("failed to set participant ID: %v", err)
	}
	logOK(t, "Participant ID set: Pino has index 1")

	if err := p.SetName("Pino"); err != nil {
		t.Fatalf("failed to set participant name: %v", err)
	}
	logOK(t, "Participant name set: Pino")

	share := dealer.GetParticipantShares(0)
	logOK(t, "Original valid share for Pino retrieved from the dealer")

	// Simulate post-distribution tampering by modifying the share,
	// leaving the dealer's public commitment unchanged.

	logSection(t, "3. Tampering attack")

	var tamperedShare crypto.Scalar
	tamperedShare.Add(&share, &crypto.One)

	logOK(t, "Pino's original share was modified by adding 1")

	if err := p.SetShare(tamperedShare); err != nil {
		t.Fatalf("failed to assign tampered share to Pino: %v", err)
	}

	logOK(t, "Tampered share assigned to Pino while keeping the original public commitment unchanged")

	// Verify that the altered share is detected and rejected.

	logSection(t, "4. VSS consistency verification")

	ok, err := p.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		t.Fatalf("VerifyConsistency returned unexpected error: %v", err)
	}

	logOK(t, "Participant checked the tampered share against the dealer's original public commitment")

	if ok {
		t.Fatal("participant accepted a tampered share as valid")
	}

	logOK(t, "VSS consistency verification rejected the tampered share")
}

// Test 3: TestTamperedPartialSignature verifies that a tampered partial
// signature is detected and causes final verification to fail.
func TestTamperedPartialSignature(t *testing.T) {
	logSection(t, "Security Test: Tampered Partial Signature")

	n := 4
	k := 2

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("params failed: %v", err)
	}
	logOK(t, fmt.Sprintf("Threshold parameters set: n = %d, k = %d", n, k))

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("secret failed: %v", err)
	}
	logOK(t, "Dealer secret generated")

	friends := []string{"A", "B", "C", "D"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("friends failed: %v", err)
	}
	logOK(t, fmt.Sprintf("Participants registered by dealer: %v", friends))

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("shares failed: %v", err)
	}
	logOK(t, "Dealer generated VSS commitments and distributed shares")

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)
	logOK(t, "Public key P = secret * G computed")

	// Initialize session and server signer.
	logSection(t, "2. Signing session setup")

	ids := []crypto.ParticipantID{1, 2}
	logOK(t, fmt.Sprintf("Signing participant indices selected: %v", ids))
	logOK(t, "ServerID is not included in indices and is handled separately")

	var sess crypto.Session
	if err := sess.SetID(testSessionID(0x11)); err != nil {
		t.Fatalf("failed to set session ID: %v", err)
	}
	logOK(t, fmt.Sprintf("Signing session ID set: %x", sess.GetID()))

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)
	logOK(t, "Session indices and index hash set")

	server := new(crypto.Server)
	server.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server.SetParams(&aux)

	ss := new(crypto.ServerSigner)
	ss.SetServer(*server)
	ss.SetP(P)
	ss.SetIndices(ids)
	ss.SetSession(&sess)

	if err := ss.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server lagrange failed: %v", err)
	}
	logOK(t, "Server signer initialized and server Lagrange coefficient computed")

	// Participants verify share consistency with the dealer commitment.
	logSection(t, "3. Share consistency verification")

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p2 := checkShareConsistency(t, "P2", 2, 1, dealer)

	logOK(t, "Both participant shares passed VSS consistency verification")

	ps1 := initParticipantSigner(t, "P1", p1, P, ids, &sess)
	ps2 := initParticipantSigner(t, "P2", p2, P, ids, &sess)

	logOK(t, "Participant signers initialized with same public key, indices, and session")

	// Participants and server derive aggregate nonce R.

	logSection(t, "4. Nonce generation and aggregate nonce computation")

	nonceServer := makeServerNonce(t, ss)
	logOK(t, "Server generated private nonce r_server and public nonce R_server")

	nonce1 := makeParticipantNonce(t, ps1)
	logOK(t, "P1 generated private nonce r_i and public nonce R_i")

	nonce2 := makeParticipantNonce(t, ps2)
	logOK(t, "P2 generated private nonce r_i and public nonce R_i")

	allM2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer),
		makeMaterial2(t, nonce1),
		makeMaterial2(t, nonce2),
	}
	logOK(t, "Collected all public nonce openings: server + P1 + P2")

	if err := ss.SetR(allM2); err != nil {
		t.Fatalf("server SetR failed: %v", err)
	}
	logOK(t, "Server computed aggregate nonce R from all public nonces")

	if err := ps1.SetR(allM2); err != nil {
		t.Fatalf("ps1 SetR failed: %v", err)
	}
	logOK(t, "P1 computed the same aggregate nonce R")

	if err := ps2.SetR(allM2); err != nil {
		t.Fatalf("ps2 SetR failed: %v", err)
	}
	logOK(t, "P2 computed the same aggregate nonce R")

	// Generate partial signatures.

	logSection(t, "5. Honest partial signature generation")

	msg := []byte("hello")
	logOK(t, fmt.Sprintf("Message to be signed set: %q", msg))

	if err := ss.SetPartialSignature(msg); err != nil {
		t.Fatalf("server partial signature failed: %v", err)
	}
	logOK(t, "Server computed its honest partial signature")

	if err := ps1.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps1 partial signature failed: %v", err)
	}
	logOK(t, "P1 computed its honest partial signature")

	if err := ps2.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps2 partial signature failed: %v", err)
	}
	logOK(t, "P2 computed its honest partial signature")

	// One partial signature is tampered before combination.

	logSection(t, "6. Tampering attack")

	tampered := ps1.GetPartialSignature()

	tampered.Z.Add(&tampered.Z, &crypto.One)

	logOK(t, "P1 partial signature was tampered while keeping the same participant index")

	attacked := []crypto.PartialSignature{
		ss.GetPartialSignature(),
		tampered,
		ps2.GetPartialSignature(),
	}

	logOK(t, "Built attacked partial signature vector: server honest + P1 tampered + P2 honest")

	// Combine partial signatures and attempt final verification.

	logSection(t, "7. Combination and final verification")

	if err := ss.CombineSignature(attacked); err != nil {
		t.Fatalf("combine failed unexpectedly: %v", err)
	}
	logOK(t, "CombineSignature accepted the structurally valid partial signature vector")

	sig := ss.GetSignature()
	logOK(t, "Final signature was built from the attacked partial signatures")

	valid, err := crypto.VerifySignature(P, msg, sig, sess)
	if err != nil {
		t.Fatalf("VerifySignature returned unexpected error: %v", err)
	}

	if valid {
		t.Fatalf("tampered partial signature produced a valid final signature")
	}

	logOK(t, "Final verification rejected the signature produced with the tampered partial")
	logOK(t, "Tampered partial signature attack correctly failed")
}

// Test 4: TestReplayAttackDifferentSession verifies that replaying a valid
// partial signature from one session into a different session is detected
// and causes final verification to fail.
func TestReplayAttackDifferentSession(t *testing.T) {
	logSection(t, "Security Test: Replay Attack Across Sessions")

	n := 5
	k := 3

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed params: %v", err)
	}
	logOK(t, fmt.Sprintf("Threshold parameters set: n = %d, k = %d", n, k))

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed secret: %v", err)
	}
	logOK(t, "Dealer secret generated")

	friends := []string{"A", "B", "C", "D", "E"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed friends: %v", err)
	}
	logOK(t, fmt.Sprintf("Participants registered by dealer: %v", friends))

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed shares: %v", err)
	}
	logOK(t, "Dealer generated VSS commitments and distributed shares")

	secret := dealer.GetSecret()

	var P crypto.Point
	P.ScalarBaseMult(&secret)

	logOK(t, "Public key P = secret * G computed")

	// ids contains only the signing participants.
	ids := []crypto.ParticipantID{1, 3, 4}
	logOK(t, fmt.Sprintf("Signing participant indices selected: %v", ids))
	logOK(t, "ServerID is not included in indices and is handled separately")

	msg := []byte("hello")
	logOK(t, fmt.Sprintf("Message to be signed set: %q", msg))

	// Participants verify share consistency with the dealer commitment.

	logSection(t, "2. Share consistency verification")

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p3 := checkShareConsistency(t, "P3", 3, 2, dealer)
	p4 := checkShareConsistency(t, "P4", 4, 3, dealer)

	logOK(t, "All selected participant shares passed VSS consistency verification")

	// Initialize Session 1 as a legitimate signing session.

	logSection(t, "3. Session 1 setup")

	var sess1 crypto.Session
	if err := sess1.SetID(testSessionID(0x01)); err != nil {
		t.Fatalf("failed session1 ID: %v", err)
	}
	logOK(t, fmt.Sprintf("Session 1 ID set: %x", sess1.GetID()))

	sess1.SetIndices(ids)
	sess1.SetIndexHash(ids)
	logOK(t, "Session 1 indices and index hash set")

	server1 := new(crypto.Server)
	server1.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server1.SetParams(&aux)

	serverSigner1 := new(crypto.ServerSigner)
	serverSigner1.SetServer(*server1)
	serverSigner1.SetP(P)
	serverSigner1.SetIndices(ids)
	serverSigner1.SetSession(&sess1)

	if err := serverSigner1.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server1 lagrange failed: %v", err)
	}
	logOK(t, "Session 1 server signer initialized and Lagrange coefficient computed")

	ps1Sess1 := initParticipantSigner(t, "P1-S1", p1, P, ids, &sess1)
	ps3Sess1 := initParticipantSigner(t, "P3-S1", p3, P, ids, &sess1)
	ps4Sess1 := initParticipantSigner(t, "P4-S1", p4, P, ids, &sess1)

	logOK(t, "Session 1 participant signers initialized")

	// Session 1 participants and server generate nonces and compute
	// aggregate nonce R.

	logSection(t, "4. Session 1 nonce generation and aggregate nonce computation")

	nonceServer1 := makeServerNonce(t, serverSigner1)
	logOK(t, "Session 1 server nonce generated")

	nonceP1S1 := makeParticipantNonce(t, ps1Sess1)
	logOK(t, "Session 1 P1 nonce generated")

	nonceP3S1 := makeParticipantNonce(t, ps3Sess1)
	logOK(t, "Session 1 P3 nonce generated")

	nonceP4S1 := makeParticipantNonce(t, ps4Sess1)
	logOK(t, "Session 1 P4 nonce generated")

	allM2Sess1 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer1),
		makeMaterial2(t, nonceP1S1),
		makeMaterial2(t, nonceP3S1),
		makeMaterial2(t, nonceP4S1),
	}
	logOK(t, "Session 1 collected all public nonce openings: server + P1 + P3 + P4")

	if err := serverSigner1.SetR(allM2Sess1); err != nil {
		t.Fatalf("server1 SetR failed: %v", err)
	}
	logOK(t, "Session 1 server computed aggregate nonce R")

	if err := ps1Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P1 session1 SetR failed: %v", err)
	}
	logOK(t, "Session 1 P1 computed aggregate nonce R")

	if err := ps3Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P3 session1 SetR failed: %v", err)
	}
	logOK(t, "Session 1 P3 computed aggregate nonce R")

	if err := ps4Sess1.SetR(allM2Sess1); err != nil {
		t.Fatalf("P4 session1 SetR failed: %v", err)
	}
	logOK(t, "Session 1 P4 computed aggregate nonce R")

	// Generate valid partial signatures for Session 1.

	logSection(t, "5. Session 1 partial signature generation")

	if err := serverSigner1.SetPartialSignature(msg); err != nil {
		t.Fatalf("server1 partial failed: %v", err)
	}
	logOK(t, "Session 1 server partial signature generated")

	if err := ps1Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P1 session1 partial failed: %v", err)
	}
	logOK(t, "Session 1 P1 partial signature generated")

	if err := ps3Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P3 session1 partial failed: %v", err)
	}
	logOK(t, "Session 1 P3 partial signature generated")

	if err := ps4Sess1.SetPartialSignature(msg); err != nil {
		t.Fatalf("P4 session1 partial failed: %v", err)
	}
	logOK(t, "Session 1 P4 partial signature generated")

	// Store one valid Session 1 partial signature for replay.
	replayedPartial := ps1Sess1.GetPartialSignature()

	logOK(t, "Stored P1 partial signature from session 1 as replay target")

	// Session 2 reuses the sam signing set but introduces a new session identifier.

	logSection(t, "6. Session 2 setup")

	var sess2 crypto.Session
	if err := sess2.SetID(testSessionID(0x09)); err != nil {
		t.Fatalf("failed session2 ID: %v", err)
	}
	logOK(t, fmt.Sprintf("Session 2 ID set: %x", sess2.GetID()))

	sess2.SetIndices(ids)
	sess2.SetIndexHash(ids)
	logOK(t, "Session 2 uses the same signing set but a different session ID")

	server2 := new(crypto.Server)
	server2.SetShare(dealer.GetServerShare())
	server2.SetParams(&aux)

	serverSigner2 := new(crypto.ServerSigner)
	serverSigner2.SetServer(*server2)
	serverSigner2.SetP(P)
	serverSigner2.SetIndices(ids)
	serverSigner2.SetSession(&sess2)

	if err := serverSigner2.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server2 lagrange failed: %v", err)
	}
	logOK(t, "Session 2 server signer initialized and Lagrange coefficient computed")

	ps1Sess2 := initParticipantSigner(t, "P1-S2", p1, P, ids, &sess2)
	ps3Sess2 := initParticipantSigner(t, "P3-S2", p3, P, ids, &sess2)
	ps4Sess2 := initParticipantSigner(t, "P4-S2", p4, P, ids, &sess2)

	logOK(t, "Session 2 participant signers initialized")

	// Session 2 signers generate new nonces and derive a new aggregate nonce R.

	logSection(t, "7. Session 2 nonce generation and aggregate nonce computation")

	nonceServer2 := makeServerNonce(t, serverSigner2)
	logOK(t, "Session 2 server nonce generated")

	nonceP1S2 := makeParticipantNonce(t, ps1Sess2)
	logOK(t, "Session 2 P1 nonce generated")

	nonceP3S2 := makeParticipantNonce(t, ps3Sess2)
	logOK(t, "Session 2 P3 nonce generated")

	nonceP4S2 := makeParticipantNonce(t, ps4Sess2)
	logOK(t, "Session 2 P4 nonce generated")

	allM2Sess2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer2),
		makeMaterial2(t, nonceP1S2),
		makeMaterial2(t, nonceP3S2),
		makeMaterial2(t, nonceP4S2),
	}
	logOK(t, "Session 2 collected all fresh public nonce openings: server + P1 + P3 + P4")

	if err := serverSigner2.SetR(allM2Sess2); err != nil {
		t.Fatalf("server2 SetR failed: %v", err)
	}
	logOK(t, "Session 2 server computed fresh aggregate nonce R")

	if err := ps1Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P1 session2 SetR failed: %v", err)
	}
	logOK(t, "Session 2 P1 computed fresh aggregate nonce R")

	if err := ps3Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P3 session2 SetR failed: %v", err)
	}
	logOK(t, "Session 2 P3 computed fresh aggregate nonce R")

	if err := ps4Sess2.SetR(allM2Sess2); err != nil {
		t.Fatalf("P4 session2 SetR failed: %v", err)
	}
	logOK(t, "Session 2 P4 computed fresh aggregate nonce R")

	// Generate valid partial signatures for Session 2.

	logSection(t, "8. Session 2 fresh partial signature generation")

	if err := serverSigner2.SetPartialSignature(msg); err != nil {
		t.Fatalf("server2 partial failed: %v", err)
	}
	logOK(t, "Session 2 server partial signature generated")

	if err := ps1Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P1 session2 partial failed: %v", err)
	}
	logOK(t, "Session 2 P1 fresh partial signature generated")

	if err := ps3Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P3 session2 partial failed: %v", err)
	}
	logOK(t, "Session 2 P3 fresh partial signature generated")

	if err := ps4Sess2.SetPartialSignature(msg); err != nil {
		t.Fatalf("P4 session2 partial failed: %v", err)
	}
	logOK(t, "Session 2 P4 fresh partial signature generated")

	// Replace one fresh partial signature with a valid partial signature
	// replayed from Session 1.

	logSection(t, "9. Replay attack attempt")

	attackedPartials := []crypto.PartialSignature{
		serverSigner2.GetPartialSignature(),
		replayedPartial, // P1 partial signature from Session 1 (replayed)
		ps3Sess2.GetPartialSignature(),
		ps4Sess2.GetPartialSignature(),
	}

	logOK(t, "Built attacked partial signature vector for session 2")
	logOK(t, "P1 fresh session 2 partial was replaced with P1 old session 1 partial")

	if err := serverSigner2.CombineSignature(attackedPartials); err != nil {
		t.Fatalf("combine failed unexpectedly: %v", err)
	}
	logOK(t, "CombineSignature accepted the structurally valid replay vector")

	sig := serverSigner2.GetSignature()
	logOK(t, "Final signature was built using one replayed partial signature")

	valid, err := crypto.VerifySignature(P, msg, sig, sess2)
	if err != nil {
		t.Fatalf("VerifySignature returned unexpected error: %v", err)
	}

	if valid {
		t.Fatalf("replayed partial from session1 produced a valid signature in session2")
	}

	logOK(t, "Final verification rejected the signature containing the replayed partial")
	logOK(t, "Replay attack across sessions correctly failed")
}

// Test 5: TestDuplicateParticipantIDsRejected verifies that a duplicate participant
// ID in the signing set is detected and rejected, preventing malformed threshold
// configurations from entering the protocol.
func TestDuplicateParticipantIDsRejected(t *testing.T) {
	logSection(t, "Security Test: Duplicate Participant IDs in Signing Set")

	n := 5
	k := 3

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed params: %v", err)
	}
	logOK(t, fmt.Sprintf("Threshold parameters set: n = %d, k = %d", n, k))

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed secret generation: %v", err)
	}
	logOK(t, "Dealer secret generated")

	friends := []string{"A", "B", "C", "D", "E"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed friends setup: %v", err)
	}
	logOK(t, fmt.Sprintf("Participants registered by dealer: %v", friends))

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed commitment/share generation: %v", err)
	}
	logOK(t, "Dealer generated valid commitments and shares")

	secret := dealer.GetSecret()

	var P crypto.Point
	P.ScalarBaseMult(&secret)

	logOK(t, "Public key P = secret * G computed")

	// Define invalid signing set containing duplicate participant IDs.

	logSection(t, "2. Invalid duplicate-ID signing set")

	// Participant 1 appears two times in ids.
	ids := []crypto.ParticipantID{1, 1, 3}

	logOK(t, fmt.Sprintf("Injected malicious signing set with duplicate IDs: %v", ids))

	// Session reject invalid signing set during index validation.

	logSection(t, "3. Session initialization")

	var sess crypto.Session

	if err := sess.SetID(testSessionID(0xAA)); err != nil {
		t.Fatalf("failed session ID: %v", err)
	}

	errSession := sess.SetIndices(ids)
	if errSession == nil {
		t.Fatalf("session.SetIndices accepted duplicate participant IDs")
	}
	logOK(t, fmt.Sprintf("Session correctly rejected duplicate IDs with error: %v", errSession))

	sess.SetIndexHash(ids)

	// Server validates and rejects duplicate IDs.
	logSection(t, "4. Server signer validation")

	server := new(crypto.Server)
	server.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server.SetParams(&aux)

	ss := new(crypto.ServerSigner)
	ss.SetServer(*server)
	ss.SetP(P)

	errServer := ss.SetIndices(ids)
	if errServer == nil {
		t.Fatalf("serverSigner.SetIndices accepted duplicate participant IDs")
	}
	logOK(t, fmt.Sprintf("ServerSigner correctly rejected duplicate IDs with error: %v", errServer))

	ss.SetSession(&sess)

	logOK(t, "Duplicate participant IDs are rejected at input validation stage")
}

// Test 6: TestKParticipantsWithoutServerFails verifies that a threshold signing
// attempt fails when only k participants contribute without the server.
func TestKParticipantsWithoutServerFails(t *testing.T) {
	logSection(t, "Security Test: k Participants WITHOUT Server (Must Fail)")

	n := 5
	k := 3

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	friends := []string{"A", "B", "C", "D", "E"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate shares: %v", err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	logOK(t, "Dealer initialized and public key computed")

	// Define the signing set.

	logSection(t, "2. Selecting k participants (NO server)")

	ids := []crypto.ParticipantID{1, 2, 3}

	logOK(t, "Signing set contains only participants")

	var sess crypto.Session
	if err := sess.SetID(testSessionID(0xAA)); err != nil {
		t.Fatalf("failed session ID: %v", err)
	}

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	logOK(t, "Session initialized without server node")

	// Initialize server signer but it will not be used in nonce or signature phase.

	logSection(t, "3. Server intentionally excluded from signing protocol")

	server := new(crypto.Server)
	server.SetShare(dealer.GetServerShare())
	aux := dealer.GetTsParameters()
	server.SetParams(&aux)

	ss := new(crypto.ServerSigner)
	ss.SetServer(*server)
	ss.SetP(P)
	ss.SetIndices(ids)
	ss.SetSession(&sess)

	if err := ss.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("lagrange failed: %v", err)
	}

	logOK(t, "Server signer exists but will not contribute")

	// Initialize participants.

	logSection(t, "4. Participant setup")

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p2 := checkShareConsistency(t, "P2", 2, 1, dealer)
	p3 := checkShareConsistency(t, "P3", 3, 2, dealer)

	ps1 := initParticipantSigner(t, "P1", p1, P, ids, &sess)
	ps2 := initParticipantSigner(t, "P2", p2, P, ids, &sess)
	ps3 := initParticipantSigner(t, "P3", p3, P, ids, &sess)

	logSection(t, "5. Nonce generation without server")

	nonce1 := makeParticipantNonce(t, ps1)
	nonce2 := makeParticipantNonce(t, ps2)
	nonce3 := makeParticipantNonce(t, ps3)

	allM2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonce1),
		makeMaterial2(t, nonce2),
		makeMaterial2(t, nonce3),
	}

	if err := ps1.SetR(allM2); err != nil {
		t.Fatalf("ps1 SetR failed: %v", err)
	}
	if err := ps2.SetR(allM2); err != nil {
		t.Fatalf("ps2 SetR failed: %v", err)
	}
	if err := ps3.SetR(allM2); err != nil {
		t.Fatalf("ps3 SetR failed: %v", err)
	}

	logOK(t, "Aggregate nonce derived without server contribution")

	// Participants generate partial signatures normally

	logSection(t, "6. Partial signatures without server")

	msg := []byte("test message")

	if err := ps1.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps1 failed: %v", err)
	}
	if err := ps2.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps2 failed: %v", err)
	}
	if err := ps3.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps3 failed: %v", err)
	}

	partials := []crypto.PartialSignature{
		ps1.GetPartialSignature(),
		ps2.GetPartialSignature(),
		ps3.GetPartialSignature(),
	}

	logOK(t, "Collected k partial signatures without server")

	// Attempt to combine partial signatures.

	logSection(t, "7. CombineSignature: expected to fail")

	err := ss.CombineSignature(partials)

	if err == nil {
		sig := ss.GetSignature()

		valid, vErr := crypto.VerifySignature(P, msg, sig, sess)
		if vErr != nil {
			t.Fatalf("verify error: %v", vErr)
		}

		if valid {
			t.Fatalf("signature valid without server")
		}
	}

	logOK(t, "Signing attempt rejected due to missing server contribution")
}

// Test 7: TestKParticipantsWithoutServerFails verifies that a threshold signing
// attempt fails when server and only k-1 participants contribute.
func TestServerWithKMinus1ParticipantsFails(t *testing.T) {
	logSection(t, "Security Test: Server + (k-1) Participants must fail")

	n := 5
	k := 3

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed params: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed secret: %v", err)
	}

	friends := []string{"A", "B", "C", "D", "E"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed shares: %v", err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	logOK(t, "Dealer initialized and public key computed")

	// Define signing set with k-1 participant and initialize session.

	logSection(t, "2. Selecting k-1 participants")

	ids := []crypto.ParticipantID{1, 2}

	var sess crypto.Session
	if err := sess.SetID(testSessionID(0xDE)); err != nil {
		t.Fatalf("failed session ID: %v", err)
	}

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	logOK(t, "Session initialized with insufficient participant set")

	// Initialize Server signer.

	logSection(t, "3. Server setup (included)")

	server := new(crypto.Server)
	server.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	server.SetParams(&aux)

	ss := new(crypto.ServerSigner)
	ss.SetServer(*server)
	ss.SetP(P)
	ss.SetIndices(ids)
	ss.SetSession(&sess)

	if err := ss.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("server lagrange failed: %v", err)
	}

	logOK(t, "Server signer initialized")

	// Initialize k-1 participants.

	logSection(t, "4. Participant setup (k-1 only)")

	p1 := checkShareConsistency(t, "P1", 1, 0, dealer)
	p2 := checkShareConsistency(t, "P2", 2, 1, dealer)

	ps1 := initParticipantSigner(t, "P1", p1, P, ids, &sess)
	ps2 := initParticipantSigner(t, "P2", p2, P, ids, &sess)

	logSection(t, "5. Nonce generation")

	nonceServer := makeServerNonce(t, ss)
	nonce1 := makeParticipantNonce(t, ps1)
	nonce2 := makeParticipantNonce(t, ps2)

	allM2 := []crypto.MaterialToSend2{
		makeMaterial2(t, nonceServer),
		makeMaterial2(t, nonce1),
		makeMaterial2(t, nonce2),
	}

	if err := ss.SetR(allM2); err != nil {
		t.Fatalf("SetR failed: %v", err)
	}
	if err := ps1.SetR(allM2); err != nil {
		t.Fatalf("ps1 SetR failed: %v", err)
	}
	if err := ps2.SetR(allM2); err != nil {
		t.Fatalf("ps2 SetR failed: %v", err)
	}

	logOK(t, "Aggregate nonce derived with insufficient participants")

	// Generate partial signatures of server and k-1 participants.

	logSection(t, "6. Partial signatures")

	msg := []byte("test message k-1")

	if err := ss.SetPartialSignature(msg); err != nil {
		t.Fatalf("server partial failed: %v", err)
	}
	if err := ps1.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps1 partial failed: %v", err)
	}
	if err := ps2.SetPartialSignature(msg); err != nil {
		t.Fatalf("ps2 partial failed: %v", err)
	}

	partials := []crypto.PartialSignature{
		ss.GetPartialSignature(),
		ps1.GetPartialSignature(),
		ps2.GetPartialSignature(),
	}

	// Attempt to combine partial signatures.

	logSection(t, "7. Combine + final verification")

	err := ss.CombineSignature(partials)

	if err != nil {
		logOK(t, "CombineSignature correctly rejected insufficient threshold set")
		return
	}

	sig := ss.GetSignature()

	valid, vErr := crypto.VerifySignature(P, msg, sig, sess)
	if vErr != nil {
		t.Fatalf("verify error: %v", vErr)
	}

	if valid {
		t.Fatalf("signature valid with only k-1 participants + server")
	}

	logOK(t, "Signature correctly invalid with insufficient threshold")
}

// Test 8: TestWrongParticipantIndexShareMismatch verifies that a participant cannot
// use a share not intended for its assigned ID.
func TestWrongParticipantIndexShareMismatch(t *testing.T) {
	logSection(t, "Security Test: Wrong Participant Index / Share Mismatch")

	n := 5
	k := 3

	// Dealer generates the secret, distributes shares, and publishes
	// commitment for verifiable secret sharing.

	logSection(t, "1. Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed params: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed secret: %v", err)
	}

	if err := dealer.SetFriends([]string{"A", "B", "C", "D", "E"}); err != nil {
		t.Fatalf("failed friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed shares: %v", err)
	}

	logOK(t, "Dealer initialized and shares generated")

	// Extract a valid share (P1).

	logSection(t, "2. Extract valid share")

	validShare := dealer.GetParticipantShares(0)

	logOK(t, "Valid share of P1 extracted")

	// Inject mismatch between participant ID and share.

	logSection(t, "3. Inject mismatch (ID vs share)")

	p := new(crypto.Participant)

	// Set ID = 3.

	if err := p.SetID(3); err != nil {
		t.Fatalf("failed to set ID: %v", err)
	}

	if err := p.SetName("P3"); err != nil {
		t.Fatalf("failed to set participant name: %v", err)
	}

	// Assign mismatched share.

	if err := p.SetShare(validShare); err != nil {
		t.Fatalf("failed to set mismatched share: %v", err)
	}

	logOK(t, "P3 uses P1's share (mismatch injected)")

	// Verify consistency of the share.

	logSection(t, "4. VSS consistency check")

	ok, err := p.VerifyConsistency(*dealer.GetComm())
	if err != nil {
		t.Fatalf("VerifyConsistency error: %v", err)
	}

	if ok {
		t.Fatalf("mismatched share accepted (ID/share mismatch)")
	}

	logOK(t, "Mismatch correctly rejected by VSS verification")
}
