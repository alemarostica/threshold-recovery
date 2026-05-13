package test

import (
	"testing"

	"threshold-recovery/internal/crypto"
)

func logSection(t *testing.T, title string) {
	t.Helper()
	t.Logf("\n========== %s ==========", title)
}

func logOK(t *testing.T, msg string) {
	t.Helper()
	t.Logf("[OK] %s", msg)
}

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

	p.SetName(name)
	p.SetShare(dealer.GetParticipantShares(shareIndex))

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
	ps.SetIndices(ids)
	ps.SetSession(sess)

	if err := ps.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set %s Lagrange coefficient: %v", name, err)
	}

	logOK(t, name+" signer initialized")

	return ps
}

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

func TestLSSSFullSigningFlow(t *testing.T) {
	logSection(t, "LSSS / VSS + Threshold Signing Test")

	n := 5
	k := 3

	// -------------------------------------------------------------------------
	// Dealer setup
	// -------------------------------------------------------------------------

	logSection(t, "Dealer setup")

	dealer := new(crypto.Dealer)

	if err := dealer.SetTsParameters(n, k); err != nil {
		t.Fatalf("failed to set threshold parameters: %v", err)
	}

	if err := dealer.SetSecret(); err != nil {
		t.Fatalf("failed to generate dealer secret: %v", err)
	}

	secret := dealer.GetSecret()
	P := *new(crypto.Point).ScalarBaseMult(&secret)

	friends := []string{"Gianni", "Pino", "Gino", "Cornelio", "Beppe"}
	if err := dealer.SetFriends(friends); err != nil {
		t.Fatalf("failed to set friends: %v", err)
	}

	if err := dealer.SetCommAndShares(); err != nil {
		t.Fatalf("failed to generate commitments and shares: %v", err)
	}

	logOK(t, "Dealer generated wallet secret, commitments, and shares")

	// -------------------------------------------------------------------------
	// Share consistency verification
	// -------------------------------------------------------------------------

	logSection(t, "Share consistency verification")

	Gianni := checkShareConsistency(t, "Gianni", 3, 2, dealer)
	Pino := checkShareConsistency(t, "Pino", 1, 0, dealer)
	Gino := checkShareConsistency(t, "Gino", 2, 1, dealer)
	Cornelio := checkShareConsistency(t, "Cornelio", 4, 3, dealer)
	Beppe := checkShareConsistency(t, "Beppe", 5, 4, dealer)

	_ = Gino
	_ = Beppe

	// -------------------------------------------------------------------------
	// Server and signing session setup
	// -------------------------------------------------------------------------

	logSection(t, "Server and signing session setup")

	S := new(crypto.Server)
	ServerS := new(crypto.ServerSigner)

	ids := []crypto.ParticipantID{1, 3, 4}

	ServerS.SetP(P)
	ServerS.SetIndices(ids)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set server Lagrange coefficient: %v", err)
	}

	S.SetShare(dealer.GetServerShare())

	aux := dealer.GetTsParameters()
	S.SetParams(&aux)

	ServerS.SetServer(*S)

	var sess crypto.Session
	id := []byte{1, 0, 0}
	if err := sess.SetID(id); err != nil {
		t.Fatalf("failed to set session ID: %v", err)
	}

	sess.SetIndices(ids)
	sess.SetIndexHash(ids)

	ServerS.SetSession(&sess)

	if err := ServerS.SetLagrangeCoefficient(); err != nil {
		t.Fatalf("failed to set server Lagrange coefficient after session setup: %v", err)
	}

	logOK(t, "Server signer initialized")
	logOK(t, "Signing session initialized")

	PinoS := initParticipantSigner(t, "Pino", Pino, P, ids, &sess)
	GianniS := initParticipantSigner(t, "Gianni", Gianni, P, ids, &sess)
	CornelioS := initParticipantSigner(t, "Cornelio", Cornelio, P, ids, &sess)

	// -------------------------------------------------------------------------
	// Nonce commitment phase
	// -------------------------------------------------------------------------

	logSection(t, "Nonce commitment phase")

	nonceServer := makeServerNonce(t, ServerS)
	noncePino := makeParticipantNonce(t, PinoS)
	nonceGianni := makeParticipantNonce(t, GianniS)
	nonceCornelio := makeParticipantNonce(t, CornelioS)

	logOK(t, "Private nonces and public nonce points generated")

	m1Server := makeMaterial1(t, nonceServer)
	m1Pino := makeMaterial1(t, noncePino)
	m1Gianni := makeMaterial1(t, nonceGianni)
	m1Cornelio := makeMaterial1(t, nonceCornelio)

	ServerS.SetMaterialToSend1(m1Server)
	PinoS.SetMaterialToSend1(m1Pino)
	GianniS.SetMaterialToSend1(m1Gianni)
	CornelioS.SetMaterialToSend1(m1Cornelio)

	logOK(t, "Nonce commitments generated")

	m2Server := makeMaterial2(t, nonceServer)
	m2Pino := makeMaterial2(t, noncePino)
	m2Gianni := makeMaterial2(t, nonceGianni)
	m2Cornelio := makeMaterial2(t, nonceCornelio)

	ServerS.SetMaterialToSend2(m2Server)
	PinoS.SetMaterialToSend2(m2Pino)
	GianniS.SetMaterialToSend2(m2Gianni)
	CornelioS.SetMaterialToSend2(m2Cornelio)

	logOK(t, "Nonce openings generated")

	verifyNonceFromParticipant(t, ServerS, "Pino", PinoS)
	verifyNonceFromParticipant(t, ServerS, "Gianni", GianniS)
	verifyNonceFromParticipant(t, ServerS, "Cornelio", CornelioS)

	// -------------------------------------------------------------------------
	// Aggregate nonce computation
	// -------------------------------------------------------------------------

	logSection(t, "Aggregate nonce computation")

	allM2 := []crypto.MaterialToSend2{
		m2Server,
		m2Pino,
		m2Gianni,
		m2Cornelio,
	}

	if err := ServerS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for server: %v", err)
	}
	if err := PinoS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Pino: %v", err)
	}
	if err := GianniS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Gianni: %v", err)
	}
	if err := CornelioS.SetR(allM2); err != nil {
		t.Fatalf("failed to set aggregate R for Cornelio: %v", err)
	}

	logOK(t, "All signing parties computed the same aggregate nonce R")

	// -------------------------------------------------------------------------
	// Partial signature generation
	// -------------------------------------------------------------------------

	logSection(t, "Partial signature generation")

	msg := []byte("transaction made")

	if err := ServerS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute server partial signature: %v", err)
	}
	if err := PinoS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Pino partial signature: %v", err)
	}
	if err := GianniS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Gianni partial signature: %v", err)
	}
	if err := CornelioS.SetPartialSignature(msg); err != nil {
		t.Fatalf("failed to compute Cornelio partial signature: %v", err)
	}

	logOK(t, "Server partial signature generated")
	logOK(t, "Pino partial signature generated")
	logOK(t, "Gianni partial signature generated")
	logOK(t, "Cornelio partial signature generated")

	// -------------------------------------------------------------------------
	// Final signature combination
	// -------------------------------------------------------------------------

	logSection(t, "Final signature combination")

	zPino := PinoS.GetPartialSignature()
	zGianni := GianniS.GetPartialSignature()
	zCornelio := CornelioS.GetPartialSignature()

	partialsForServer := []crypto.PartialSignature{
		zPino,
		zGianni,
		zCornelio,
	}

	if err := ServerS.CombineSignature(partialsForServer); err != nil {
		t.Fatalf("failed to combine threshold signature: %v", err)
	}

	sig := ServerS.GetSignature()

	logOK(t, "Final threshold signature combined")

	// -------------------------------------------------------------------------
	// Reconstruction sanity check
	// -------------------------------------------------------------------------

	logSection(t, "Reconstruction sanity check")

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

	tmp.Multiply(&lambdaPino, &sharePino)
	rec.Add(&rec, &tmp)

	tmp.Multiply(&lambdaGianni, &shareGianni)
	rec.Add(&rec, &tmp)

	tmp.Multiply(&lambdaCornelio, &shareCornelio)
	rec.Add(&rec, &tmp)

	if rec.Equal(&secret) != 1 {
		t.Fatalf("reconstructed scalar does not match dealer secret")
	}

	logOK(t, "Reconstructed scalar matches dealer secret")

	var recP crypto.Point
	recP.ScalarBaseMult(&rec)

	var secretP crypto.Point
	secretP.ScalarBaseMult(&secret)

	if recP.Equal(&secretP) != 1 {
		t.Fatalf("reconstructed public key does not match dealer public key")
	}

	if P.Equal(&secretP) != 1 {
		t.Fatalf("dealer public key does not match secret-derived public key")
	}

	logOK(t, "Reconstructed public key matches dealer public key")

	// -------------------------------------------------------------------------
	// Final signature verification
	// -------------------------------------------------------------------------

	logSection(t, "Final signature verification")

	valid, err := crypto.VerifySignature(P, msg, sig, sess)
	if err != nil {
		t.Fatalf("signature verification returned error: %v", err)
	}

	if !valid {
		t.Fatalf("final threshold signature is NOT valid")
	}

	logOK(t, "Final threshold signature verified successfully")
}
