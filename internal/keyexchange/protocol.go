package keyexchange

import (
	"bytes"
	"errors"
)

// Helper interno per estrarre i dati in sicurezza
func getBytes(data map[string][]byte, key string) ([]byte, error) {
	val, ok := data[key]
	if !ok || len(val) == 0 {
		return nil, errors.New("missing or empty field: " + key)
	}
	return val, nil
}

// ---------------- M1: Avvio da parte di A ----------------

func StartAsInitiator(
	myID, peerID string,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
) (*SessionState, error) {

	state := &SessionState{
		MyID:   myID,
		PeerID: peerID,
	}

	var err error
	state.MyPriv, state.MyPub, err = crypto.GenerateEphemeralDH()
	if err != nil {
		return nil, err
	}

	state.NonceA = crypto.RandomNonce()
	epoch := dir.GetEpoch()

	payload := bytes.Join([][]byte{
		[]byte("M1"), []byte(myID), []byte(peerID), state.MyPub, state.NonceA,
	}, nil)

	sig, err := crypto.Sign(mySigPriv, payload)
	if err != nil {
		return nil, err
	}

	msg := Message{
		Type:  M1,
		From:  myID,
		To:    peerID,
		Epoch: epoch,
		Data: map[string][]byte{
			"X":      state.MyPub,
			"nonceA": state.NonceA,
			"sig":    sig,
		},
	}

	return state, sender.Send(msg)
}

// ---------------- M2: Gestione M1 lato B e Risposta ----------------

func HandleM1(
	msg Message,
	myID string,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
) (*SessionState, error) {

	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return nil, err
	}

	x, err := getBytes(msg.Data, "X")
	if err != nil {
		return nil, err
	}
	nonceA, err := getBytes(msg.Data, "nonceA")
	if err != nil {
		return nil, err
	}
	sigM1, err := getBytes(msg.Data, "sig")
	if err != nil {
		return nil, err
	}

	payload := bytes.Join([][]byte{
		[]byte("M1"), []byte(msg.From), []byte(myID), x, nonceA,
	}, nil)

	if !crypto.Verify(peerPubSig, payload, sigM1) {
		return nil, errors.New("invalid M1 signature")
	}

	state := &SessionState{
		MyID:    myID,
		PeerID:  msg.From,
		PeerPub: x,
		NonceA:  nonceA,
	}

	state.MyPriv, state.MyPub, err = crypto.GenerateEphemeralDH()
	if err != nil {
		return nil, err
	}
	state.NonceB = crypto.RandomNonce()

	payload2 := bytes.Join([][]byte{
		[]byte("M2"), []byte(myID), []byte(msg.From), state.MyPub, state.PeerPub, state.NonceA, state.NonceB,
	}, nil)

	sigM2, err := crypto.Sign(mySigPriv, payload2)
	if err != nil {
		return nil, err
	}

	reply := Message{
		Type:  M2,
		From:  myID,
		To:    msg.From,
		Epoch: msg.Epoch,
		Data: map[string][]byte{
			"Y":      state.MyPub,
			"nonceA": state.NonceA,
			"nonceB": state.NonceB,
			"sig":    sigM2,
		},
	}

	return state, sender.Send(reply)
}

// ---------------- M3: Gestione M2 lato A e Derivazione Chiave ----------------

func HandleM2AsInitiator(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	plaintext []byte, // La tua Share
) error {

	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return err
	}

	y, err := getBytes(msg.Data, "Y")
	if err != nil {
		return err
	}
	nonceA_rec, err := getBytes(msg.Data, "nonceA")
	if err != nil {
		return err
	}
	nonceB, err := getBytes(msg.Data, "nonceB")
	if err != nil {
		return err
	}
	sigM2, err := getBytes(msg.Data, "sig")
	if err != nil {
		return err
	}

	// CRITICO: Controllo Anti-Replay
	if !bytes.Equal(nonceA_rec, state.NonceA) {
		return errors.New("security alert: nonceA mismatch! Possible replay attack")
	}

	payload := bytes.Join([][]byte{
		[]byte("M2"), []byte(msg.From), []byte(state.MyID), y, state.MyPub, nonceA_rec, nonceB,
	}, nil)

	if !crypto.Verify(peerPubSig, payload, sigM2) {
		return errors.New("invalid M2 signature")
	}

	state.PeerPub = y
	state.NonceB = nonceB

	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return err
	}

	tr := bytes.Join([][]byte{
		[]byte(state.MyID), []byte(state.PeerID), state.MyPub, state.PeerPub, state.NonceA, state.NonceB,
	}, nil)
	state.Transcript = crypto.Hash(tr)

	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return err
	}

	ct, nonceAEAD, err := crypto.Encrypt(state.SharedKey, plaintext, state.Transcript)
	if err != nil {
		return err
	}

	msg3 := Message{
		Type:  M3,
		From:  state.MyID,
		To:    state.PeerID,
		Epoch: msg.Epoch,
		Data: map[string][]byte{
			"ct":    ct,
			"nonce": nonceAEAD,
		},
	}

	return sender.Send(msg3)
}

// ---------------- Gestione M3 lato B (Decifrazione) ----------------

func HandleM3(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
) ([]byte, error) {

	ct, err := getBytes(msg.Data, "ct")
	if err != nil {
		return nil, err
	}
	nonceAEAD, err := getBytes(msg.Data, "nonce")
	if err != nil {
		return nil, err
	}

	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return nil, err
	}

	// Stesso ordine esatto di A per il transcript
	tr := bytes.Join([][]byte{
		[]byte(state.PeerID), []byte(state.MyID), state.PeerPub, state.MyPub, state.NonceA, state.NonceB,
	}, nil)
	state.Transcript = crypto.Hash(tr)

	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return nil, err
	}

	return crypto.Decrypt(state.SharedKey, nonceAEAD, ct, state.Transcript)
}
