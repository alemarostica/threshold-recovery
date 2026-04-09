package keyexchange

import (
	"bytes"
	"errors"
)

// Avvio da parte di A (M1)

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
		[]byte("M1"),
		[]byte(myID),
		[]byte(peerID),
		state.MyPub,
		state.NonceA,
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

// Gestione M1 lato B → risposta M2

func HandleM1(
	msg Message,
	myID string,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
) (*SessionState, error) {

	state := &SessionState{
		MyID:   myID,
		PeerID: msg.From,
	}

	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return nil, err
	}

	payload := bytes.Join([][]byte{
		[]byte("M1"),
		[]byte(msg.From),
		[]byte(myID),
		msg.Data["X"],
		msg.Data["nonceA"],
	}, nil)

	if !crypto.Verify(peerPubSig, payload, msg.Data["sig"]) {
		return nil, errors.New("invalid signauture")
	}

	state.PeerPub = msg.Data["X"]
	state.NonceA = msg.Data["nonceA"]

	state.MyPriv, state.MyPub, err = crypto.GenerateEphemeralDH()
	if err != nil {
		return nil, err
	}

	state.NonceB = crypto.RandomNonce()

	payload2 := bytes.Join([][]byte{
		[]byte("M2"),
		[]byte(myID),
		[]byte(msg.From),
		state.MyPub,
		state.PeerPub,
		state.NonceA,
		state.NonceB,
	}, nil)

	sig, err := crypto.Sign(mySigPriv, payload2)
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
			"sig":    sig,
		},
	}

	return state, sender.Send(reply)
}

// Gestione M2 lato A → derivazione chiave + M3

func HandleM2AsInitiator(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
	plaintext []byte,
) error {

	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return err
	}

	payload := bytes.Join([][]byte{
		[]byte("M2"),
		[]byte(msg.From),
		[]byte(state.MyID),
		msg.Data["Y"],
		state.MyPub,
		msg.Data["nonceA"],
		msg.Data["nonceB"],
	}, nil)

	if !crypto.Verify(peerPubSig, payload, msg.Data["sig"]) {
		return errors.New("invalid signature")
	}

	state.PeerPub = msg.Data["Y"]
	state.NonceB = msg.Data["nonceB"]

	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return err
	}

	tr := bytes.Join([][]byte{
		[]byte(state.MyID),
		[]byte(state.PeerID),
		state.MyPub,
		state.PeerPub,
		state.NonceA,
		state.NonceB,
	}, nil)

	state.Transcript = crypto.Hash(tr)
	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return err
	}

	ct, nonce, err := crypto.Encrypt(state.SharedKey, plaintext, state.Transcript)
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
			"nonce": nonce,
		},
	}

	return sender.Send(msg3)
}

// Gestione M3 lato B (decifrazione)

func HandleM3(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
) ([]byte, error) {

	ct := msg.Data["ct"]
	nonce := msg.Data["nonce"]

	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return nil, err
	}

	tr := bytes.Join([][]byte{
		[]byte(state.PeerID),
		[]byte(state.MyID),
		state.PeerPub,
		state.MyPub,
		state.NonceA,
		state.NonceB,
	}, nil)

	state.Transcript = crypto.Hash(tr)
	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return nil, err
	}

	return crypto.Decrypt(state.SharedKey, nonce, ct, state.Transcript)
}
