package keyexchange

import (
	"bytes"
	"errors"
)

// This file implements the three-round Authenticated Key Exchange (AKE) protocol.
// The protocol proceeds as follows:
// 1. M1: The initiator generates an ephemeral Diffie-Hellman key pair,
//        signs its first message, and sends its public ephemeral key with a fresh nonce.
// 2. M2: The responder verifies M1, generates its own ephemeral keypair,
//        signs the response, and binds both parties' contributions.
// 3. M3: The initiator verifies M2, derives the shared session key,
//        encrypts the share, and sends it to the responder.
// 4. The responder reconstructs the session key, verifies M3 integrity and authenticity
// through AEAD decryption, and decrypts the share.

// Mutual authentication is achieved through digital signatures, while
// confidentiality is provided by ephemeral Diffie-Hellman combined with
// transcript-bound key derivation and AEAD encryption.

// GetBytes extracts a required byte field from a message.
func getBytes(data map[string][]byte, key string) ([]byte, error) {
	val, ok := data[key]
	if !ok || len(val) == 0 {
		return nil, errors.New("missing or empty field: " + key)
	}
	return val, nil
}

// StartAsInitiator constructs and sends M1, the first protocol message.
// The initiator samples fresh ephemeral Diffie-Hellman material,
// generates a nonce, signs the payload, and sends the
// authenticated first message to the responder.
func StartAsInitiator(
	myID, peerID string,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
) (*SessionState, error) {

	// Initialize local session state.
	state := &SessionState{
		MyID:   myID,
		PeerID: peerID,
	}

	// Generate ephemeral Diffie–Hellman keypair.
	var err error
	state.MyPriv, state.MyPub, err = crypto.GenerateEphemeralDH()
	if err != nil {
		return nil, err
	}

	// Sample a fresh nonce and retrieve the current epoch.
	state.NonceA = crypto.RandomNonce()
	epoch := dir.GetEpoch()

	// Construct M1 payload as:
	// message type || sender ID || receiver ID || ephemeral public key || nonceA
	payload := bytes.Join([][]byte{
		[]byte("M1"), []byte(myID), []byte(peerID), state.MyPub, state.NonceA,
	}, nil)

	// Sign M1 payload with the initiator's private key.
	sig, err := crypto.Sign(mySigPriv, payload)
	if err != nil {
		return nil, err
	}

	// Assemble the authenticated M1 message.
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

// HandleM1 verifies M1 and sends M2 as the responder.
// The responder authenticates the initiator through signature verification,
// stores the initiator's ephemeral contribution, generates fresh session material,
// and returns an authenticated response message.
func HandleM1(
	msg Message,
	myID string,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	mySigPriv []byte,
) (*SessionState, error) {

	// Recover the initiator's public verification key.
	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return nil, err
	}

	// Extract authenticated M1 fields.
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

	// Reconstruct signed M1 payload as:
	// message type || sender ID || receiver ID || initiator public key || nonceA
	payload := bytes.Join([][]byte{
		[]byte("M1"), []byte(msg.From), []byte(myID), x, nonceA,
	}, nil)

	// Verify initiator authenticity.
	if !crypto.Verify(peerPubSig, payload, sigM1) {
		return nil, errors.New("invalid M1 signature")
	}

	// Initialize responder session state.
	state := &SessionState{
		MyID:    myID,
		PeerID:  msg.From,
		PeerPub: x,
		NonceA:  nonceA,
	}

	// Generate responder ephemeral Diffie-Hellman keypair and fresh nonce.
	state.MyPriv, state.MyPub, err = crypto.GenerateEphemeralDH()
	if err != nil {
		return nil, err
	}
	state.NonceB = crypto.RandomNonce()

	// Construct M2 payload as:
	// message type || responder ID || initiator ID || responder public key || initiator public key || nonceA || nonceB
	payload2 := bytes.Join([][]byte{
		[]byte("M2"), []byte(myID), []byte(msg.From), state.MyPub, state.PeerPub, state.NonceA, state.NonceB,
	}, nil)

	// Sign M2 payload with the responder's private key.
	sigM2, err := crypto.Sign(mySigPriv, payload2)
	if err != nil {
		return nil, err
	}

	// Assemble the authenticated M2 message.
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

// HandleM2AsInitiator verifies M2, derives the session key, and sends M3.
// The initiator authenticates the responder, checks nonce consistency,
// derives the transcript-bound session key,
// and encrypts the share.
func HandleM2AsInitiator(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
	dir Directory,
	sender MessageSender,
	plaintext []byte,
) error {

	// Recover the responder's public verification key.
	peerPubSig, err := dir.GetPublicKey(msg.From)
	if err != nil {
		return err
	}

	// Extract authenticated M2 fields.
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

	// Verify nonceA consistency.
	if !bytes.Equal(nonceA_rec, state.NonceA) {
		return errors.New("security alert: nonceA mismatch! Possible replay attack")
	}

	// Reconstruct M2 payload as:
	// message type || responder ID || initiator ID || responder public key || initiator public key || nonceA || nonceB
	payload := bytes.Join([][]byte{
		[]byte("M2"), []byte(msg.From), []byte(state.MyID), y, state.MyPub, nonceA_rec, nonceB,
	}, nil)

	// Verify responder authenticity.
	if !crypto.Verify(peerPubSig, payload, sigM2) {
		return errors.New("invalid M2 signature")
	}

	// Store responder session material in local session state.
	state.PeerPub = y
	state.NonceB = nonceB

	// Compute ephemeral Diffie–Hellman shared secret.
	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return err
	}

	// Construct the protocol transcript as:
	// initiator ID || responder ID || initiator public key || responder public key || nonceA || nonceB
	tr := bytes.Join([][]byte{
		[]byte(state.MyID), []byte(state.PeerID), state.MyPub, state.PeerPub, state.NonceA, state.NonceB,
	}, nil)
	state.Transcript = crypto.Hash(tr)

	// Derive the final session key from shared secret and transcript.
	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return err
	}

	// Encrypt the share using the established session key.
	ct, nonceAEAD, err := crypto.Encrypt(state.SharedKey, plaintext, state.Transcript)
	if err != nil {
		return err
	}

	// Assemble M3 containing the encrypted share.
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

// HandleM3 derives the responder session key and decrypts the share.
// The responder reconstructs the transcript and derives the session key.
func HandleM3(
	state *SessionState,
	msg Message,
	crypto CryptoProvider,
) ([]byte, error) {

	// Extract encrypted payload and nonce from M3.
	ct, err := getBytes(msg.Data, "ct")
	if err != nil {
		return nil, err
	}
	nonceAEAD, err := getBytes(msg.Data, "nonce")
	if err != nil {
		return nil, err
	}

	// Recompute ephemeral Diffie–Hellman shared secret.
	shared, err := crypto.ComputeSharedSecret(state.MyPriv, state.PeerPub)
	if err != nil {
		return nil, err
	}

	// Reconstruct the protocol transcript using the same ordering of the initiator:
	// initiator ID || responder ID || initiator public key || responder public key || nonceA || nonceB
	tr := bytes.Join([][]byte{
		[]byte(state.PeerID), []byte(state.MyID), state.PeerPub, state.MyPub, state.NonceA, state.NonceB,
	}, nil)
	state.Transcript = crypto.Hash(tr)

	// Derive the final session key from shared secret and transcript.
	state.SharedKey, err = crypto.DeriveKey(shared, state.Transcript)
	if err != nil {
		return nil, err
	}

	// Decrypt the share using the session key.
	return crypto.Decrypt(state.SharedKey, nonceAEAD, ct, state.Transcript)
}
