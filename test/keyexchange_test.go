package test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"threshold-recovery/internal/keyexchange"
)

// RealTestDir is a simple mock directory used only in tests.
//
// In the real protocol, identities are associated with long-term Ed25519
// public keys. Here we simulate this behaviour with a map from identity
// strings to Ed25519 public keys.
type RealTestDir struct {
	Keys map[string]ed25519.PublicKey
}

// GetPublicKey returns the public signing key associated with an identity.
func (d *RealTestDir) GetPublicKey(id string) (ed25519.PublicKey, error) {
	key, ok := d.Keys[id]
	if !ok {
		return nil, errors.New("unknown identity")
	}
	return key, nil
}

// GetEpoch returns a fixed epoch value for testing purposes.
func (d *RealTestDir) GetEpoch() uint64 {
	return 2026
}

// mockSender is a small helper used to simulate message delivery.
//
// Instead of sending messages over a real network, the test stores each
// outgoing message into a local variable.
type mockSender func(keyexchange.Message) error

func (m mockSender) Send(msg keyexchange.Message) error {
	return m(msg)
}

// newTestProvider returns the real cryptographic provider used by the protocol.
//
// This is important: the tests should not duplicate the cryptographic logic.
// They should test the actual DefaultProvider implementation used in the code.
func newTestProvider() *keyexchange.DefaultProvider {
	return keyexchange.NewDefaultProvider()
}

// TestCompleteProtocol performs a full simulation of the authenticated
// Diffie-Hellman key exchange between Alice and Bob.
//
// The test checks that:
//   - Alice sends M1;
//   - Bob verifies M1 and sends M2;
//   - Alice verifies M2 and sends an encrypted M3;
//   - Bob decrypts M3 correctly;
//   - the decrypted payload matches the original one.
func TestCompleteProtocol(t *testing.T) {
	logSection(t, "Start key exchange (Alice <-> Bob)")

	cryptoProvider := newTestProvider()

	// 1. Identity setup.
	//
	// Alice and Bob each have a long-term Ed25519 signing key pair.
	// The public keys are registered in the test directory.
	logSection(t, "Identity and directory setup")

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	logOK(t, "Identities generated and registered in directory")

	// 2. Network simulation.
	//
	// The protocol sends three messages:
	//   M1: Alice -> Bob
	//   M2: Bob   -> Alice
	//   M3: Alice -> Bob
	//
	// Instead of using a real network, each sender stores the message
	// into a local variable.
	var msgM1, msgM2, msgM3 keyexchange.Message

	senderToBob := mockSender(func(msg keyexchange.Message) error {
		msgM1 = msg
		return nil
	})

	senderToAlice := mockSender(func(msg keyexchange.Message) error {
		msgM2 = msg
		return nil
	})

	senderFinal := mockSender(func(msg keyexchange.Message) error {
		msgM3 = msg
		return nil
	})

	// 3. Alice starts the protocol and sends M1.
	logSection(t, "Alice initiates M1")

	stateA, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		senderToBob,
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	logOK(t, "Alice generated and sent M1")

	// 4. Bob receives M1, verifies Alice, and replies with M2.
	logSection(t, "Bob receives M1 and replies with M2")

	stateB, err := keyexchange.HandleM1(
		msgM1,
		"Bob",
		cryptoProvider,
		dir,
		senderToAlice,
		privB,
	)
	if err != nil {
		t.Fatalf("HandleM1 failed: %v", err)
	}

	logOK(t, "Bob verified Alice's identity and sent M2")

	// 5. Alice receives M2, verifies Bob, derives the session key,
	// encrypts the payload, and sends M3.
	logSection(t, "Alice receives M2 and sends M3")

	originalPayload := []byte("A generic secret message")

	err = keyexchange.HandleM2AsInitiator(
		stateA,
		msgM2,
		cryptoProvider,
		dir,
		senderFinal,
		originalPayload,
	)
	if err != nil {
		t.Fatalf("HandleM2AsInitiator failed: %v", err)
	}

	logOK(t, "Alice established the shared secret and encrypted M3")

	// 6. Bob receives M3 and decrypts the encrypted payload.
	logSection(t, "Bob receives M3 and decrypts it")

	decryptedPayload, err := keyexchange.HandleM3(stateB, msgM3, cryptoProvider)
	if err != nil {
		t.Fatalf("HandleM3 failed: %v", err)
	}

	// 7. Final correctness check.
	if !bytes.Equal(decryptedPayload, originalPayload) {
		t.Fatalf(
			"data inconsistency.\nExpected: %s\nGot:      %s",
			originalPayload,
			decryptedPayload,
		)
	}

	logOK(t, "Protocol completed successfully")
}

// TestInitiatorStateInitialization checks the state initialized by Alice
// during StartAsInitiator.
func TestInitiatorStateInitialization(t *testing.T) {
	logSection(t, "Unit Test: Initiator State")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
		},
	}

	dummySender := mockSender(func(m keyexchange.Message) error {
		return nil
	})

	state, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		dummySender,
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	if state == nil {
		t.Fatal("state is nil")
	}

	if state.MyID != "Alice" || state.PeerID != "Bob" {
		t.Errorf("wrong IDs in state: got %s -> %s", state.MyID, state.PeerID)
	}

	if len(state.MyPriv) == 0 {
		t.Error("ephemeral private key was not generated")
	}

	if len(state.MyPub) == 0 {
		t.Error("ephemeral public key was not generated")
	}

	if len(state.NonceA) == 0 {
		t.Error("NonceA was not generated")
	}

	logOK(t, "Initiator state correctly initialized with DH material and nonce")
}

// TestResponderStateInitialization checks the state initialized by Bob
// when handling Alice's M1.
func TestResponderStateInitialization(t *testing.T) {
	logSection(t, "Responder State from HandleM1")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	var msgM1 keyexchange.Message

	aliceSender := mockSender(func(m keyexchange.Message) error {
		msgM1 = m
		return nil
	})

	stateA, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		aliceSender,
		privA,
	)
	if err != nil {
		t.Fatalf("Alice failed to start: %v", err)
	}

	stateB, err := keyexchange.HandleM1(
		msgM1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error { return nil }),
		privB,
	)
	if err != nil {
		t.Fatalf("Bob failed to handle M1: %v", err)
	}

	if !bytes.Equal(stateB.NonceA, stateA.NonceA) {
		t.Error("Bob's NonceA does not match Alice's NonceA")
	}

	if !bytes.Equal(stateB.PeerPub, stateA.MyPub) {
		t.Error("Bob's PeerPub does not match Alice's MyPub")
	}

	if len(stateB.MyPriv) == 0 {
		t.Error("Bob's ephemeral private key is missing")
	}

	if len(stateB.MyPub) == 0 {
		t.Error("Bob's ephemeral public key is missing")
	}

	if len(stateB.NonceB) == 0 {
		t.Error("Bob's NonceB is missing")
	}

	logOK(t, "Bob's state is synchronized with Alice's initial state")
}

// TestHandleM1WrongRecipient verifies that Bob rejects an M1 message
// generated by Alice for Charles but delivered to Bob.
func TestHandleM1WrongRecipient(t *testing.T) {
	logSection(t, "M1 Wrong Recipient")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	pubC, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Charles signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice":   pubA,
			"Bob":     pubB,
			"Charles": pubC,
		},
	}

	var msgM1 keyexchange.Message

	aliceSender := mockSender(func(m keyexchange.Message) error {
		msgM1 = m
		return nil
	})

	_, err = keyexchange.StartAsInitiator(
		"Alice",
		"Charles",
		cryptoProvider,
		dir,
		aliceSender,
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	// The message was intended for Charles, but Bob receives it.
	// Bob must reject it because the recipient identity does not match.
	_, err = keyexchange.HandleM1(
		msgM1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error { return nil }),
		privB,
	)

	if err == nil {
		t.Error("Bob accepted a message intended for Charles")
	} else {
		logOK(t, "Bob correctly rejected M1 intended for Charles")
	}
}

// TestAliceRejectsCorruptedM2 verifies that Alice rejects M2 if Bob's
// signature has been modified.
func TestAliceRejectsCorruptedM2(t *testing.T) {
	logSection(t, "Alice verifies Bob's signature")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	var m1 keyexchange.Message

	stateA, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m1 = m
			return nil
		}),
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	var m2 keyexchange.Message

	_, err = keyexchange.HandleM1(
		m1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m2 = m
			return nil
		}),
		privB,
	)
	if err != nil {
		t.Fatalf("HandleM1 failed: %v", err)
	}

	// An attacker corrupts Bob's signature in M2.
	sig, ok := m2.Data["sig"]
	if !ok || len(sig) == 0 {
		t.Fatal("M2 sig field not found or empty")
	}

	sig[0] ^= 0xFF

	// Alice must reject the forged M2.
	err = keyexchange.HandleM2AsInitiator(
		stateA,
		m2,
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error { return nil }),
		[]byte("secret"),
	)

	if err == nil {
		t.Error("Alice accepted M2 with a corrupted signature")
	} else {
		logOK(t, "Alice correctly rejected the forged M2")
	}
}

// TestBobRejectsTamperedPayloadM3 verifies that Bob detects a modified M3
// ciphertext through AEAD authentication.
func TestBobRejectsTamperedPayloadM3(t *testing.T) {
	logSection(t, "Security Test: Bob verifies AEAD integrity (M3)")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	var m1, m2, m3 keyexchange.Message

	stateA, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m1 = m
			return nil
		}),
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	stateB, err := keyexchange.HandleM1(
		m1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m2 = m
			return nil
		}),
		privB,
	)
	if err != nil {
		t.Fatalf("HandleM1 failed: %v", err)
	}

	err = keyexchange.HandleM2AsInitiator(
		stateA,
		m2,
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m3 = m
			return nil
		}),
		[]byte("top secret share"),
	)
	if err != nil {
		t.Fatalf("HandleM2AsInitiator failed: %v", err)
	}

	// An attacker modifies the ciphertext.
	ct, ok := m3.Data["ct"]
	if !ok || len(ct) == 0 {
		t.Fatal("M3 Data['ct'] not found or empty")
	}

	ct[0] ^= 0xFF

	// Bob must reject the message because AEAD authentication fails.
	_, err = keyexchange.HandleM3(stateB, m3, cryptoProvider)
	if err == nil {
		t.Error("Bob decrypted a tampered message without error")
	} else {
		logOK(t, "Bob detected tampering in M3")
	}
}

// TestIdentitySpoofingM1 ensures that Bob rejects an M1 message where
// the sender claims to be Alice but the signature was generated with
// Eve's private key.
func TestIdentitySpoofingM1(t *testing.T) {
	logSection(t, "Security Test: M1 Identity Spoofing")

	cryptoProvider := newTestProvider()

	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	_, privEve, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Eve signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	var m1 keyexchange.Message

	// Eve signs the message using her own private key, but the identity
	// inside the protocol message claims to be Alice.
	_, _ = keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m1 = m
			return nil
		}),
		privEve,
	)

	// Bob must verify the signature using Alice's registered public key.
	// Since the message was signed by Eve, verification must fail.
	_, err = keyexchange.HandleM1(
		m1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error { return nil }),
		privB,
	)

	if err == nil {
		t.Error("Bob accepted an M1 from an impostor claiming to be Alice")
	} else {
		logOK(t, "Bob detected and rejected the spoofed identity")
	}
}

// TestTranscriptMismatchM3 verifies that Bob rejects the final message if
// his local session transcript has been modified.
//
// Since the transcript is used during key derivation, changing NonceA in
// Bob's state should cause Bob to derive a different AEAD key. Therefore,
// decryption of M3 must fail.
func TestTranscriptMismatchM3(t *testing.T) {
	logSection(t, "Session Transcript Integrity")

	cryptoProvider := newTestProvider()

	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Alice signing key: %v", err)
	}

	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Bob signing key: %v", err)
	}

	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{
			"Alice": pubA,
			"Bob":   pubB,
		},
	}

	var m1, m2, m3 keyexchange.Message

	stateA, err := keyexchange.StartAsInitiator(
		"Alice",
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m1 = m
			return nil
		}),
		privA,
	)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	stateB, err := keyexchange.HandleM1(
		m1,
		"Bob",
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m2 = m
			return nil
		}),
		privB,
	)
	if err != nil {
		t.Fatalf("HandleM1 failed: %v", err)
	}

	err = keyexchange.HandleM2AsInitiator(
		stateA,
		m2,
		cryptoProvider,
		dir,
		mockSender(func(m keyexchange.Message) error {
			m3 = m
			return nil
		}),
		[]byte("secret share"),
	)
	if err != nil {
		t.Fatalf("HandleM2AsInitiator failed: %v", err)
	}

	if len(stateB.NonceA) == 0 {
		t.Fatal("NonceA is missing from Bob's state")
	}

	// The local transcript stored by Bob is modified.
	// Bob will therefore derive a different session key.
	stateB.NonceA[0] ^= 0xFF

	_, err = keyexchange.HandleM3(stateB, m3, cryptoProvider)
	if err == nil {
		t.Error("Bob accepted M3 despite a transcript mismatch")
	} else {
		logOK(t, "Bob detected the session history inconsistency")
	}
}
