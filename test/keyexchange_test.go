package test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"threshold-recovery/internal/keyexchange"

	"golang.org/x/crypto/chacha20poly1305"
)

// Uncomment only for single file testing.

func logSection(t *testing.T, title string) {
	t.Helper()
	t.Logf("\n========== %s ==========", title)
}

func logOK(t *testing.T, msg string) {
	t.Helper()
	t.Logf("[OK] %s", msg)
}

// Interface implementation.

type RealCrypto struct{}

func (r RealCrypto) GenerateEphemeralDH() ([]byte, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

func (r RealCrypto) ComputeSharedSecret(priv, peerPub []byte) ([]byte, error) {
	p, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, errors.New("invalid private key bytes")
	}

	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, errors.New("invalid peer public key")
	}

	return p.ECDH(pub)
}

func (r RealCrypto) Sign(priv []byte, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	return ed25519.Sign(priv, msg), nil
}

func (r RealCrypto) Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func (r RealCrypto) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (r RealCrypto) RandomNonce() []byte {
	out := make([]byte, 32)
	rand.Read(out)
	return out
}

func (r RealCrypto) DeriveKey(shared, transcript []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, transcript, "share-transfer-v1", 32)
}

func (r RealCrypto) Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

func (r RealCrypto) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, aad)
}

// Server mock

type RealTestDir struct {
	Keys map[string]ed25519.PublicKey
}

func (d *RealTestDir) GetPublicKey(id string) (ed25519.PublicKey, error) {
	key, ok := d.Keys[id]
	if !ok {
		return nil, errors.New("unknown identity")
	}
	return key, nil
}

func (d *RealTestDir) GetEpoch() uint64 { return 2026 }

// Helper per gestire il mittente nel test
type mockSender func(keyexchange.Message) error

func (m mockSender) Send(msg keyexchange.Message) error { return m(msg) }

// Test 1: TestCompleteProtocol performs a full simulation of the Authenticated
// Diffie–Hellman key exchange. At the end, it is checked if the payload
// decrypted by Bob is correct.
func TestCompleteProtocol(t *testing.T) {
	logSection(t, "Start key exchange (Alice <-> Bob)")
	crypto := RealCrypto{}

	// 1. Setup phase.
	logSection(t, "Identity and directory setup")
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	dir := &RealTestDir{
		Keys: map[string]ed25519.PublicKey{"Alice": pubA, "Bob": pubB},
	}
	logOK(t, "Identities generated and registered in dir")

	// Channels/Variables to simulate the network exchange.
	var msgM1, msgM2, msgM3 keyexchange.Message
	senderToBob := func(msg keyexchange.Message) error { msgM1 = msg; return nil }
	senderToAlice := func(msg keyexchange.Message) error { msgM2 = msg; return nil }
	senderFinal := func(msg keyexchange.Message) error { msgM3 = msg; return nil }

	// 2. Alice starts the protocol.
	logSection(t, "Alice initiates M1")
	stateA, err := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, mockSender(senderToBob), privA)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}
	logOK(t, "Alice generated and sent M1")

	// 3. Bob responds to Alice.
	logSection(t, "Bob receives M1 and replies with M2")
	stateB, err := keyexchange.HandleM1(msgM1, "Bob", crypto, dir, mockSender(senderToAlice), privB)
	if err != nil {
		t.Fatalf("HandleM1 failed: %v", err)
	}
	logOK(t, "Bob verified Alice's Identity and sent M2")

	// 4. Alice sends the encrypted payload.
	logSection(t, "Alice receives M2 and sends M3")
	originalPayload := []byte("A generic secret message")
	err = keyexchange.HandleM2AsInitiator(stateA, msgM2, crypto, dir, mockSender(senderFinal), originalPayload)
	if err != nil {
		t.Fatalf("HandleM2AsInitiator failed: %v", err)
	}
	logOK(t, "Alice established the shared secret and encrypted M3")

	// 5. Bob recovers the payload
	logSection(t, "Bob receives M3 and decrypts it")
	decryptedPayload, err := keyexchange.HandleM3(stateB, msgM3, crypto)
	if err != nil {
		t.Fatalf("HandleM3 failed: %v", err)
	}

	// 6. Final verification
	if !bytes.Equal(decryptedPayload, originalPayload) {
		t.Fatalf("Data inconsistency.\nExpected: %s\nGot:      %s", originalPayload, decryptedPayload)
	}
	logOK(t, "Protocol completed.")
}

// Test 2: TestInitiatorStateInitialization checks the state initialized
// by Alice During StartAsInitiator.
func TestInitiatorStateInitialization(t *testing.T) {
	logSection(t, "Unit Test: Initiator State")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	// Generate the key.
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	dir.Keys = map[string]ed25519.PublicKey{"Alice": pubA}

	dummySender := mockSender(func(m keyexchange.Message) error { return nil })

	// Run StartAsInitiator
	state, err := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, dummySender, privA)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	// Verify if the state is nil
	if state == nil {
		t.Fatal("State is nil")
	}
	// Verify if the IDs are correct.
	if state.MyID != "Alice" || state.PeerID != "Bob" {
		t.Errorf("Wrong IDs in state: got %s->%s", state.MyID, state.PeerID)
	}
	// Verify if Alice private key is generated.
	if len(state.MyPriv) == 0 {
		t.Error("Ephemeral private key not generated")
	}
	// Verify if the nonce is generated.
	if len(state.NonceA) == 0 {
		t.Error("Nonce A was not generated")
	}

	logOK(t, "Initiator state correctly initialized with DH material and nonces")
}

// Test 3: TestResponderStateInitialization checks the state initialized
// by Bob in HandleM1.
func TestResponderStateInitialization(t *testing.T) {
	logSection(t, "Responder State from HandleM1")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	// Setup Alice and Bob in the Directory.
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	dir.Keys = map[string]ed25519.PublicKey{"Alice": pubA, "Bob": pubB}

	// Run StartAsInitiator.
	var msgM1 keyexchange.Message
	aliceSender := mockSender(func(m keyexchange.Message) error {
		msgM1 = m
		return nil
	})

	stateA, err := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, aliceSender, privA)
	if err != nil {
		t.Fatalf("Alice failed to start: %v", err)
	}

	// Run HandleM1
	stateB, err := keyexchange.HandleM1(msgM1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { return nil }), privB)
	if err != nil {
		t.Fatalf("Bob failed to handle M1: %v", err)
	}

	// Verify if the two NonceA correspond.
	if !bytes.Equal(stateB.NonceA, stateA.NonceA) {
		t.Error("Bob's NonceA does not match Alice's NonceA")
	}

	// Verify if the two Alice public key correspond.
	if !bytes.Equal(stateB.PeerPub, stateA.MyPub) {
		t.Error("Bob's PeerPub does not match Alice's MyPub")
	}

	// Verify if Bob private key and NonceB are generated.
	if len(stateB.MyPriv) == 0 || len(stateB.NonceB) == 0 {
		t.Error("Bob's ephemeral material is missing")
	}

	logOK(t, "Bob's state is synchronized with Alice's initial state")
}

// Test 4: TestHandleM1WrongRecipient verifies that Bob rejects an M1 message
// generated by Alice for Charles but send to Bob.
func TestHandleM1WrongRecipient(t *testing.T) {
	logSection(t, "M1 Wrong Recipient")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	pubC, _, _ := ed25519.GenerateKey(rand.Reader)

	dir.Keys = map[string]ed25519.PublicKey{
		"Alice":   pubA,
		"Bob":     pubB,
		"Charles": pubC,
	}

	// Alice prepares M1 for Charles.
	var msgM1 keyexchange.Message
	aliceSender := mockSender(func(m keyexchange.Message) error {
		msgM1 = m
		return nil
	})

	_, err := keyexchange.StartAsInitiator("Alice", "Charles", crypto, dir, aliceSender, privA)
	if err != nil {
		t.Fatalf("StartAsInitiator failed: %v", err)
	}

	// Suppose M1 is delivered to Bob instead of Charles.
	_, err = keyexchange.HandleM1(msgM1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { return nil }), privB)

	if err == nil {
		t.Error("Bob accepted a message intended for Charles")
	} else {
		logOK(t, "Bob correctly rejected M1 intended for Charles")
	}
}

// Test 5: TestAliceRejectsCorruptedM2 verifies if Alice rejects a forged
// signature of M2.
func TestAliceRejectsCorruptedM2(t *testing.T) {
	logSection(t, "Alice verifies Bob's signature")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	dir.Keys = map[string]ed25519.PublicKey{"Alice": pubA, "Bob": pubB}

	var m1 keyexchange.Message
	stateA, _ := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m1 = m; return nil }), privA)

	var m2 keyexchange.Message
	keyexchange.HandleM1(m1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m2 = m; return nil }), privB)

	// Suppose an attacker intercepts M2 and modifies Bob's signature.
	if sig, ok := m2.Data["sig"]; ok && len(sig) > 0 {
		sig[0] ^= 0xFF
	} else {
		t.Fatal("M2 sig field not found or empty")
	}

	// Verify if Alice rejects the forged signature.
	err := keyexchange.HandleM2AsInitiator(stateA, m2, crypto, dir, mockSender(func(m keyexchange.Message) error { return nil }), []byte("secret"))
	if err == nil {
		t.Error("Alice accepted M2 with a corrupted signature!")
	} else {
		logOK(t, "Alice correctly rejected the forged M2")
	}
}

// Test 6: TestBobRejectsTamperedPayloadM3 verifies that Bob detects a
// tampered M3 ciphertext.
func TestBobRejectsTamperedPayloadM3(t *testing.T) {
	logSection(t, "Security Test: Bob verifies AEAD integrity (M3)")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	dir.Keys = map[string]ed25519.PublicKey{"Alice": pubA, "Bob": pubB}

	var m1, m2, m3 keyexchange.Message
	stateA, _ := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m1 = m; return nil }), privA)
	stateB, _ := keyexchange.HandleM1(m1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m2 = m; return nil }), privB)
	keyexchange.HandleM2AsInitiator(stateA, m2, crypto, dir, mockSender(func(m keyexchange.Message) error { m3 = m; return nil }), []byte("top secret share"))

	// Suppose an attacker intercepts and modifies M3 ciphertext.
	if ct, ok := m3.Data["ct"]; ok && len(ct) > 0 {
		ct[0] ^= 0xFF
	} else {
		t.Fatal("M3 Data['ct'] not found or empty")
	}

	// Verify that Bob detects the tampered message during the AEAD decryption.
	_, err := keyexchange.HandleM3(stateB, m3, crypto)
	if err == nil {
		t.Error("Bob decrypted a tampered message without error")
	} else {
		logOK(t, "Bob detected tampering in M3")
	}
}

// Test 7: TestIdentitySpoofingM1 ensures that Bob rejects an M1 message
// where the sender claims to be Alice but the signature is forged by an attacker.
func TestIdentitySpoofingM1(t *testing.T) {
	logSection(t, "Security Test: M1 Identity Spoofing")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)

	// Generate Eve keys.
	_, privEve, _ := ed25519.GenerateKey(rand.Reader)

	dir.Keys = map[string]ed25519.PublicKey{
		"Alice": pubA,
		"Bob":   pubB,
	}

	// Eve sends M1, signed with her key, claiming to be Alice.
	var m1 keyexchange.Message
	_, _ = keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error {
		m1 = m
		return nil
	}), privEve)

	// Bob receives M1 and verifies the signature.
	_, err := keyexchange.HandleM1(m1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { return nil }), privB)
	if err == nil {
		t.Error("Bob accepted an M1 from an impostor claiming to be Alice")
	} else {
		logOK(t, "Bob detected and rejected the spoofed identity")
	}
}

// Test 8: TestTranscriptMismatched verifies that Bob rejects the final message
// if his session state, in particular the Nonce and so the Transcript, has been tampered with.
func TestTranscriptMismatchM3(t *testing.T) {
	logSection(t, "Session Transcript Integrity")
	crypto := RealCrypto{}
	dir := &RealTestDir{}

	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	dir.Keys = map[string]ed25519.PublicKey{"Alice": pubA, "Bob": pubB}

	var m1, m2, m3 keyexchange.Message
	stateA, _ := keyexchange.StartAsInitiator("Alice", "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m1 = m; return nil }), privA)
	stateB, _ := keyexchange.HandleM1(m1, "Bob", crypto, dir, mockSender(func(m keyexchange.Message) error { m2 = m; return nil }), privB)

	keyexchange.HandleM2AsInitiator(stateA, m2, crypto, dir, mockSender(func(m keyexchange.Message) error { m3 = m; return nil }), []byte("secret share"))

	// Suppose an attacker intercepts NonceA and modifies it.
	if len(stateB.NonceA) > 0 {
		stateB.NonceA[0] ^= 0xFF
	} else {
		t.Fatal("NonceA is missing from Bob's state")
	}

	// Bob tries to decrypt M3 but it must fail since the transcript doesn't match Alice's.
	_, err := keyexchange.HandleM3(stateB, m3, crypto)
	if err == nil {
		t.Error("Bob accepted M3 despite a Transcript mismatch")
	} else {
		logOK(t, "Bob detected the session history inconsistency")
	}
}
