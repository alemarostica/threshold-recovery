package crypto

import "errors"

var (
	ErrInvalidShare = errors.New("share verification failed")
	ErrInvalidSig   = errors.New("signature verification failed")
)

// This Verifier describes what the server needs to check before accepting data
type Verifier interface {
	// VerifySignature checks if a message was signed by the wallet's private key
	// Used for liveness check
	VerifySignature(pubKey []byte, message []byte, signature []byte) bool

	// VerifyShare checks if a VSS share is valid against a commitment
	// Used during registration to ensure the server isn's storing incorrect stuff
	VerifyShare(share []byte, commitment []byte) bool

	// Takes server's share and msg to sign
	// Returns the partial server's signature
	SignPartial(share []byte, message []byte) ([]byte, error)
}

// All this is just placeholder stuff
type MockVerifier struct{}

func (m *MockVerifier) VerifySignature(pubKey, msg, sig []byte) bool {
	return true
}

func (m *MockVerifier) VerifyShare(share, commit []byte) bool {
	return true
}

func (m* MockVerifier) SignPartial(share, msg []byte) ([]byte, error) {
	return []byte("mock_partial_signature"), nil
}
