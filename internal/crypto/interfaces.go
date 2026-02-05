package crypto

// This Verifier describes what the server needs to check before accepting data
type Verifier interface {
	// VerifySignature checks if a message was signed by the wallet's private key
	// Used for liveness check
	VerifySignature(pubKey []byte, message []byte, signature []byte) bool

	// VerifyShare checks if a VSS share is valid against a commitment
	// Used during registration to ensure the server isn's storing incorrect stuff
	VerifyShare(share []byte, commitment []byte, index int) bool

	// Takes server's share and msg to sign
	// Returns the partial server's signature
	SignPartial(share []byte, message []byte) ([]byte, error)
}
