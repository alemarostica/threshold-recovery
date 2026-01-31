// EVERYTHING IN THIS FILE IS A MOCKUP OF THE FUNCTIONALITY TO BE IMPLEMENTED
package crypto

import (
	"crypto/rand"
	// Apparently deprecated
	// "math/rand"
	"encoding/hex"
	"fmt"
)

// A piece of the secret
type Share struct {
	Index int    `json:"index"`
	Value []byte `json:"value"`
}

// Provides simulation methods
type TSS struct{}

func NewTSS() *TSS {
	return &TSS{}
}

// Creates a FAKE keypair
func (t *TSS) GenerateIdentity() (pubKey []byte, privKey []byte) {
	// Implementation will use secp256k1 or ed25519
	mockPub := make([]byte, 32)
	mockPriv := make([]byte, 32)
	rand.Read(mockPub)
	rand.Read(mockPriv)
	return mockPub, mockPriv
}

// Split with Shamir's Secret Sharing (k of n)
func (t *TSS) SplitSecret(secret []byte, n, k int) ([]Share, error) {
	if k > n {
		return nil, fmt.Errorf("threshold k cannot be larger than participants n")
	}

	shares := make([]Share, n)
	for i := range n {
		// For now, random noise as shares
		val := make([]byte, len(secret))
		rand.Read(val)

		shares[i] = Share{
			Index: i + 1, // Share index starts at 1, not 0
			Value: val,
		}
	}
	return shares, nil
}

// VSS public commitments
// Allow shareholders to verify their share is valid without seeing the secret
func (t *TSS) ComputeCommitments(secret []byte, k int) []byte {
	// Elliptic curve points?
	return fmt.Appendf(nil, "mock_commitment_for_%s", hex.EncodeToString(secret[:4]))
}
