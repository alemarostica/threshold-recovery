package keyexchange

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
)

// DefaultProvider implements the CryptoProvider interface using modern cryptographic primitives:
// - X25519 for Diffie–Hellman key exchange;
// - Ed25519 for digital signatures;
// - HKDF-SHA256 for key derivation;
// - XChaCha20-Poly1305 for authenticated encryption.
type DefaultProvider struct{}

func NewDefaultProvider() *DefaultProvider {
	return &DefaultProvider{}
}

// GenerateEphemeralDH generates an ephemeral ECDH (X25519) key pair.
func (p *DefaultProvider) GenerateEphemeralDH() ([]byte, []byte, error) {

	// Generate a private key using a cryptographically secure RNG.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Return the private key and the corresponding public key.
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

// ComputeSharedSecret derives a shared secret using ECDH (X25519).
func (p *DefaultProvider) ComputeSharedSecret(privBytes, peerPubBytes []byte) ([]byte, error) {

	// Reconstruct the local private key from bytes.
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, errors.New("invalid private key bytes")
	}

	// Reconstruct the peer public key from bytes.
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, errors.New("invalid peer public key")
	}

	// Perform ECDH key agreement.
	return priv.ECDH(peerPub)
}

// Sign generates an Ed25519 digital signature over the given message, using the private key.
func (p *DefaultProvider) Sign(privSigKey []byte, msg []byte) ([]byte, error) {

	if len(privSigKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}

	return ed25519.Sign(privSigKey, msg), nil
}

// Verify checks an Ed25519 signature, using the public key.
func (p *DefaultProvider) Verify(pubSigKey []byte, msg []byte, sig []byte) bool {

	if len(pubSigKey) != ed25519.PublicKeySize {
		return false
	}

	return ed25519.Verify(pubSigKey, msg, sig)
}

// DeriveKey derives a session key using HKDF-SHA256.
// The transcript is used as a context-binding material.
func (p *DefaultProvider) DeriveKey(sharedSecret, transcript []byte) ([]byte, error) {

	return hkdf.Key(sha256.New, sharedSecret, transcript, "share-transfer-v1", 32)

}

// Encrypt performs authenticated encryption using XChaCha20-Poly1305 (AEAD).
func (p *DefaultProvider) Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {

	// Initialize AEAD cipher.
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	clear(key)
	runtime.KeepAlive(key)

	// Generate random nonce.
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Encrypt the plaintext with associated data.
	ct := aead.Seal(nil, nonce, plaintext, aad)

	return ct, nonce, nil

}

// Decrypt decrypts and authenticates an AEAD ciphertext.
// It ensures both confidentiality and integrity of the message.
func (p *DefaultProvider) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	clear(key)
	runtime.KeepAlive(key)

	// Decrypt and verify.
	return aead.Open(nil, nonce, ciphertext, aad)

}

// RandomNonce generates a cryptographically secure random 32-byte nonce.
func (p *DefaultProvider) RandomNonce() []byte {

	b := make([]byte, 32)
	rand.Read(b)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Errorf("failed to generate random nonce: %w", err))
	}

	return b

}

// Hash computes a SHA256 digest.
func (p *DefaultProvider) Hash(data []byte) []byte {

	h := sha256.Sum256(data)

	return h[:]

}
