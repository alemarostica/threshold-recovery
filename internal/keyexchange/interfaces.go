package keyexchange

import (
	"crypto/ed25519"
	"threshold-recovery/internal/crypto"
)

// --- CRYPTO INTERFACES ---

type CryptoProvider interface {
	GenerateEphemeralDH() (priv, pub []byte, err error)
	ComputeSharedSecret(priv, peerPub []byte) ([]byte, error)

	Sign(privSigKey []byte, msg []byte) ([]byte, error)
	Verify(pubSigKey []byte, msg []byte, sig []byte) bool

	DeriveKey(sharedSecret, transcript []byte) ([]byte, error)

	Encrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error)
	Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error)

	RandomNonce() []byte
	Hash(data []byte) []byte
}

// --- SERVER INTERFACE ---

type Directory interface {
	GetPublicKey(userID string) (ed25519.PublicKey, error)
	GetEpoch() uint64
}

type MessageSender interface {
	Send(msg Message) error
}

type ShareMessage struct {
	Index       int                 `json:"index"`
	Share       crypto.Scalar       `json:"scalar"`
	Commitments crypto.Commitments  `json:"commitments"`
	PubParams   crypto.PublicParams `json:"public_params"`
}
