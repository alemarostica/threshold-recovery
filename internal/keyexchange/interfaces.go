package keyexchange

import (
	"crypto/ed25519"
	"threshold-recovery/internal/crypto"
)

// This file defines the interfaces required by an Authenticated Key Exchange (AKE) protocol.
// The protocol provides mutual authentication between participants and establishes a
// secure channel used to protect all subsequent communications.

// CRYPTO INTERFACES

// CryptoProvider defines cryptographic primitives required by the AKE protocol,
// // including Diffie–Hellman, signatures, key derivation, and AEAD encryption.
type CryptoProvider interface {

	// GenerateEphemeralDH generates an ephemeral Diffie-Hellman keypair for a session.
	GenerateEphemeralDH() (priv, pub []byte, err error)
	// ComputeSharedSecret derives the Diffie-Hellman shared secret.
	ComputeSharedSecret(priv, peerPub []byte) ([]byte, error)

	Sign(privSigKey []byte, msg []byte) ([]byte, error)
	Verify(pubSigKey []byte, msg []byte, sig []byte) bool

	// DeriveKey applies a KDF over the shared secret and transcript to obtain the session key.
	DeriveKey(sharedSecret, transcript []byte) ([]byte, error)

	Encrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error)
	Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error)

	RandomNonce() []byte
	Hash(data []byte) []byte
}

// SERVER INTERFACE

// Directory provides access to participants' public keys and protocol epoch.
type Directory interface {
	GetPublicKey(userID string) (ed25519.PublicKey, error)
	GetEpoch() uint64
}

// MessageSender abstracts message transmission between participants.
type MessageSender interface {
	Send(msg Message) error
}

// USEFUL STRUCTS

// ShareMessage represents the payload used in the recovery phase of the protocol.
type ShareMessage struct {
	Index       int                    `json:"index"`
	Share       []byte                 `json:"scalar"`
	Commitments [][]byte               `json:"commitments"`
	PubParams   crypto.ThresholdParams `json:"public_params"`
	Username    string                 `json:"username"`
	WalletPub   ed25519.PublicKey      `json:"wallet_pub_kex"`
}

type NonceMessage struct {
	Index crypto.ParticipantID `json:"participant_id"`
	Ci    []byte               `json:"ci"`
}
