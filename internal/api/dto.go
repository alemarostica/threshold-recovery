package api

import (
	"crypto/ed25519"
	"threshold-recovery/internal/crypto"
	"time"
)

// Data Transfer Objects, everything coming from the outside world

type FriendShareInput struct {
	FriendPubKey  []byte `json:"friend_public_key"`
	EncryptedBlob []byte `json:"encrypted_blob"`
}

// The request to register a wallet
type RegisterRequest struct {
	Username            string              `json:"username"`
	PublicKey           []byte              `json:"public_key"`
	ServerShare         crypto.Share        `json:"server_share"`
	Commitments         []crypto.Commitment `json:"commitments"`
	InactivityThreshold time.Duration       `json:"inactivity_threshold"`
	FriendShares        []FriendShareInput  `json:"friend_shares"`
}

type SignedRegisterRequest struct {
	Data      RegisterRequest `json:"data"`
	Signature []byte          `json:"signature"`
}

type SharePickupRequest struct {
	PubKey       []byte `json:"public_key"`
	FriendPubKey []byte `json:"friend_public_key"`

	// let's add some security
	Timestamp int64  `json:"timestamp"`
	Signature []byte `json:"signature"`
}

type SharePickupResponse struct {
	ShareBlob []byte              `json:"share_blob"`
	Comms     []crypto.Commitment `json:"commitments"`
}

// Liveness request is the JSON body for POST /liveness
type LivenessRequest struct {
	Username  string `json:"username"`
	PublicKey []byte `json:"public_key"`
	Timestamp int64  `json:"timestamp"` // Should help preventing replay attacks
}

type SignedLivenessRequest struct {
	Data      LivenessRequest `json:"data"`
	Signature []byte          `json:"singature"`
}

// The request to the server to provide a partial signature
type SignRequest struct {
	PublicKey []byte `json:"public_key"`
	Message   []byte `json:"message"`
}

type RegisterParticipantRequest struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

type ParticipantResponse struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Epoch     uint64            `json:"epoch"`
}

type SignedParticipantResponse struct {
	Data      ParticipantResponse `json:"data"`
	Signature []byte              `json:"signature"`
}
