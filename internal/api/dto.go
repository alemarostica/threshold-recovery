package api

import (
	"time"
)

// Data Transfer Objects, everything coming from the outside world

type FriendShareInput struct {
	FriendPubKey  []byte `json:"friend_public_key"`
	EncryptedBlob []byte `json:"encrypted_blob"`
}

// The request to register a wallet
type RegisterRequest struct {
	PublicKey           []byte             `json:"public_key"`
	EncryptedShare      []byte             `json:"encrypted_share"`
	ShareCommitment     []byte             `json:"share_commitment"`
	InactivityThreshold time.Duration      `json:"inactivity_threshold"`
	FriendShares        []FriendShareInput `json:"friend_shares"`
}

type SharePickupRequest struct {
	PublicKey    []byte `json:"public_key"`
	FriendPubKey []byte `json:"friend_pub_key"`
	Signature    []byte `json:"signature"`
}

// Liveness request is the JSON body for POST /liveness
type LivenessRequest struct {
	PublicKey []byte `json:"public_key"`
	Timestamp int64  `json:"timestamp"` // Should help preventing replay attacks
	Signature []byte `json:"signature"` // User's proof
}

// The request to the server to provide a partial signature
type SignRequest struct {
	PublicKey []byte `json:"public_key"`
	Message   string `json:"message"`
}

type RegisterParticipantRequest struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
}
