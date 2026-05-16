package api

import (
	"crypto/ed25519"
	"threshold-recovery/internal/crypto"
	"time"

	"filippo.io/edwards25519"
)

// Data Transfer Objects, everything coming from the outside world

type FriendShareInput struct {
	FriendPubKey  []byte `json:"friend_public_key"`
	EncryptedBlob []byte `json:"encrypted_blob"`
}

// The request to register a wallet
type RegisterRequest struct {
	Username            string                 `json:"username"`
	PublicKey           []byte                 `json:"public_key"`
	ServerShare         []byte                 `json:"server_share"`
	PubParams           crypto.ThresholdParams `json:"public_params"`
	Commitments         [][]byte               `json:"commitments"`
	InactivityThreshold time.Duration          `json:"inactivity_threshold"`
	P                   []byte                 `json:"point"`
}

type SignedRegisterRequest struct {
	Data      RegisterRequest `json:"data"`
	Signature []byte          `json:"signature"`
}

type RegisterResponse struct {
	PubKey       []byte `json:"public_key"`
	FriendPubKey []byte `json:"friend_public_key"`

	// let's add some security
	Timestamp int64  `json:"timestamp"`
	Signature []byte `json:"signature"`
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

type RegisterParticipantResponse struct {
	ServerPublicKey ed25519.PublicKey   `json:"server_public_key"`
	Alpha           edwards25519.Scalar `json:"alpha"`
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

// Signing stuff
type SignInitRequest struct {
	WalletPubKey   []byte               `json:"wallet_pub_key"`
	WalletUsername string               `json:"username"`
	ParticipantID  crypto.ParticipantID `json:"participant_id"`
	Requester      string               `json:"requester"`
}

type SignInitResponse struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message"`
	SessionID   []byte                 `json:"session,omitempty"`
	VectorV     []crypto.ParticipantID `json:"vector_v,omitempty"`
	JoinedCount int                    `json:"joined_count,omitempty"`
	P           []byte                 `json:"point,omitempty"`
	Usernames   []string               `json:"usernames,omitempty"`
}

type SignCommitment struct {
	ParticipantID crypto.ParticipantID `json:"id"`
	Commitment    []byte               `json:"c"`
}

type SignReveal struct {
	ParticipantID crypto.ParticipantID `json:"id"`
	Reveal        []byte               `json:"r"`
}

type PartialSigMessage struct {
	ParticipantID crypto.ParticipantID `json:"id"`
	Z             []byte               `json:"z"`
}

type SetM1Request struct {
	SessionID []byte               `json:"session_id"`
	Ci        []byte               `json:"ci"`
	Index     crypto.ParticipantID `json:"index"`
	Username  string               `json:"username"`
}

type SetM2Request struct {
	SessionID []byte               `json:"session_id"`
	Ri        []byte               `json:"ri"`
	Index     crypto.ParticipantID `json:"index"`
	Username  string               `json:"username"`
}

type M1_dto struct {
	Ci    []byte               `json:"ci"`
	Index crypto.ParticipantID `json:"index"`
}

type M2_dto struct {
	Ri    []byte               `json:"ci"`
	Index crypto.ParticipantID `json:"index"`
}

type GetM1Request struct {
	Username  string `json:"username"`
	SessionID []byte `json:"session_id"`
}

type GetM1Response struct {
	M1Array []M1_dto `json:"m1_array"`
}

type GetM2Request struct {
	Username  string `json:"username"`
	SessionID []byte `json:"session_id"`
}

type GetM2Response struct {
	M2Array []M2_dto `json:"m2_array"`
}

type SendPartialSign struct {
	Username         string                  `json:"username"`
	SessionID        []byte                  `json:"session_id"`
	PartialSignature crypto.PartialSignature `json:"partial_signature"`
}

type GetPartialSigns struct {
	Username  string `json:"username"`
	SessionID []byte `json:"session_id"`
}

type GetPartialSignsResp struct {
	PartialSignatures []crypto.PartialSignature `json:"partial_signatures"`
}

type SignedSignInitRequest struct {
	Data      SignInitRequest `json:"data"`
	Signature []byte          `json:"signature"`
}

type SignedSetM1Request struct {
	Data      SetM1Request `json:"data"`
	Signature []byte       `json:"signature"`
}

type SignedSetM2Request struct {
	Data      SetM2Request `json:"data"`
	Signature []byte       `json:"signature"`
}

type SignedGetM1Request struct {
	Data      GetM1Request `json:"data"`
	Signature []byte       `json:"signature"`
}

type SignedGetM2Request struct {
	Data      GetM2Request `json:"data"`
	Signature []byte       `json:"signature"`
}

type SignedSendPartialSign struct {
	Data      SendPartialSign `json:"data"`
	Signature []byte          `json:"signature"`
}

type SignedGetPartialSigns struct {
	Data      GetPartialSigns `json:"data"`
	Signature []byte          `json:"signature"`
}
