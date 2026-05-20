package core

import (
	"crypto/ed25519"
	"threshold-recovery/internal/crypto"
	"time"
)

// WalletState represents the current recovery state of a wallet.
type WalletState string

const (
	StateActive   WalletState = "ACTIVE"
	StateDormant  WalletState = "DORMANT"
	StateRecovery WalletState = "RECOVERY"
)

// Wallet stores the server-side metadata required to enforce the recovery
// policy and participate in the threshold signing protocol.
type Wallet struct {
	ID string `json:"id"`
	// PublicKey is used to verify liveness updates signed by the wallet owner.
	PublicKey []byte `json:"public_key"`

	// Recovery policy parameters.
	LastActivity        time.Time     `json:"last_activity"`
	ExpirationDate      time.Time     `json:"expiration_date"`
	InactivityThreshold time.Duration `json:"inactivity_threshold"`

	// Cryptographic material stored by the server.
	//
	// ServerShare is used only after the recovery policy allows activation.
	// Commitments allow participants and the server to verify secret shares.
	ServerShare []byte   `json:"server_share"`
	Commitments [][]byte `json:"commitments"`

	// Public threshold parameters and wallet public key used during recovery.
	ThresholdParams crypto.ThresholdParams `json:"threshold_params"`
	P               []byte                 `json:"point"`
}

// IsRecoverable returns true when the wallet recovery policy is satisfied.
//
// Recovery is enabled either when the inactivity period has elapsed since the
// last liveness update, or when the absolute expiration date has passed.
func (w *Wallet) IsRecoverable() bool {
	// If now > LastActivity + Threshold OR now > ExpirationDate
	deadline := w.LastActivity.Add(w.InactivityThreshold)
	return time.Now().After(deadline) || time.Now().After(w.ExpirationDate)
}

// Participant represents a registered user that can receive recovery shares
// and take part in the collaborative signing protocol.
type Participant struct {
	ID        string            `json:"id"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	CreatedAt time.Time         `json:"created_at"`
}
