package core

import "time"

// This type represents the state of the recovery process

type WalletState string

// Various possible states of the wallet
const (
	StateActive   WalletState = "ACTIVE"
	StateDormant  WalletState = "DORMANT"
	StateRecovery WalletState = "RECOVERY"
)

// The user's data
type Wallet struct {
	ID string `json:"id"`
	// Used in verification of liveness signatures
	PublicKey []byte `json:"public_key"`

	// Access control
	LastActivity        time.Time     `json:"last_activity"`
	ExpirationDate      time.Time     `json:"expiration_date"`
	InactivityThreshold time.Duration `json:"inactivity_threshold"`

	// Cryptography stuff
	// The server's share, locked unless policy allows access
	EncryptedShare []byte `json:"encrypted_share"`
}

// Returns whether the wallet is in a recoverable state
func (w *Wallet) IsRecoverable() bool {
	// If now > LastActivity + Threshold OR now > ExpirationDate
	deadline := w.LastActivity.Add(w.InactivityThreshold)
	return time.Now().After(deadline) || time.Now().After(w.ExpirationDate)
}
