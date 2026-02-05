package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"threshold-recovery/internal/core"
	"time"
)

// The JSONStore is simply a path to a directory
type JSONStore struct {
	DataDir    string
	HMACSecret []byte
}

func NewJSONStore(dir string, secret string) *JSONStore {
	return &JSONStore{
		DataDir:    dir,
		HMACSecret: []byte(secret),
	}
}

func (s *JSONStore) DeriveFriendSlot(walletPubKey, friendPubKey []byte) string {
	h := hmac.New(sha256.New, s.HMACSecret)

	// Must bind slot to both wallet and friend otherwise same friends would have same slot in different wallets
	h.Write(walletPubKey)
	h.Write(friendPubKey)

	return hex.EncodeToString(h.Sum(nil))
}

// This take a wallet name and finds the corresponding file on local storage
func (s *JSONStore) GetWallet(pubKey []byte) (*core.Wallet, error) {
	id := s.deriveID(pubKey)
	path := filepath.Join(s.DataDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w core.Wallet
	// Funky name for a function that parses JSON, it also appears to use some base64 magic
	err = json.Unmarshal(data, &w)
	return &w, err
}

// Creates a new wallet to local storage
func (s *JSONStore) RegisterWallet(w *core.Wallet) error {
	w.ID = s.deriveID(w.PublicKey)

	path := filepath.Join(s.DataDir, w.ID+".json")

	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("wallet for this public key already exists")
	}
	return s.save(w)
}

// Simply updates the liveliness, rewrites the entire file (could it be optimized? Maybe it is pointless to do so)
func (s *JSONStore) UpdateLiveness(pubKey []byte) error {
	w, err := s.GetWallet(pubKey)
	if err != nil {
		return err
	}
	w.LastActivity = time.Now()
	w.ExpirationDate = time.Now().Add(w.InactivityThreshold)
	return s.save(w)
}

// Private helper to write files
func (s *JSONStore) save(w *core.Wallet) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.DataDir, w.ID+".json")
	return os.WriteFile(path, data, 0600)
}

// Deterministically derive a Public key into a storage ID
func (s *JSONStore) deriveID(pubKey []byte) string {
	h := hmac.New(sha256.New, s.HMACSecret)
	h.Write(pubKey)
	return hex.EncodeToString(h.Sum(nil))
}

// Creates a new "registered user"
func (s *JSONStore) SaveParticipant(p *core.Participant) error {
	// Create participants dir if it does it exist
	partDir := filepath.Join(s.DataDir, "participants")
	if err := os.MkdirAll(partDir, 0755); err != nil {
		return err
	}

	path := filepath.Join(partDir, p.ID+".json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("participant ID '%s' already taken", p.ID)
	}

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Retrieves a "registered user"
func (s *JSONStore) GetParticipant(id string) (*core.Participant, error) {
	path := filepath.Join(s.DataDir, "participants", id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("participant not found")
	}

	var p core.Participant
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
