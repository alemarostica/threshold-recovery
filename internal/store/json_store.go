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

// Deterministically derive a Public key into a storage ID
func (s *JSONStore) deriveID(pubKey []byte) string {
	h := hmac.New(sha256.New, s.HMACSecret)
	h.Write(pubKey)
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
