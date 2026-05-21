package store

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"threshold-recovery/internal/core"
	"time"
)

// JSONStore provides a simple file-based storage layer.
// Wallets and participants are persisted as JSON files inside DataDir.
type JSONStore struct {
	DataDir     string
	HMACSecret  []byte
	PKeyIDDBDir string
	mu          sync.Mutex
}

type ParticipantDirectory struct {
	Epoch        uint64                       `json:"epoch"`
	Participants map[string]*core.Participant `json:"participants"`
}

func NewJSONStore(dir, secret string) *JSONStore {
	return &JSONStore{
		DataDir:    dir,
		HMACSecret: []byte(secret),
	}
}

// DeriveFriendSlot derives a deterministic storage slot for a friend within a wallet.
// The slot is bound to both the wallet public key and the friend's public key, so that
// the same friend receives different slots in different wallets.
func (s *JSONStore) DeriveFriendSlot(walletPubKey, friendPubKey []byte) string {
	h := hmac.New(sha256.New, s.HMACSecret)

	h.Write(walletPubKey)
	h.Write(friendPubKey)

	return hex.EncodeToString(h.Sum(nil))
}

// GetWallet retrieves a wallet from local storage using the wallet public key
// and the corresponding user public key.
func (s *JSONStore) GetWallet(pubKey []byte, userPubKey ed25519.PublicKey) (*core.Wallet, error) {
	id := s.deriveID(pubKey, userPubKey)
	path := filepath.Join(s.DataDir, id+".json")

	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w core.Wallet
	err = json.Unmarshal(data, &w)
	return &w, err
}

// RegisterWallet stores a newly created wallet in local storage.
// The wallet identifier is deterministically derived from the wallet public key
// and the user public key.
func (s *JSONStore) RegisterWallet(w *core.Wallet, userPubKey ed25519.PublicKey) error {
	w.ID = s.deriveID(w.PublicKey, userPubKey)

	path := filepath.Join(s.DataDir, w.ID+".json")

	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("wallet for this public key already exists")
	}
	return s.save(w)
}

// DeleteWallet removes a wallet from local storage.
func (s *JSONStore) DeleteWallet(w *core.Wallet, userPubKey ed25519.PublicKey) error {
	w.ID = s.deriveID(w.PublicKey, userPubKey)

	path := filepath.Join(s.DataDir, w.ID+".json")

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("wallet does not exist")
	}

	// Delete
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete wallet file: %w", err)
	}

	return nil
}

// UpdateLiveness updates the last activity timestamp of a wallet.
// Since this prototype uses JSON file storage, the whole wallet file is rewritten.
func (s *JSONStore) UpdateLiveness(pubKey []byte, userPubKey ed25519.PublicKey) error {
	w, err := s.GetWallet(pubKey, userPubKey)
	if err != nil {
		return err
	}
	w.LastActivity = time.Now()
	return s.save(w)
}

// save writes a wallet to local JSON storage.
func (s *JSONStore) save(w *core.Wallet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.DataDir, w.ID+".json")
	return os.WriteFile(path, data, 0600)
}

// deriveID deterministically derives an internal storage identifier from
// a wallet public key and the corresponding user public key.
func (s *JSONStore) deriveID(pubKey []byte, userPubKey ed25519.PublicKey) string {
	h := hmac.New(sha256.New, s.HMACSecret)
	h.Write(pubKey)
	h.Write(userPubKey)
	return hex.EncodeToString(h.Sum(nil))
}

// loadDirectory loads the participant directory from local storage.
// If no directory exists yet, an empty directory is initialized with epoch zero.
func (s *JSONStore) loadDirectory() (*ParticipantDirectory, error) {
	path := filepath.Join(s.DataDir, "participants.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ParticipantDirectory{
				Epoch:        0,
				Participants: make(map[string]*core.Participant),
			}, nil
		}
		return nil, err
	}

	var dir ParticipantDirectory
	if err := json.Unmarshal(data, &dir); err != nil {
		return nil, err
	}
	return &dir, nil
}

// SaveParticipant stores a newly registered participant in the local directory.
// The epoch is increased whenever the participant directory changes.
func (s *JSONStore) SaveParticipant(p *core.Participant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.loadDirectory()
	if err != nil {
		return err
	}

	if _, exists := dir.Participants[p.ID]; exists {
		return fmt.Errorf("participant ID '%s' is taken", p.ID)
	}

	dir.Participants[p.ID] = p
	dir.Epoch++

	data, err := json.MarshalIndent(dir, "", "  ")
	if err != nil {
		return nil
	}

	path := filepath.Join(s.DataDir, "participants.json")
	return os.WriteFile(path, data, 0600)
}

// GetParticipant retrieves a registered participant and returns the current
// participant-directory epoch together with it.
func (s *JSONStore) GetParticipant(id string) (*core.Participant, uint64, error) {
	dir, err := s.loadDirectory()
	if err != nil {
		return nil, 0, err
	}

	p, exists := dir.Participants[id]
	if !exists {
		return nil, dir.Epoch, fmt.Errorf("participant not found")
	}

	return p, dir.Epoch, nil
}
