// Technically, there could be some race conditions when editing data about files
// Realistically this will not happen since this is a demo
// Do we care?

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
	DataDir     string
	HMACSecret  []byte
	PKeyIDDBDir string
}

type ParticipantDirectory struct {
	Epoch        uint64                        `json:"epoch"`
	Participants map[string]*core.Participant `json:"participants"`
}

func NewJSONStore(dir, secret string) *JSONStore {
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
	// fmt.Printf("[GetWallet] pubkey: %v\n", pubKey)
	id := s.deriveID(pubKey)
	// fmt.Printf("[GetWallet] id (derived): %v\n", id)
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

// Deterministically derive a Public key into a storage ID
func (s *JSONStore) deriveID(pubKey []byte) string {
	h := hmac.New(sha256.New, s.HMACSecret)
	h.Write(pubKey)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *JSONStore) loadDirectory() (*ParticipantDirectory, error) {
	path := filepath.Join(s.DataDir, "participants.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ParticipantDirectory{
				Epoch: 0, // TODO: ma un int
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

// Creates a new "registered user"
func (s *JSONStore) SaveParticipant(p *core.Participant) error {
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

// Retrieves a "registered user"
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
