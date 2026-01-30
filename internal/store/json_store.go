package store

import (
	"fmt"
	"encoding/json"
	// "errors"
	"os"
	"path/filepath"
	"threshold-recovery/internal/core"
	"time"
)

// The JSONStore is simply a path to a directory
type JSONStore struct {
	DataDir string
}

func NewJSONStore(dir string) *JSONStore {
	return &JSONStore{DataDir: dir}
}

// This take a wallet name and finds the corresponding file on local storage
func (s *JSONStore) GetWallet(id string) (*core.Wallet, error) {
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
	path := filepath.Join(s.DataDir, w.ID+".json")

	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("wallet with ID %s already exists", w.ID)
	}
	return s.save(w)
}

// Simply updates the liveliness, rewrites the entire file (could it be optimized? Maybe it is pointless to do so)
func (s *JSONStore) UpdateLiveness(id string) error {
	w, err := s.GetWallet(id)
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
