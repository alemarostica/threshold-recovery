package store

import (
	"encoding/json"
	// "errors"
	"os"
	"path/filepath"
	"threshold-recovery/internal/core"
	"time"
)

type JSONStore struct {
	DataDir string
}

func NewJSONStore(dir string) *JSONStore {
	return &JSONStore{DataDir: dir}
}

func (s *JSONStore) GetWallet(id string) (*core.Wallet, error) {
	path := filepath.Join(s.DataDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w core.Wallet
	err = json.Unmarshal(data, &w)
	return &w, err
}

func (s *JSONStore) UpdateLiveness(id string) error {
	w, err := s.GetWallet(id)
	if err != nil {
		return err
	}
	w.LastActivity = time.Now()
	return s.RegisterWallet(w)
}

func (s *JSONStore) RegisterWallet(w *core.Wallet) error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.DataDir, w.ID+".json")
	return os.WriteFile(path, data, 0600)
}
