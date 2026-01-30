package config

import (
	"encoding/json"
	"os"
)

// Simple struct which holds all the configurations
type Config struct {
	ServerPort          string `json:"server_port"`
	DataDir             string `json:"data_dir"`
	DefaultTimeoutHours int    `json:"default_timeout_hours"`
}

// This loads the configuration JSON file and parses it into a Config var
func Load(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = json.Unmarshal(file, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
