package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerPort          string `json:"server_port"`
	DataDir             string `json:"data_dir"`
	DefaultTimeoutHours int    `json:"default_timeout_hours"`
}

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
