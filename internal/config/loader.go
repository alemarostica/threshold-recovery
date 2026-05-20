package config

import (
	"encoding/json"
	"os"
)

// Config contains the server configuration loaded from the JSON config file.
type Config struct {
	ServerPort          string `json:"server_port"`
	DataDir             string `json:"data_dir"`
	DefaultTimeoutHours int    `json:"default_timeout_hours"`
	HMACSecret          string `json:"hmac_secret"`
}

// Load reads a JSON configuration file from path and decodes it into a Config.
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
