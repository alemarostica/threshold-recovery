package keyexchange

import (
	"encoding/json"
)

// This file provides serialization helpers for the ShareMessage struct.
// ShareMessage is encoded as JSON before transmission so it can be
// exchanged as a byte payload within the exchange protocol.

// MarshalShare encodes a ShareMessage as a JSON byte array.
func MarshalShare(msg ShareMessage) ([]byte, error) {
	return json.MarshalIndent(msg, "", "  ")
}

// UnmarshalShare decodes a JSON-encoded ShareMessage.
func UnmarshalShare(data []byte) (ShareMessage, error) {
	var s ShareMessage
	err := json.Unmarshal(data, &s)
	return s, err
}
