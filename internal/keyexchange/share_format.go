// Is this really necessary?
// We could just make it so we don't have to fucking marshal and unmarshal each time
package keyexchange

import (
	"encoding/json"
)

// convert a Share struct (ID + value) into a byte array
func MarshalShare(msg ShareMessage) ([]byte, error) {
	return json.MarshalIndent(msg, "", "  ")
}

func UnmarshalShare(data []byte) (ShareMessage, error) {
	var s ShareMessage
	err := json.Unmarshal(data, &s)
	return s, err
}
