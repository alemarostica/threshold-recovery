// Is this really necessary?
// We could just make it so we don't have to fucking marshal and unmarshal each time
package crypto

import (
	"encoding/json"
)

// convert a Share struct (ID + value) into a byte array
func MarshalShare(s Share) ([]byte, error) {
	return json.Marshal(s)
}

func UnmarshalShare(data []byte) (Share, error) {
	var s Share
	err := json.Unmarshal(data, &s)
	return s, err
}
