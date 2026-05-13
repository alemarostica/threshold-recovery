package keyexchange

// MessageType identifies the phase of the key exchange protocol.
// Each message type corresponds to a distinct step in the Authenticated
// key exchange execution.
type MessageType string

// M1, M2, M3 are message types corresponding to the three rounds of the protocol.
const (
	M1 MessageType = "M1"
	M2 MessageType = "M2"
	M3 MessageType = "M3"
)

// Message defines the generic transport format used to exchange protocol
// messages. It includes routing information, freshness guarantees,
// and a payload with protocol-specific data.
type Message struct {
	Type  MessageType       `json:"type"`
	From  string            `json:"from"`
	To    string            `json:"to"`
	Epoch uint64            `json:"epoch"`
	Data  map[string][]byte `json:"data"`
}
