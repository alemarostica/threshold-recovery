package keyexchange

type MessageType string

const (
	M1 MessageType = "M1"
	M2 MessageType = "M2"
	M3 MessageType = "M3"
)

type Message struct {
	Type  MessageType       `json:"type"`
	From  string            `json:"from"`
	To    string            `json:"to"`
	Epoch uint64            `json:"epoch"`
	Data  map[string][]byte `json:"data"`
}
