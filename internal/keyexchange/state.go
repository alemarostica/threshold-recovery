package keyexchange

type SessionState struct {
	MyID   string
	PeerID string

	// DH
	MyPriv  []byte
	MyPub   []byte
	PeerPub []byte

	// Nonces
	NonceA []byte
	NonceB []byte

	// Derived
	SharedKey  []byte
	Transcript []byte
}
