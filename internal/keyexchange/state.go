package keyexchange

// SessionState stores the local state of one authenticated key exchange session.
type SessionState struct {

	// Participant identities.
	MyID   string
	PeerID string

	// Ephemeral Diffie–Hellman key material.
	MyPriv  []byte
	MyPub   []byte
	PeerPub []byte

	// Session nonces exchanged during the protocol.
	NonceA []byte
	NonceB []byte

	// Values derived during session establishment.
	SharedKey  []byte
	Transcript []byte
}
