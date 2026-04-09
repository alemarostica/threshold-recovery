package keyexchange

// --- CRYPTO INTERFACES ---

type CryptoProvider interface {
	GenerateEphemeralDH() (priv, pub []byte, err error)
	ComputeSharedSecret(priv, peerPub []byte) ([]byte, error)

	Sign(privSigKey []byte, msg []byte) ([]byte, error)
	Verify(pubSigKey []byte, msg []byte, sig []byte) bool

	DeriveKey(sharedSecret, transcript []byte) ([]byte, error)

	Encrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error)
	Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error)

	RandomNonce() []byte
	Hash(data []byte) []byte
}

// --- SERVER INTERFACE ---

type Directory interface {
	GetPublicKey(userID string) ([]byte, error)
	GetEpoch() uint64
}

type MessageSender interface {
	Send(msg Message) error
}
