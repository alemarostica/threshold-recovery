package crypto

import (
	"crypto/ecdh"    // BINGO! Addio crypto/elliptic
	"crypto/ed25519" // Per le firme
	"crypto/hkdf"    // Per la KDF
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305" // Per la cifratrua simmetrica
)

// DefaultProvider non ha più bisogno del CurveCtx. X25519 è lo standard.
type DefaultProvider struct{}

func NewDefaultProvider() *DefaultProvider {
	return &DefaultProvider{}
}

// Generazione chiavi effimere per ECDH x25519
func (p *DefaultProvider) GenerateEphemeralDH() ([]byte, []byte, error) {
	// Generiamo una chiave privata effimera su curva X25519
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Restituiamo i byte crudi (32 byte per la privata, 32 per la pubblica)
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

func (p *DefaultProvider) ComputeSharedSecret(privBytes, peerPubBytes []byte) ([]byte, error) {
	// Ricostruiamo la nostra chiave privata
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, errors.New("invalid private key bytes")
	}

	// Ricostruiamo e validiamo la chiave pubblica del peer (Go controlla automaticamente che sia valida!)
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, errors.New("invalid peer public key")
	}

	// ECDH puro, sicuro e testato
	return priv.ECDH(peerPub)
}

// firme: ed25519
func (p *DefaultProvider) Sign(privSigKey []byte, msg []byte) ([]byte, error) {
	if len(privSigKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	return ed25519.Sign(privSigKey, msg), nil
}

func (p *DefaultProvider) Verify(pubSigKey []byte, msg []byte, sig []byte) bool {
	if len(pubSigKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pubSigKey, msg, sig)
}

// KDF (HKDF-SHA256)

func (p *DefaultProvider) DeriveKey(sharedSecret, transcript []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, sharedSecret, transcript, "share-transfer-v1", 32)
}

// AEAD (XChaCha20-Poly1305)

func (p *DefaultProvider) Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := p.RandomNonce()[:aead.NonceSize()]
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return ct, nonce, nil
}

func (p *DefaultProvider) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// Utils

func (p *DefaultProvider) RandomNonce() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func (p *DefaultProvider) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
