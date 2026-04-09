package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// implements keyexchange.CryptoProvider interface
type DefaultProvider struct {
	Ctx *CurveCtx
}

func NewDefaultProvider(ctx *CurveCtx) *DefaultProvider {
	return &DefaultProvider{Ctx: ctx}
}

func (p *DefaultProvider) GenerateEphemeralDH() ([]byte, []byte, error) {
	priv, x, y, err := elliptic.GenerateKey(p.Ctx.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub := elliptic.Marshal(p.Ctx.Curve, x, y)
	return priv, pub, nil
}

func (p *DefaultProvider) ComputeSharedSecret(priv, peerPub []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(p.Ctx.Curve, peerPub)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	sx, _ := p.Ctx.Curve.ScalarMult(x, y, priv)
	return sx.Bytes(), nil
}

func (p *DefaultProvider) Sign(privSigKey []byte, msg []byte) ([]byte, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = p.Ctx.Curve
	priv.D = new(big.Int).SetBytes(privSigKey)
	priv.PublicKey.X, priv.PublicKey.Y = p.Ctx.Curve.ScalarBaseMult(privSigKey)

	hash := p.Hash(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		return nil, err
	}

	// format as fixed 64 bytes
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[:32])
	return sig, nil
}

func (p *DefaultProvider) Verify(pubSigKey []byte, msg []byte, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	x, y := elliptic.Unmarshal(p.Ctx.Curve, pubSigKey)
	if x == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: p.Ctx.Curve, X: x, Y: y}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, p.Hash(msg), r, s)
}

func (p *DefaultProvider) DeriveKey(sharedSecret, transcript []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(transcript)
	return h.Sum(nil), nil
}

func (p *DefaultProvider) Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := p.RandomNonce()[:gcm.NonceSize()]
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return ct, nonce, nil
}

func (p *DefaultProvider) Decrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func (p *DefaultProvider) RandomNonce() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func (p *DefaultProvider) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
