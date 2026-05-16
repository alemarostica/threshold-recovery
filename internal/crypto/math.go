package crypto

import "filippo.io/edwards25519"

// Arguably si potrebbe hardcodare, tanto é sempre quella
func GenerateAlpha() *edwards25519.Scalar {
	g := new(edwards25519.Scalar)
	g.SetCanonicalBytes([]byte{
		2, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	return g
}
