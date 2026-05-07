package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

func IntToBytes(i int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToParticipantID(b []byte) (ParticipantID, error) {
	if len(b) != 4 {
		return 0, errors.New("invalid participant id length")
	}
	return ParticipantID(binary.BigEndian.Uint32(b)), nil
}

func scalarOne() Scalar {
	var one Scalar

	b := make([]byte, 32)
	b[0] = 1

	if _, err := one.SetCanonicalBytes(b); err != nil {
		panic(err)
	}

	return one
}

func SetAlpha() Scalar {
	g := new(Scalar)
	g.SetCanonicalBytes([]byte{
		2, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	})
	return *g
}

// Square and multiply by base, using exponentiation by squaring
func ScalarPow(base *Scalar, exp uint8, s *Scalar) {
	result := One
	power := edwards25519.NewScalar().Set(base)

	for exp > 0 {
		if exp&1 == 1 {
			result.Multiply(&result, power)
		}

		power.Multiply(power, power)
		exp >>= 1
	}

	*s = result
	result = Scalar{} // zeroization of result
	*power = Scalar{} // zeroization of power
}

func generateRandomScalar(s *Scalar) error {

	buf := make([]byte, 64)

	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Errorf("generateRandomScalar failed: %w", err)
	}

	aus, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
	if err != nil {
		*aus = Scalar{} // zeroization of aus
		return fmt.Errorf("generateRandomScalar failed: %w", err)
	}
	*s = *aus
	*aus = Scalar{} // zeroization of s

	return nil
}

func generateRandomScalars(scalars []Scalar) error {

	buf := make([]byte, 64)

	var s *Scalar
	var err error

	for i := 0; i < len(scalars); i++ {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return fmt.Errorf("generateRandomScalars failed: %w", err)
		}

		s, err = edwards25519.NewScalar().SetUniformBytes(buf[:])
		if err != nil {
			*s = Scalar{} // zeroization of s
			return fmt.Errorf("generateRandomScalars failed: %w", err)
		}
		scalars[i] = *s
		*s = Scalar{} // zeroization of s
	}
	return nil
}

var One = scalarOne()
var alpha = SetAlpha()
