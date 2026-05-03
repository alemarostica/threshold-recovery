package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"
)

type NonceShare struct {
	Index ParticipantID
	ri    Scalar
	Ri    []byte
	ci    []byte
}

// commitNonce calcola H(sess.ID || sess.IndexHash || index || Ri).
func commitNonce(sess *Session, index ParticipantID, Ri []byte) []byte {
	h := sha256.New()
	h.Write(sess.ID)
	h.Write(sess.IndexHash)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(index))
	h.Write(tmp[:])

	h.Write(Ri)
	return h.Sum(nil)
}

func NewNonceShare(sess *Session, index ParticipantID) (*NonceShare, error) {
	if !sess.HasParticipant(index) {
		return nil, errors.New("participant not in session")
	}
	if sess == nil {
		return nil, errors.New("nil session")
	}

	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}

	var ri Scalar
	ri.SetUniformBytes(seed)

	var R Point
	R.ScalarBaseMult(&ri)

	Ri := R.Bytes()
	ci := commitNonce(sess, index, Ri)

	return &NonceShare{
		Index: index,
		ri:    ri,
		Ri:    Ri,
		ci:    ci,
	}, nil
}

func (n *NonceShare) Commit() []byte {
	out := make([]byte, len(n.ci))
	copy(out, n.ci)
	return out
}

func (n *NonceShare) Reveal() []byte {
	out := make([]byte, len(n.Ri))
	copy(out, n.Ri)
	return out
}

func VerifyNonce(sess *Session, index ParticipantID, commit, Ri []byte) bool {
	if !sess.HasParticipant(index) {
		return false
	}
	if sess == nil {
		return false
	}

	if len(commit) != sha256.Size {
		return false
	}

	var R edwards25519.Point
	if _, err := R.SetBytes(Ri); err != nil {
		return false
	}

	sum := commitNonce(sess, index, Ri)
	return subtle.ConstantTimeCompare(sum, commit) == 1
}

func (s *Session) HasParticipant(id ParticipantID) bool {
	for _, x := range s.Indices {
		if x == id {
			return true
		}
	}
	return false
}
