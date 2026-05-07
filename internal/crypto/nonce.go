package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"

	"filippo.io/edwards25519"
)

// commitNonce calcola H(sess.ID || sess.IndexHash || index || Ri).
func commitNonce(sess *Session, index ParticipantID, Ri []byte) []byte {
	h := sha256.New()
	h.Write(sess.id)
	h.Write(sess.indexHash)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(index))
	h.Write(tmp[:])

	h.Write(Ri)
	return h.Sum(nil)
}

func VerifyNonceAux(sess *Session, index ParticipantID, commit, Ri []byte) bool {
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
