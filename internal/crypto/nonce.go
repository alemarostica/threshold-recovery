package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// commitNonce calcola H(sess.ID || sess.IndexHash || index || Ri).
func commitNonce(sess *Session, index ParticipantID, Ri Point) []byte {
	h := sha256.New()
	h.Write(sess.id)
	h.Write(sess.indexHash)

	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(index))
	h.Write(tmp[:])

	h.Write(Ri.Bytes())
	return h.Sum(nil)
}

func VerifyNonceAux(sess *Session, index ParticipantID, commit []byte, Ri Point) (bool, error) {
	if sess == nil {
		return false, errors.New("VerifyNonceAux failed: sess is nil")
	}

	if !sess.HasParticipant(index) {
		return false, errors.New("VerifyNonceAux failed: index is not a participant of the session")
	}

	if len(commit) != sha256.Size {
		return false, errors.New("VerifyNonceAux failed: commit has incorrect length")
	}

	sum := commitNonce(sess, index, Ri)
	return subtle.ConstantTimeCompare(sum, commit) == 1, nil
}
