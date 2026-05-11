package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// commitNonce computes the first-round nonce commitment.
//
// In the signing protocol, signer_i first sends a commitment to its public
// nonce R_i and reveals R_i only in the next round. The session data and signer
// index are included to bind the commitment to this signing execution.
// commitNonce computes c_i = H(sessionID || indexHash || i || R_i).
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

// VerifyNonceAux checks that a revealed R_i matches the first-round commitment.
//
// This prevents a signer from choosing or changing its nonce after seeing the
// nonces revealed by the other active signers.
func VerifyNonceAux(sess *Session, index ParticipantID, commit []byte, Ri Point) (bool, error) {
	if sess == nil {
		return false, errors.New("VerifyNonceAux failed: sess is nil")
	}

	if !sess.HasSigner(index) {
		return false, errors.New("VerifyNonceAux failed: index is not a participant of the session")
	}

	if len(commit) != sha256.Size {
		return false, errors.New("VerifyNonceAux failed: commit has incorrect length")
	}

	sum := commitNonce(sess, index, Ri)
	return subtle.ConstantTimeCompare(sum, commit) == 1, nil
}
