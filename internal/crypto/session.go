package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

func NewSession(indices []ParticipantID, k, n int) (*Session, error) {
	cp, err := NormalizeParticipantIDs(indices, n)
	if err != nil {
		return nil, err
	}

	if len(cp) != k {
		return nil, errors.New("invalid number of signers")
	}

	h := sha256.New()
	tmp := make([]byte, 4)

	for _, id := range cp {
		binary.BigEndian.PutUint32(tmp, uint32(id))
		h.Write(tmp)
	}

	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		return nil, err
	}

	return &Session{
		id:        sid,
		indices:   cp,
		indexHash: h.Sum(nil),
	}, nil
}
