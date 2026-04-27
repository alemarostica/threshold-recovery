package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

type Session struct {
	ID        []byte
	Indices   []int
	IndexHash []byte
}

func NewSession(indices []int) (*Session, error) {
	if len(indices) < 2 {
		return nil, errors.New("need at least 2 participants")
	}
	cp := append([]int(nil), indices...) //create a copy of the slice
	sort.Ints(cp)                        // the order doesn't matter

	h := sha256.New()
	tmp := make([]byte, 4) // buffer of 4 bytes used for every index
	for _, i := range cp {
		binary.BigEndian.PutUint32(tmp, uint32(i)) // example: i=1 → 00 00 00 01
		h.Write(tmp)                               // concatenate the 4 bytes in the hashing
	}

	// creation of 32 random bytes
	sid := make([]byte, 32)
	if _, err := rand.Read(sid); err != nil {
		return nil, err
	}

	return &Session{
		ID:        sid,        // random session ID
		Indices:   cp,         // ordered list
		IndexHash: h.Sum(nil), // final digest (32 byte)
	}, nil
}
