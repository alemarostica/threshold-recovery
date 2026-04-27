package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

type Scalar = edwards25519.Scalar
type Matrix [][]Scalar

func scalarOne() Scalar {
	var one Scalar

	b := make([]byte, 32)
	b[0] = 1

	if _, err := one.SetCanonicalBytes(b); err != nil {
		panic(err)
	}

	return one
}

func scalarZero() Scalar {
	var z Scalar
	return z
}

func computePowers(alpha *Scalar, maxExp int) []Scalar {
	if maxExp < 0 {
		panic("negative maxExp")
	}

	powers := make([]Scalar, maxExp+1)
	one := scalarOne()
	powers[0].Set(&one)

	for i := 1; i <= maxExp; i++ {
		powers[i].Multiply(&powers[i-1], alpha)
	}

	return powers
}

// BuildM costruisce la matrice.
// k = soglia
// n = partecipanti
// colonna 0 = server
// colonne 1..n = partecipanti
//
// Ha k righe e n+1 colonne:
// riga 0: 1 1 1 ... 1
// riga 1: 1 α α ... α
// riga i>=2: 0 1 α^(i-1) α^(2(i-1)) ... α^((n-1)(i-1))
func BuildM(alpha *Scalar, k, n int) Matrix {
	if k < 2 {
		panic("k must be at least 2")
	}
	if n < k {
		panic("n must be >= k")
	}

	cols := n + 1
	maxExp := (k - 1) * (n - 1)
	powers := computePowers(alpha, maxExp)

	M := make(Matrix, k)
	for i := range M {
		M[i] = make([]Scalar, cols)
	}

	one := scalarOne()

	// Riga 0: tutti 1
	for j := 0; j < cols; j++ {
		M[0][j].Set(&one)
	}

	// Riga 1: 1, alpha, alpha, ..., alpha
	M[1][0].Set(&one)
	for j := 1; j < cols; j++ {
		M[1][j].Set(alpha)
	}

	// Righe successive
	for i := 2; i < k; i++ {
		// colonna 0 = 0, già zero value

		// colonna 1 = 1
		M[i][1].Set(&one)

		for j := 2; j < cols; j++ {
			exp := (i - 1) * (j - 1)
			M[i][j].Set(&powers[exp])
		}
	}

	return M
}

func PrintMatrix(M Matrix) {
	for i := range M {
		for j := range M[i] {
			fmt.Printf("%x ", M[i][j].Bytes())
		}
		fmt.Println()
	}
}

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
