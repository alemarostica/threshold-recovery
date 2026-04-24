package lsss

import (
	"fmt"

	"filippo.io/edwards25519"
)

type Element = edwards25519.Scalar
type Matrix [][]Element

func scalarOne() Element {
	var one Element

	b := make([]byte, 32)
	b[0] = 1

	if _, err := one.SetCanonicalBytes(b); err != nil {
		panic(err)
	}

	return one
}

func scalarZero() Element {
	var z Element
	return z
}

func computePowers(alpha *Element, maxExp int) []Element {
	if maxExp < 0 {
		panic("negative maxExp")
	}

	powers := make([]Element, maxExp+1)
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
func BuildM(alpha *Element, k, n int) Matrix {
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
		M[i] = make([]Element, cols)
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
