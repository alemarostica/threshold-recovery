package lsss

import (
	"fmt"

	"filippo.io/edwards25519/field"
)

type Element = field.Element

type Matrix [][]Element

func computePowers(alpha *Element, maxExp int) []Element {
	if maxExp < 0 {
		panic("negative maxExp")
	}

	powers := make([]Element, maxExp+1)
	powers[0].One()

	for i := 1; i <= maxExp; i++ {
		powers[i].Multiply(&powers[i-1], alpha)
	}

	return powers
}

// BuildM costruisce la matrice.
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

	// Riga 0: tutti 1
	for j := 0; j < cols; j++ {
		M[0][j].One()
	}

	// Riga 1: 1, alpha, alpha, ..., alpha
	M[1][0].One()
	for j := 1; j < cols; j++ {
		M[1][j].Set(alpha)
	}

	// Righe successive
	for i := 2; i < k; i++ {
		// prima colonna = 0 (zero value)
		M[i][1].One()

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

func GenerateGammais(M Matrix, n int, indices []ParticipantID) []Element {
	alpha := &M[1][1]

	var one Element
	one.One()

	var alphaMinusOne Element
	alphaMinusOne.Subtract(alpha, &one) // alpha - 1

	var invAlphaMinusOne Element
	invAlphaMinusOne.Invert(&alphaMinusOne) // 1 / (alpha - 1)

	var minusOne Element
	minusOne.Negate(&one) // -1

	var coeffLambda2 Element
	coeffLambda2.Multiply(&minusOne, &invAlphaMinusOne) // -1 / (alpha - 1)

	// vettore finale lungo n, inizialmente tutto zero
	gammais := make([]Element, n)
	for i := 0; i < n; i++ {
		gammais[i].Zero()
	}

	if len(indices) == 0 {
		return gammais
	}

	// dato che indices è ordinato, l'ultimo è il massimo
	maxIdx := int(indices[len(indices)-1])

	powers := computePowers(alpha, maxIdx)

	m := len(indices)

	// xs = alpha^i per i negli indici selezionati
	xs := make([]Element, m)
	for i, idx := range indices {
		xs[i].Set(&powers[int(idx)])
	}

	// lambda puri di Lagrange
	lambdas := make([]Element, m)
	for i := 0; i < m; i++ {
		lambdas[i].One()

		for j := 0; j < m; j++ {
			if i == j {
				continue
			}

			var den Element
			den.Subtract(&xs[j], &xs[i]) // x_j - x_i

			var denInv Element
			denInv.Invert(&den)

			var factor Element
			factor.Multiply(&xs[j], &denInv) // x_j / (x_j - x_i)

			lambdas[i].Multiply(&lambdas[i], &factor)
		}
	}

	// gamma_i = (-1/(alpha-1)) * lambda_i
	// e lo mettiamo nella posizione del partecipante
	for i, idx := range indices {
		pos := int(idx) - 1 // partecipanti numerati da 1 a n
		gammais[pos].Multiply(&coeffLambda2, &lambdas[i])
	}

	return gammais
}
