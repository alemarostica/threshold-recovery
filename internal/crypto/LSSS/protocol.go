package lsss

import "filippo.io/edwards25519"

type ParticipantID int

type PublicParams struct {
	K int // soglia
	N int // numero di partecipanti (utenti)
	M Matrix
}

type DealerShares struct {
	ServerShare       Element   // beta1
	ParticipantShares []Element // gamma1,...,gamman
}

type SecretVector struct {
	S  Element   // segreto
	R2 Element   // coefficiente per p1
	T  []Element // t1,...,t_{k-1}
}

type ReconstructionSet struct {
	Indices []ParticipantID
	Shares  []Element
}

type Commitments struct {
	// da decidere in base a come rappresenti g^x
	// per ora lo lasciamo astratto
}

type Protocol struct {
	PP    PublicParams
	Alpha Element
}

func NewProtocol(alpha *Element, k, n int) *Protocol {
	return &Protocol{
		PP: PublicParams{
			K: k,
			N: n,
			M: BuildM(alpha, k, n),
		},
		Alpha: *alpha,
	}
}

func (p *Protocol) Distribute(v SecretVector) DealerShares {
	// beta1 = s + r2
	var beta1 Element
	beta1.Add(&v.S, &v.R2)

	var beta2 Element
	beta2.Multiply(&v.R2, &p.Alpha)
	beta2.Add(&beta2, &v.S)

	// gamma_i = beta2 + t_1*alpha^(i-1) + t_2*alpha^(2(i-1)) + ... + t_{k-1}*alpha^((k-1)(i-1))
	participantShares := make([]Element, p.PP.N)
	for i := 0; i < p.PP.N; i++ {
		var share Element
		share.Set(&beta2)
		for j := 0; j < p.PP.K-1; j++ {
			var term Element
			term.Multiply(&v.T[j], &p.PP.M[j+2][i+1]) // M[j+2][i+1] = alpha^((j)(i))
			share.Add(&share, &term)
		}
		participantShares[i].Set(&share)
	}

	return DealerShares{
		ServerShare:       beta1,
		ParticipantShares: participantShares,
	}

}

func CoefficientsForSecret(M Matrix, n int, indices []ParticipantID) []Element {
	alpha := &M[1][1]

	one := scalarOne()

	var alphaMinusOne Element
	alphaMinusOne.Subtract(alpha, &one) // alpha - 1

	var invAlphaMinusOne Element
	invAlphaMinusOne.Invert(&alphaMinusOne) // 1 / (alpha - 1)

	var minusOne Element
	minusOne.Negate(&one) // -1

	var coeffLambda2 Element
	coeffLambda2.Multiply(&minusOne, &invAlphaMinusOne) // -1 / (alpha - 1)

	// vettore finale lungo n, inizialmente tutto zero
	cis := make([]Element, n)
	for i := 0; i < n; i++ {
		cis[i].Set(edwards25519.NewScalar()) // zero
	}

	if len(indices) == 0 {
		return cis
	}

	// indices è ordinato, quindi l'ultimo è il massimo
	maxIdx := int(indices[len(indices)-1])
	if maxIdx <= 0 || maxIdx > n {
		panic("participant index out of range")
	}

	powers := computePowers(alpha, maxIdx)

	m := len(indices)

	// xs = alpha^i per i negli indici selezionati
	xs := make([]Element, m)
	for i, idx := range indices {
		if int(idx) <= 0 || int(idx) > n {
			panic("participant index out of range")
		}
		xs[i].Set(&powers[int(idx)])
	}

	// lambda puri di Lagrange:
	// lambda_i = Π_{j != i} x_j / (x_j - x_i)
	lambdas := make([]Element, m)
	for i := 0; i < m; i++ {
		lambdas[i].Set(&one)

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

	// c_i = (-1/(alpha-1)) * lambda_i
	// e lo mettiamo nella posizione del partecipante
	for i, idx := range indices {
		pos := int(idx) - 1 // partecipanti numerati da 1 a n
		cis[pos].Multiply(&coeffLambda2, &lambdas[i])
	}

	return cis
}

// prova
