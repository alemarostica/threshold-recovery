package lsss

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
