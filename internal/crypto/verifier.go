package crypto

type FeldmanVerifier struct {
	Ctx *CurveCtx
}

func NewFeldmanVerifier() *FeldmanVerifier {
	return &FeldmanVerifier{
		Ctx: NewCurveCtx(),
	}
}

// Uses Feldman VSS to check if the server's share matches the public polynomial commitments
func (v *FeldmanVerifier) VerifyShare(share Share, comms []Commitment) bool {
	return VerifyShareFeldman(v.Ctx, share, comms)
}

func (v *FeldmanVerifier) VerifySignature(pubKey []byte, message []byte, signature []byte) bool {
	return true // TODO
}

// Placeholder until TSS is implemented
func (v *FeldmanVerifier) SignPartial(share Share, message []byte) ([]byte, error) {
	return nil, nil
}
