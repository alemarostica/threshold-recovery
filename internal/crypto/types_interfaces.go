package crypto

type PartialSignature struct {
	Index ParticipantID
	Z     Scalar
}

type Signature struct {
	R Point
	Z Scalar
}

type WirePartialSignature struct {
	Index []byte
	Z     []byte
}

type WireSignature struct {
	R []byte
	Z []byte
}
