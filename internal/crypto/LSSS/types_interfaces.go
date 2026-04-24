package lsss

type PartialSignature struct {
	Index ParticipantID
	Z     Scalar
}

type Signature struct {
	R Point
	Z Scalar
}
