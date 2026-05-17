package api

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"threshold-recovery/internal/crypto"
)

type PendingSign struct {
	WalletPubKeyHex string
	Threshold       int
	TotalN          int
	Participants    []crypto.ParticipantID
	Usernames       []string
}

type SigningSession struct {
	Signer            crypto.ServerSigner
	Materials1        []crypto.MaterialToSend1
	Materials2        []crypto.MaterialToSend2
	PartialSignatures []crypto.PartialSignature
	Message           []byte
	Sorted            bool
	Verified          bool
	Signature         crypto.Signature
	WalletPubKeyHex   string
	WalletOwner       string
	RetrievedBy       map[string]bool
}

// is it necessary?
func sortMaterials(session *SigningSession) {
	slices.SortFunc(session.Materials1, func(a, b crypto.MaterialToSend1) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})

	slices.SortFunc(session.Materials2, func(a, b crypto.MaterialToSend2) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})

	session.Sorted = true
}

func verifyNonces(session *SigningSession) error {
	for i := range len(session.Materials1) {
		if i == 0 {
			// skip server?
			continue
		}

		ok, err := session.Signer.VerifyNonce(&session.Materials1[i], &session.Materials2[i])
		if err != nil {
			return err
		}

		if !ok {
			return fmt.Errorf("Nonces for participant %d did not verify.\n", i)
		}
	}

	session.Verified = true

	return nil
}

func findSigningSessionByID(sessionID []byte) (*SigningSession, bool) {
	for _, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), sessionID) {
			return signingSession, true
		}
	}
	return nil, false
}

func expectedSigningMaterialCount(s *SigningSession) int {
	return len(s.Signer.GetIndices()) + 1 // participants + server
}
