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

// sortMaterials orders the nonce commitment and nonce reveal messages by
// participant index. This ensures that the two slices can be compared
// position-by-position during nonce verification.
func sortMaterials(session *SigningSession) {
	slices.SortFunc(session.Materials1, func(a, b crypto.MaterialToSend1) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})

	slices.SortFunc(session.Materials2, func(a, b crypto.MaterialToSend2) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})

	session.Sorted = true
}

// verifyNonces checks that each revealed nonce is consistent with the
// commitment previously submitted by the same participant.
//
// The server nonce is skipped because it is generated locally by the server
// and does not need to be verified through the commitment-opening mechanism.
func verifyNonces(session *SigningSession) error {
	for i := range len(session.Materials1) {
		if session.Materials1[i].GetIndex() == crypto.ServerID {
			// skip server
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

// utility that allows to find a session by its ID
func findSigningSessionByID(sessionID []byte) (*SigningSession, bool) {
	for _, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), sessionID) {
			return signingSession, true
		}
	}
	return nil, false
}

// Id equivalent to returning the number of signing participants
func expectedSigningMaterialCount(s *SigningSession) int {
	return len(s.Signer.GetIndices()) + 1 // participants + server
}
