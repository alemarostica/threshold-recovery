package main

import (
	"bufio"
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/crypto"
	"time"
)

// Initializes the threshold signature recovery procedure.
func InitializePartialSign(db *LocalDB) {
	if len(db.ReceivedShares) == 0 {
		fmt.Println("No shares found in local database.")
		return
	}

	// Display available shares stored locally.
	fmt.Println("\nAvailable shares for recovery:")
	for i, s := range db.ReceivedShares {
		fmt.Printf("[%d] Wallet Owner: %s (Wallet Pub: %x)\n", i, s.Username, s.WalletPub)
	}
	// Select the share to use for recovery.
	fmt.Print("Select share index: ")
	idxStr := ReadInput(bufio.NewReader(os.Stdin))
	idx, _ := strconv.Atoi(idxStr)

	if idx < 0 || idx >= len(db.ReceivedShares) {
		fmt.Println("Invalid selection.")
		return
	}
	selected := db.ReceivedShares[idx]

	fmt.Println("Checking wallet status and joining recovery pool on server...")

	// Build the signature initialization request.
	initReq := api.SignInitRequest{
		Requester:      db.MyIdentity.Name,
		WalletPubKey:   selected.WalletPub,
		WalletUsername: selected.Username,
		ParticipantID:  crypto.ParticipantID(selected.Index),
	}

	initBytes, _ := json.Marshal(initReq)
	signedInitReq := api.SignedSignInitRequest{
		Data:      initReq,
		Signature: ed25519.Sign(db.MyIdentity.PrivateKey, initBytes),
	}

	// Poll the server until the signing threshold is reached.
	for {
		var resp api.SignInitResponse
		err := callAPI("POST", "/sign/init", signedInitReq, &resp)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Server confirms that enough participants joined the session.
		if resp.Status == "ready" {
			fmt.Printf("\nThreshold reached, server confirmed session\n")

			var err error

			// Reconstruct participant data from the stored share
			var part crypto.Participant
			err = part.SetID(crypto.ParticipantID(selected.Index))
			if err != nil {
				fmt.Printf("Failed to set participant ID: %v\n", err)
				return
			}
			err = part.SetName(selected.Username)
			if err != nil {
				fmt.Printf("Failed to set participant name: %v\n", err)
				return
			}

			// Restore the scalar value associated with the participant share.
			var shareScalar crypto.Scalar
			if _, err := shareScalar.SetCanonicalBytes(selected.Value); err != nil {
				fmt.Printf("Failed to load share scalar: %v\n", err)
				return
			}

			err = part.SetShare(shareScalar)
			if err != nil {
				fmt.Printf("Failed to set participant share: %v\n", err)
				return
			}

			// Initialize the participant signer.
			var ps crypto.ParticipantSigner
			err = ps.SetParticipant(&part)
			if err != nil {
				fmt.Printf("Failed to set signer participant: %v\n", err)
				return
			}
			err = ps.SetIndices(resp.VectorV)
			if err != nil {
				fmt.Printf("Failed to set signer indices: %v\n", err)
				return
			}

			// Initialize the participant signer.
			err = ps.SetLagrangeCoefficient()
			if err != nil {
				fmt.Printf("Failed to set Lagrange coefficients: %v\n", err)
				return
			}

			fmt.Printf("Lagrange coefficients succesfully calculated.\n")

			// Decode the aggregated public point.
			point, err := new(crypto.Point).SetBytes(resp.P)
			if err != nil {
				fmt.Printf("Failed to decode public key P: %v\n", err)
				return
			}

			err = ps.SetP(*point)
			if err != nil {
				fmt.Printf("Failed to public point: %v\n", err)
				return
			}

			// Create and configure the signing session.
			session := &crypto.Session{}
			err = session.SetID(resp.SessionID)
			if err != nil {
				fmt.Printf("Failed to set session ID: %v\n", err)
				return
			}
			err = session.SetIndices(resp.VectorV)
			if err != nil {
				fmt.Printf("Failed to set session indices: %v\n", err)
				return
			}
			err = session.SetIndexHash(resp.VectorV)
			if err != nil {
				fmt.Printf("Failed to set session IndexHash: %v\n", err)
				return
			}

			if err := ps.SetSession(session); err != nil {
				fmt.Printf("Failed to set session in signer: %v\n", err)
				return
			}

			// Generate nonce material for the signing round.
			var nonce crypto.NonceShare
			if err := nonce.SetIndex(ps.GetParticipant().GetID()); err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			if err := nonce.Setri(); err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			if err := nonce.SetRi(); err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			err = nonce.SetCommit(session)
			if err != nil {
				fmt.Printf("Failed to set nonce commit on session: %v\n", err)
				return
			}
			err = ps.SetN(nonce)
			if err != nil {
				fmt.Printf("Failed to set signer nonce: %v\n", err)
				return
			}

			// Build the first signing message (M1).
			ci, err := nonce.GetCommit()
			if err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			var m1 crypto.MaterialToSend1
			err = m1.SetIndex(nonce.GetIndex())
			if err != nil {
				fmt.Printf("Failed to m1 index: %v\n", err)
				return
			}
			err = m1.SetCommit(ci)
			if err != nil {
				fmt.Printf("Failed to set m1 commit: %v\n", err)
				return
			}

			err = ps.SetMaterialToSend1(m1)
			if err != nil {
				fmt.Printf("Failed to signer m1: %v\n", err)
				return
			}

			// Send M1 to the server.
			setM1Req := api.SetM1Request{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
				Ci:        m1.GetCommit(),
				Index:     m1.GetIndex(),
			}

			setM1Bytes, _ := json.Marshal(setM1Req)
			signedSetM1Req := &api.SignedSetM1Request{
				Data:      setM1Req,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, setM1Bytes),
			}

			if err := callAPI("POST", "/sign/setm1", signedSetM1Req, nil); err != nil {
				fmt.Printf("Could not send M1: %v\n", err)
				return
			}

			// Build the second signing message (M2).
			Ri, err := nonce.GetRi()
			if err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			var m2 crypto.MaterialToSend2
			err = m2.SetIndex(nonce.GetIndex())
			if err != nil {
				fmt.Printf("Failed to set m1 index: %v\n", err)
				return
			}
			err = m2.SetRi(*Ri)
			if err != nil {
				fmt.Printf("Failed to m2 Ri: %v\n", err)
				return
			}

			err = ps.SetMaterialToSend2(m2)
			if err != nil {
				fmt.Printf("Failed to signer m2: %v\n", err)
				return
			}

			// Request all M1 messages from the server.
			getM1Req := api.GetM1Request{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
			}

			getM1Bytes, _ := json.Marshal(getM1Req)
			signedGetM1Req := &api.SignedGetM1Request{
				Data:      getM1Req,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, getM1Bytes),
			}

			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()

			// Wait until all M1 messages are available.
			var allM1resp api.GetM1Response
			for range ticker.C {
				if err := callAPI("POST", "/sign/getm1", signedGetM1Req, &allM1resp); err != nil {
					fmt.Printf("Could not get M1 array: %v\n", err)
					continue
				}
				break
			}

			// Reconstruct all received M1 messages.
			var allM1 []crypto.MaterialToSend1
			for _, m := range allM1resp.M1Array {
				var m1 crypto.MaterialToSend1
				err = m1.SetIndex(m.Index)
				if err != nil {
					fmt.Printf("Failed to set m1 index while rebuilding allM1: %v\n", err)
					return
				}
				err = m1.SetCommit(m.Ci)
				if err != nil {
					fmt.Printf("Failed to set m1 commit while rebulding allM1: %v\n", err)
					return
				}
				allM1 = append(allM1, m1)
			}

			// Sort M1 messages by participant index.
			slices.SortFunc(allM1, func(a, b crypto.MaterialToSend1) int {
				return cmp.Compare(a.GetIndex(), b.GetIndex())
			})

			// Send M2 to the server.
			RiPoint := m2.GetRi()
			setM2Req := api.SetM2Request{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
				Ri:        RiPoint.Bytes(),
				Index:     m2.GetIndex(),
			}

			setM2Bytes, _ := json.Marshal(setM2Req)
			signedSetM2Req := &api.SignedSetM2Request{
				Data:      setM2Req,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, setM2Bytes),
			}

			for err := callAPI("POST", "/sign/setm2", signedSetM2Req, nil); err != nil; {
				fmt.Printf("Could not send M2: %v\n", err)
				return
			}

			// Request all M2 messages from the server
			getM2Req := api.GetM2Request{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
			}

			getM2Bytes, _ := json.Marshal(getM2Req)
			signedGetM2Req := &api.SignedGetM2Request{
				Data:      getM2Req,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, getM2Bytes),
			}

			// Wait until all M2 messages are available.
			var allM2resp api.GetM2Response
			for range ticker.C {
				if err := callAPI("POST", "/sign/getm2", signedGetM2Req, &allM2resp); err != nil {
					fmt.Printf("Could not get M2 array: %v\n", err)
					continue
				}
				break
			}

			// Reconstruct all received M2 messages.
			var allM2 []crypto.MaterialToSend2
			for _, m := range allM2resp.M2Array {
				Ri, err := new(crypto.Point).SetBytes(m.Ri)
				if err != nil {
					fmt.Printf("Failed to decode Ri for participant %d: %v\n", m.Index, err)
					return
				}

				var m2 crypto.MaterialToSend2
				err = m2.SetIndex(m.Index)
				if err != nil {
					fmt.Printf("Failed to set m2 index while reconstructing allM2: %v\n", err)
					return
				}
				err = m2.SetRi(*Ri)
				if err != nil {
					fmt.Printf("Failed to set m2 Ri while reconstructing allM2: %v\n", err)
					return
				}

				allM2 = append(allM2, m2)
			}

			// Sort M2 messages by participant index.
			slices.SortFunc(allM2, func(a, b crypto.MaterialToSend2) int {
				return cmp.Compare(a.GetIndex(), b.GetIndex())
			})

			// Verify consistency between received M1 and M2 messages.
			if len(allM1) != len(allM2) {
				fmt.Println("Haven't received the same number of M1s and M2s.")
				continue
			}

			for i := range allM1 {
				if allM1[i].GetIndex() != allM2[i].GetIndex() {
					fmt.Printf("Nonce material index mismatch: M1 has %d, M2 has %d\n",
						allM1[i].GetIndex(), allM2[i].GetIndex())
					return
				}

				ok, err := ps.VerifyNonce(&allM1[i], &allM2[i])
				if err != nil {
					fmt.Printf("Error verifying nonce for participant %d: %v\n", allM1[i].GetIndex(), err)
					return
				}

				if !ok {
					fmt.Printf("Nonce for participant %d did not verify.\n", allM1[i].GetIndex())
					continue
				}
			}

			// Compute the aggregated nonce R.
			if err := ps.SetR(allM2); err != nil {
				fmt.Println("Could not set R.")
				break
			}

			// Placeholder message to be signed.
			msg := []byte("transaction to sign")

			// Generate the participant partial signature.
			if err := ps.SetPartialSignature(msg); err != nil {
				fmt.Printf("Could not create partial signature: %v\n", err)
				break
			}

			zPart := ps.GetPartialSignature()
			zScalar := zPart.GetZ()

			// Send the partial signature to the server.
			partSignReq := api.SendPartialSign{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
				PartialSignature: api.PartialSigMessage{
					ParticipantID: zPart.GetIndex(),
					Z:             zScalar.Bytes(),
				},
			}

			partSignBytes, _ := json.Marshal(partSignReq)
			signedPartSignReq := &api.SignedSendPartialSign{
				Data:      partSignReq,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, partSignBytes),
			}

			if err = callAPI("POST", "/sign/part", signedPartSignReq, nil); err != nil {
				fmt.Printf("Could not send partial signature: %v\n", err)
				break
			}

			// Request all partial signatures from the server.
			getPartSignReq := api.GetPartialSigns{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
			}

			getPartSignBytes, _ := json.Marshal(getPartSignReq)
			signedGetPartSignReq := &api.SignedGetPartialSigns{
				Data:      getPartSignReq,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, getPartSignBytes),
			}

			var signResp api.GetPartialSignsResp

			// Wait until all partial signatures are available.
			for range ticker.C {
				if err := callAPI("POST", "/sign/getSign", signedGetPartSignReq, &signResp); err != nil {
					fmt.Println("Waiting for part signs...")
					continue
				} else {
					break
				}
			}

			// Reconstruct partial signatures received from the server.
			var finalPartials []crypto.PartialSignature
			for _, pDto := range signResp.PartialSignatures {
				var z crypto.Scalar
				if _, err := z.SetCanonicalBytes(pDto.Z); err != nil {
					fmt.Printf("Invalid Z scalar from server: %v\n", err)
					return
				}

				var partSig crypto.PartialSignature
				partSig.SetIndex(&pDto.ParticipantID)
				partSig.SetZ(&z)
				finalPartials = append(finalPartials, partSig)
			}

			// Combine all partial signatures into the final signature.
			if err := ps.CombineSignature(finalPartials); err != nil {
				fmt.Printf("Could not combine signatures: %v\n", err)
				break
			}

			// Print the generated signature.
			fmt.Printf("Final signature: %v\n", ps.GetSignature())

			// Verify the final aggregated signature.
			bool, err := crypto.VerifySignature(*point, []byte("transaction to sign"), ps.GetSignature(), *session)
			if err != nil {
				fmt.Printf("Could not verify signature: %v\n", err)
				return
			}

			if bool {
				fmt.Println("Signature verified succesfully!")

				// Zeroize the consumed share from local memory.
				if db.ReceivedShares[idx].Value != nil {
					clear(db.ReceivedShares[idx].Value)
					runtime.KeepAlive(db.ReceivedShares)
				}

				// Remove the used share from the local database.
				db.ReceivedShares = append(db.ReceivedShares[:idx], db.ReceivedShares[idx+1:]...)
				SaveDB(db)
			} else {
				fmt.Println("Signature not verified.")
			}

			break
		} else if resp.Status == "waiting" {
			// Waiting for additional participants to join.
			fmt.Println("\rWaiting for other participants...")
			time.Sleep(3 * time.Second)
		} else {
			// Abort the signing procedure if the server rejects the request.
			fmt.Printf("\nABORT: %s\n", resp.Message)
			return
		}
	}
}
