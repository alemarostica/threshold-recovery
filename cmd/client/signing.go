package main

import (
	"bufio"
	"cmp"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/crypto"
	"time"
)

func InitializePartialSign(db *LocalDB) {
	if len(db.ReceivedShares) == 0 {
		fmt.Println("No shares found in local database.")
		return
	}

	// Select share
	fmt.Println("\nAvailable shares for recovery:")
	for i, s := range db.ReceivedShares {
		fmt.Printf("[%d] Wallet Owner: %s (Wallet Pub: %x)\n", i, s.Username, s.WalletPub)
	}
	fmt.Print("Select share index: ")
	idxStr := ReadInput(bufio.NewReader(os.Stdin))
	idx, _ := strconv.Atoi(idxStr)

	if idx < 0 || idx >= len(db.ReceivedShares) {
		fmt.Println("Invalid selection.")
		return
	}
	selected := db.ReceivedShares[idx]

	fmt.Println("Checking wallet status and joining recovery pool on server...")

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

	// unelegant polling
	for {
		var resp api.SignInitResponse
		err := callAPI("POST", "/sign/init", signedInitReq, &resp)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		if resp.Status == "ready" {
			fmt.Printf("\nThreshold reached, server confirmed session\n")

			// reconstruct data
			var part crypto.Participant
			part.SetID(crypto.ParticipantID(selected.Index))
			part.SetName(selected.Username)

			var shareScalar crypto.Scalar
			if _, err := shareScalar.SetCanonicalBytes(selected.Value); err != nil {
				fmt.Printf("Failed to load share scalar: %v\n", err)
				return
			}
			part.SetShare(shareScalar)

			var ps crypto.ParticipantSigner
			ps.SetParticipant(&part)
			ps.SetIndices(resp.VectorV)
			ps.SetLagrangeCoefficient()
			point, err := new(crypto.Point).SetBytes(resp.P)
			if err != nil {
				fmt.Printf("Failed to decode public key P: %v\n", err)
				return
			}
			ps.SetP(*point)
			fmt.Printf("Lagrange coefficients succesfully calculated.\n")

			session := &crypto.Session{}
			session.SetID(resp.SessionID)
			session.SetIndices(resp.VectorV)
			session.SetIndexHash(resp.VectorV)

			if err := ps.SetSession(session); err != nil {
				fmt.Printf("Failed to set session in signer: %v\n", err)
				return
			}

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

			nonce.SetCommit(session)
			ps.SetN(nonce)

			ci, err := nonce.GetCommit()
			if err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			var m1 crypto.MaterialToSend1
			m1.SetIndex(nonce.GetIndex())
			m1.SetCommit(ci)

			ps.SetMaterialToSend1(m1)

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

			Ri, err := nonce.GetRi()
			if err != nil {
				fmt.Printf("Signing error: %v\n", err)
				break
			}

			var m2 crypto.MaterialToSend2
			m2.SetIndex(nonce.GetIndex())
			m2.SetRi(*Ri)

			ps.SetMaterialToSend2(m2)

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

			var allM1resp api.GetM1Response
			for range ticker.C {
				if err := callAPI("POST", "/sign/getm1", signedGetM1Req, &allM1resp); err != nil {
					fmt.Printf("Could not get M1 array: %v\n", err)
					continue
				}
				break
			}

			var allM1 []crypto.MaterialToSend1
			for _, m := range allM1resp.M1Array {
				var m1 crypto.MaterialToSend1
				m1.SetIndex(m.Index)
				m1.SetCommit(m.Ci)
				allM1 = append(allM1, m1)
			}

			slices.SortFunc(allM1, func(a, b crypto.MaterialToSend1) int {
				return cmp.Compare(a.GetIndex(), b.GetIndex())
			})

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

			getM2Req := api.GetM2Request{
				Username:  db.MyIdentity.Name,
				SessionID: session.GetID(),
			}

			getM2Bytes, _ := json.Marshal(getM2Req)
			signedGetM2Req := &api.SignedGetM2Request{
				Data:      getM2Req,
				Signature: ed25519.Sign(db.MyIdentity.PrivateKey, getM2Bytes),
			}

			var allM2resp api.GetM2Response
			for range ticker.C {
				if err := callAPI("POST", "/sign/getm2", signedGetM2Req, &allM2resp); err != nil {
					fmt.Printf("Could not get M2 array: %v\n", err)
					continue
				}
				break
			}

			var allM2 []crypto.MaterialToSend2
			for _, m := range allM2resp.M2Array {
				Ri, err := new(crypto.Point).SetBytes(m.Ri)
				if err != nil {
					fmt.Printf("Failed to decode Ri for participant %d: %v\n", m.Index, err)
					return
				}

				var m2 crypto.MaterialToSend2
				m2.SetIndex(m.Index)
				m2.SetRi(*Ri)

				allM2 = append(allM2, m2)
			}

			slices.SortFunc(allM2, func(a, b crypto.MaterialToSend2) int {
				return cmp.Compare(a.GetIndex(), b.GetIndex())
			})

			// trigger verify nonce
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

			if err := ps.SetR(allM2); err != nil {
				fmt.Println("Could not set R.")
				break
			}

			// placeholder message, in a real application this would need to be established
			msg := []byte("transaction to sign")

			if err := ps.SetPartialSignature(msg); err != nil {
				fmt.Printf("Could not create partial signature: %v\n", err)
				break
			}

			zPart := ps.GetPartialSignature()
			zScalar := zPart.GetZ()

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

			for range ticker.C {
				if err := callAPI("POST", "/sign/getSign", signedGetPartSignReq, &signResp); err != nil {
					fmt.Println("Waiting for part signs...")
					continue
				} else {
					break
				}
			}

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

			if err := ps.CombineSignature(finalPartials); err != nil {
				fmt.Printf("Could not combine signatures: %v\n", err)
				break
			}

			// Brutely print it, should either save it or prettify it
			fmt.Printf("Final signature: %v\n", ps.GetSignature())

			bool, err := crypto.VerifySignature(*point, []byte("transaction to sign"), ps.GetSignature(), *session)
			if err != nil {
				fmt.Printf("Could not verify signature: %v\n", err)
				return
			}

			if bool {
				fmt.Println("Signature verified succesfully!")

				// Zeroize share in db
				// other function data should be handled by GC
				if db.ReceivedShares[idx].Value != nil {
					for i := range db.ReceivedShares[idx].Value {
						db.ReceivedShares[idx].Value[i] = 0
					}
				}

				db.ReceivedShares = append(db.ReceivedShares[:idx], db.ReceivedShares[idx+1:]...)
				SaveDB(db)
			} else {
				fmt.Println("Signature not verified.")
			}

			break
		} else if resp.Status == "waiting" {
			fmt.Println("\rWaiting for other participants...")
			time.Sleep(3 * time.Second)
		} else {
			fmt.Printf("\nABORT: %s\n", resp.Message)
			return
		}
	}
}
