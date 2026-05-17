package main

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/keyexchange"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// Ricorda lo stato delle sessioni di handshake in corso
var activeSessions = make(map[string]*keyexchange.SessionState)

// Salva temporaneamente le share in attesa che l'handshake finisca
var pendingMessages = make(map[string][]byte)

// Sessioni del nonce exchange
var activeNonceSessions = make(map[string]*keyexchange.SessionState)

// Messaggi pending dei nonce
var pendingNonces = make(map[string][]byte)

// Configuration
const (
	ServerURL = "https://localhost:8443"
	DBFile    = "client_db.json"
)

type Share struct {
	Value     []byte            `json:"scalar"`
	Index     int               `json:"index"`
	Username  string            `json:"username"`
	WalletPub ed25519.PublicKey `json:"wallet_pub_key"`
}

type EncryptedDB struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Local storage models
type LocalDB struct {
	MyIdentity     *Identity         `json:"my_identity"`
	Contacts       map[string]string `json:"contacts"`
	MyWallets      map[string]string `json:"my_wallets"`
	DirectoryEpoch uint64            `json:"directory_epoch"`
	ServerPub      ed25519.PublicKey `json:"server_pub"`
	ReceivedShares []Share           `json:"shares"`
	SessionKey     []byte            `json:"-"`
	Salt           []byte            `json:"-"`
}

type Identity struct {
	Name       string             `json:"name"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

type ShareSender struct{}

func (cs *ShareSender) Send(msg keyexchange.Message) error {
	err := callAPI("POST", "/shares/send", msg, nil)
	if err != nil {
		return fmt.Errorf("failed to send relay message: %v", err)
	}
	return nil
}

type NonceSender struct{}

func (ns *NonceSender) Send(msg keyexchange.Message) error {
	err := callAPI("POST", "/nonces/send", msg, nil)
	if err != nil {
		return fmt.Errorf("failed to send nonce message: %v", err)
	}
	return nil
}

type ClientDirectory struct {
	DirectoryEpoch uint64            `json:"directory_epoch"`
	MyIdentity     *Identity         `json:"identity"`
	Contacts       map[string]string `json:"contacts"`
}

func (cd *ClientDirectory) GetPublicKey(userID string) (ed25519.PublicKey, error) {
	if userID == cd.MyIdentity.Name {
		return cd.MyIdentity.PublicKey, nil
	}

	hexKey, exists := cd.Contacts[userID]
	if !exists {
		return nil, fmt.Errorf("user %s not found in local contacts", userID)
	}

	return hex.DecodeString(hexKey)
}

func (cd *ClientDirectory) GetEpoch() uint64 {
	return cd.DirectoryEpoch
}

// Main
func main() {
	reader := bufio.NewReader(os.Stdin)

	db, err := initDB(reader)
	if err != nil {
		fmt.Printf("Startup failed: %v\n", err)
		return
	}

	dir := &ClientDirectory{
		MyIdentity:     db.MyIdentity,
		DirectoryEpoch: db.DirectoryEpoch,
		Contacts:       db.Contacts,
	}

	startMessagePoller(db, dir)
	if !(db.MyIdentity == nil) && !(len(db.MyWallets) == 0) {
		pingAllWallets(db)
	}

	// Loop
	for {
		printMenu(db)
		fmt.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			showIdentity(db)
		case "2":
			addContact(reader, db)
		case "3":
			createWallet(reader, db)
		case "4":
			initializePartialSign(db)
		case "5":
			listCreatedWallets(db)
		case "0":
			fmt.Println("Goodbye.")
			if !(db.MyIdentity == nil) && !(len(db.MyWallets) == 0) {
				pingAllWallets(db)
			}
			return
		default:
			fmt.Println("Invalid Option.")
		}
		fmt.Println("\nPress Enter to continue...")
		reader.ReadString('\n')
	}
}

func callAPI(method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		bz, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal error: %w", err)
		}
		body = bytes.NewBuffer(bz)
	}

	req, err := http.NewRequest(method, ServerURL+path, body)
	if err != nil {
		return err
	}

	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	// I think this is needed with self signed certificates
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(errMsg))
	}

	if out != nil {
		if w, ok := out.(io.Writer); ok {
			defer resp.Body.Close()
			_, err := io.Copy(w, resp.Body)
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(out)
	}

	resp.Body.Close()
	return nil
}

func startMessagePoller(db *LocalDB, dir *ClientDirectory) {
	ticker := time.NewTicker(3 * time.Second) // Frequenza di polling
	go func() {
		for range ticker.C {
			pollRelay(db, dir)
		}
	}()
}

func pollRelay(db *LocalDB, dir *ClientDirectory) {
	if dir.MyIdentity == nil {
		return // skippa se non registrato
	}

	var msgs []keyexchange.Message
	err := callAPI("GET", "/shares/messages?user_id="+dir.MyIdentity.Name, nil, &msgs)
	if err != nil {
		fmt.Printf("Failed to fetch messages from relay: %v\n", err)
		return
	}
	if len(msgs) == 0 {
		return // no messages
	}

	provider := keyexchange.NewDefaultProvider()
	sender := &ShareSender{}
	myPriv := dir.MyIdentity.PrivateKey

	for _, msg := range msgs {
		fmt.Printf("\n[RELAY] Received message %s from %s\n", msg.Type, msg.From)

		switch msg.Type {
		case keyexchange.M1:
			state, err := keyexchange.HandleM1(msg, dir.MyIdentity.Name, provider, dir, sender, myPriv)
			if err != nil {
				fmt.Printf("[RELAY] Error: failed to handle M1 message from %s: %v\n", msg.From, err)
				continue
			}
			activeSessions[msg.From] = state
			fmt.Printf("[RELAY] Succesfully sent M2 to %s\n", msg.From)
		case keyexchange.M2:
			// We are dealer, friend responded
			// retrieve the session state
			state, ok := activeSessions[msg.From]
			if !ok {
				fmt.Printf("Error: no active session found for M2 from %s\n", msg.From)
				continue
			}

			// Retrieve the pending share
			shareBlob, ok := pendingMessages[msg.From]
			if !ok {
				fmt.Printf("No pending share to send to %s\n", msg.From)
				continue
			}

			// Process M2 and send M3 with share
			err := keyexchange.HandleM2AsInitiator(state, msg, provider, dir, sender, shareBlob)
			if err != nil {
				fmt.Printf("Failed to handle M2 from %s: %v\n", msg.From, err)
				continue
			}

			fmt.Printf("M2 verified. Sent M3 to %s.\n", msg.From)

			delete(activeSessions, msg.From)
			delete(pendingMessages, msg.From)
		case keyexchange.M3:
			// We are shareholder, dealer sent us encrypted share with M3
			state, ok := activeSessions[msg.From]
			if !ok {
				fmt.Printf("No active session found for M3 from %s\n", msg.From)
				continue
			}

			// Decrypt share
			plaintextMessage, err := keyexchange.HandleM3(state, msg, provider)
			if err != nil {
				fmt.Printf("Failed to decrypt M3 from %s: %v\n", msg.From, err)
				continue
			}

			// We received the share
			fmt.Printf("Succesfully received share from %s.", msg.From)

			// Temporary print
			os.WriteFile("test.bin", plaintextMessage, 0644)
			message, err := keyexchange.UnmarshalShare(plaintextMessage)
			if err != nil {
				fmt.Printf("Could not unmarshal the share: %v\n", err)
				continue
			}

			var partShare crypto.Scalar
			if _, err := partShare.SetCanonicalBytes(message.Share); err != nil {
				fmt.Printf("Invalid share: %v", err)
				continue
			}

			var rebuiltCommitments crypto.Commitment
			commitmentsMalformed := false

			for _, b := range message.Commitments {
				p, err := edwards25519.NewIdentityPoint().SetBytes(b)
				if err != nil {
					fmt.Printf("Invalid commitment encoding: %v\n", err)
					commitmentsMalformed = true
					break
				}
				rebuiltCommitments = append(rebuiltCommitments, *p)
			}

			if commitmentsMalformed {
				fmt.Println("Discarding malformed share message.")
				continue
			}

			// Verification
			var part crypto.Participant
			part.SetID(crypto.ParticipantID(message.Index))
			part.SetShare(partShare)
			part.SetName(message.Username)
			// What? id di tutti i participant? Non é semplicmente un array [1..n]?
			if ok, err := part.VerifyConsistency(rebuiltCommitments); err != nil {
				fmt.Printf("Error while verifying share: %v\n", err)
				continue
			} else if !ok {
				fmt.Printf("Share is not consistent?")
				continue
			}

			share := Share{
				Username:  message.Username,
				WalletPub: message.WalletPub,
				// Still la stessa roba del trasferimento di edwards25519 structs
				// I field sono privati quindi non se li caga nessuna funzione che non sia
				// un metodo sullo struct, bisogna quindi convertire in bytes
				Value: partShare.Bytes(),
				Index: message.Index,
			}

			db.ReceivedShares = append(db.ReceivedShares, share)

			delete(activeSessions, msg.From)
			saveDB(db)
		}

		// the prompt
		fmt.Print("\nSelect an option: ")
	}
}

func pingAllWallets(db *LocalDB) {
	for walletPubHex := range db.MyWallets {
		walletPubKey, err := hex.DecodeString(walletPubHex)
		if err != nil {
			continue
		}

		req := api.LivenessRequest{
			Username: db.MyIdentity.Name,
			// boh qua dipende da come viene fatto tss poi
			PublicKey: walletPubKey,
			Timestamp: time.Now().Unix(),
		}

		reqBytes, _ := json.Marshal(req)
		sign := ed25519.Sign(db.MyIdentity.PrivateKey, reqBytes)

		signedReq := api.SignedLivenessRequest{
			Data:      req,
			Signature: sign,
		}

		err = callAPI("POST", "/liveness", signedReq, nil)
		if err != nil {
			fmt.Printf("Failed liveness ping")
			continue
		}
	}
}

func initializePartialSign(db *LocalDB) {
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
	idxStr := readInput(bufio.NewReader(os.Stdin))
	idx, _ := strconv.Atoi(idxStr)

	if idx < 0 || idx >= len(db.ReceivedShares) {
		fmt.Println("Invalid selection.")
		return
	}
	selected := db.ReceivedShares[idx]

	fmt.Println("Checking wallet status and joining recovery pool on server...")

	fmt.Printf("selected share pub: %s\n", hex.EncodeToString(selected.WalletPub))

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
			fmt.Printf("Vector v (indices): %v\n", resp.VectorV)

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
					fmt.Println("waiting for part signs...")
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
			fmt.Printf("Final signature: %v", ps.GetSignature())

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
				saveDB(db)
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

func createWallet(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- [CREATE NEW THRESHOLD WALLET] ---")

	// Get n and k
	// Remember that one share goes to the server, this n is just the friends
	fmt.Print("Enter number of shares for friends, at least 2 (n): ")
	n, err := strconv.Atoi(readInput(r))
	if err != nil || n < 2 {
		fmt.Println("Error: n must be a number >= 2.")
		return
	}

	// Same as with n, this is just the friends, server would constitute one shareholder
	fmt.Print("Enter threshold, at least 2 (k): ")
	k, err := strconv.Atoi(readInput(r))
	if err != nil || k < 1 || k > n {
		fmt.Printf("Error: k must be between 1 and %d\n", n)
		return
	}

	fmt.Println("\nYour contacts:")
	var names []string
	for name := range db.Contacts {
		names = append(names, name)
		fmt.Printf("- %s\n", name)
	}

	fmt.Printf("Enter %d friend names, comma separated: ", n)
	chosenStr := readInput(r)
	chosenStr = strings.TrimSpace(chosenStr)
	rawChosenNames := strings.Split(chosenStr, ",")

	var chosenNames []string
	var friendKeys [][]byte

	for _, cn := range rawChosenNames {
		name := strings.TrimSpace(cn)
		if name == "" {
			fmt.Println("Error: please provide valid contact names separated by commas.")
			return
		}

		keyHex, ok := db.Contacts[name]
		if !ok {
			fmt.Printf("Error: Contact '%s' not found.\n", name)
			return
		}

		kb, err := hex.DecodeString(keyHex)
		if err != nil {
			fmt.Printf("Error: stored public key for contact '%s' is invalid.\n", name)
			return
		}

		chosenNames = append(chosenNames, name)
		friendKeys = append(friendKeys, kb)
	}

	if len(friendKeys) != n {
		fmt.Printf("Error: You must select exactly %d friends.\n", n)
		return
	}

	// Timeout
	fmt.Print("Enter inactivity timeout (e.g. 30s, 24h, 720h): ")
	timeoutDur, err := time.ParseDuration(readInput(r))
	if err != nil {
		fmt.Println("Error: Invalid duration format. Use 's', 'm' or 'h'.")
		return
	}

	fmt.Print("Give this wallet a local nickname: ")
	walletName := readInput(r)

	// We generate an ed25519 key
	// In a real application the user would input his wallet's key
	// C'mon, this is just a demo
	walletPubkey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate wallet keys: %v\n", err)
		return
	}

	// TODO: il secret scalar non lo devo fare con la privKey del wallet?

	var dealer crypto.Dealer
	dealer.SetTsParameters(n, k)
	dealer.SetSecret()
	dealer.SetFriends(chosenNames)
	dealer.SetCommAndShares()

	commPoints := *dealer.GetComm()
	commBytes := make([][]byte, len(commPoints))
	for i, p := range commPoints {
		commBytes[i] = p.Bytes()
	}

	serverShare := dealer.GetServerShare()
	var serverShareBytes = serverShare.Bytes()

	secret := dealer.GetSecret()
	point := *new(crypto.Point).ScalarBaseMult(&secret)

	regReq := api.RegisterRequest{
		Username:            db.MyIdentity.Name,
		PublicKey:           walletPubkey,
		ServerShare:         serverShareBytes,
		PubParams:           dealer.GetTsParameters(),
		Commitments:         commBytes,
		InactivityThreshold: timeoutDur,
		P:                   point.Bytes(),
	}

	dataBytes, _ := json.Marshal(regReq)
	sign := ed25519.Sign(db.MyIdentity.PrivateKey, dataBytes)

	req := api.SignedRegisterRequest{
		Data:      regReq,
		Signature: sign,
	}

	if err := callAPI("POST", "/register", req, nil); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		return
	}

	provider := keyexchange.NewDefaultProvider()
	dir := &ClientDirectory{
		MyIdentity:     db.MyIdentity,
		DirectoryEpoch: db.DirectoryEpoch,
		Contacts:       db.Contacts,
	}
	sender := &ShareSender{}
	myPriv := db.MyIdentity.PrivateKey

	fmt.Println("Starting key exchange...")

	for i, cn := range chosenNames {
		friendName := strings.TrimSpace(cn)

		if friendName == "" {
			fmt.Println("Error: please provide valid contact names separated by commas.")
			return
		}
		share_1 := dealer.GetParticipantShares(i)
		shareBytes := share_1.Bytes()

		// edwards25519's struct fields are private, have to reverse unfortunately
		// or they can't be marshaled
		share := keyexchange.ShareMessage{
			Index:       i + 1,
			Share:       shareBytes,
			Commitments: commBytes,
			PubParams:   dealer.GetTsParameters(),
			Username:    db.MyIdentity.Name,
			WalletPub:   walletPubkey,
		}

		shareBlob, err := keyexchange.MarshalShare(share)
		if err != nil {
			fmt.Printf("Marshal error for share %s: %v\n", friendName, err)
			continue
		}

		pendingMessages[friendName] = shareBlob

		state, err := keyexchange.StartAsInitiator(db.MyIdentity.Name, friendName, provider, dir, sender, myPriv)
		if err != nil {
			fmt.Printf("Failed handshake with %s: %v\n", friendName, err)
			continue
		}

		activeSessions[friendName] = state
		fmt.Printf("Sent M1 messages to %s\n", friendName)
	}

	wHex := hex.EncodeToString(walletPubkey)
	db.MyWallets[wHex] = walletName
	saveDB(db)

	// zeroize the secret
	zero := make([]byte, 64)
	secret.SetCanonicalBytes(zero)

	fmt.Println("\nSUCCESS: Wallet registered on the server.")
	fmt.Printf("WALLET PUBLIC KEY (HEX): %s\n", wHex)
	fmt.Println("Handshakes succesfully initiated")
}

func deriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func encryptDB(db *LocalDB) ([]byte, error) {
	plaintext, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(db.SessionKey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	env := EncryptedDB{
		Salt:       db.Salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	return json.MarshalIndent(env, "", "  ")
}

func decryptDB(env *EncryptedDB, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Password is wrong or data is tampered
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func initDB(r *bufio.Reader) (*LocalDB, error) {
	data, err := os.ReadFile(DBFile)

	if os.IsNotExist(err) || len(data) == 0 {
		db := &LocalDB{
			Contacts:       make(map[string]string),
			MyWallets:      make(map[string]string),
			DirectoryEpoch: 0,
		}
		setupIdentity(r, db)
		return db, nil
	} else if err != nil {
		return nil, err
	}

	var env EncryptedDB
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("failed to parse encrypted database format")
	}

	return loginAndUnlock(&env)
}

func setupIdentity(r *bufio.Reader, db *LocalDB) {
Begin:
	fmt.Print("Choose username: ")
	name := readInput(r)

	fmt.Print("Choose password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("Something went wrong while reading password")
		goto Begin
	}

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		fmt.Printf("Failed to generate salt: %v\n", err)
		goto Begin
	}

	db.Salt = salt
	db.SessionKey = deriveKey(bytePassword, salt)
	
	for i := range bytePassword { bytePassword[i] = 0 }

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate identity keys: %v\n", err)
		goto Begin
	}

	db.MyIdentity = &Identity{
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}

	fmt.Print("Registering with server...\n")
	
	var resp api.RegisterParticipantResponse
	req := api.RegisterParticipantRequest{ID: name, PublicKey: pubKey}
	if err := callAPI("POST", "/participants", req, &resp); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		// goto jumpscare
		// Però dai, nel kernel di Linux lo usano in questa maniera quindi ci sta
		goto Begin
	}
	db.ServerPub = resp.ServerPublicKey

	saveDB(db)
}

func loginAndUnlock(env *EncryptedDB) (*LocalDB, error) {
	fmt.Println("Encrypted database found.")

	for range 3 {
		fmt.Printf("Enter password to login: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}

		start := time.Now()
		targetDuration := 2 * time.Second

		key := deriveKey(passwordBytes, env.Salt)

		for i := range passwordBytes { passwordBytes[i] = 0 }

		plaintext, err := decryptDB(env, key)

		if err == nil {
			var db LocalDB
			if err := json.Unmarshal(plaintext, &db); err != nil {
				return nil, errors.New("databae decrypted, but JSON is corrupted")
			}

			db.SessionKey = key
			db.Salt = env.Salt
			if db.MyWallets == nil { db.MyWallets = make(map[string]string) }
			if db.Contacts == nil { db.Contacts = make(map[string]string) }

			fmt.Printf("Welcome back, %s!\n", db.MyIdentity.Name)
			return &db, nil
		}

		elapsed := time.Since(start)
		if elapsed < targetDuration {
			time.Sleep(targetDuration - elapsed)
		}

		fmt.Println("Incorrect password or corrupt database. Please try again.")
	}
	return nil, errors.New("maximum login attempts reached")
}

// Menu functions
func printMenu(db *LocalDB) {
	fmt.Print("\033[H\033[2J")
	fmt.Println("==================================================================")
	fmt.Printf(" USER: %s | CONTACTS: %d | CREATED: %d\n",
		db.MyIdentity.Name, len(db.Contacts), len(db.MyWallets))
	fmt.Println("==================================================================")
	fmt.Println(" 1. Show My Identity (for Dealer)    4. Initialize Signing")
	fmt.Println(" 2. Add a Contact                    5. List My Created Wallets")
	fmt.Println(" 3. Create New Wallet (Dealer)       0. Exit")
	fmt.Println("==================================================================")
	fmt.Printf("Server Pub: %s\n", hex.EncodeToString(db.ServerPub))
}

func showIdentity(db *LocalDB) {
	fmt.Println("\n--- Identity ---")
	fmt.Printf("Username:   %s\n", db.MyIdentity.Name)
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(db.MyIdentity.PublicKey))
	fmt.Println("\n(Send this public key to shareholder so they can add you")
}

func addContact(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Type ID of friend to add: ")
	name := readInput(r)
	if name == db.MyIdentity.Name {
		fmt.Printf("You can't be friends with yourself! (...maybe?)")
		return
	}
	
	if name == "" {
		fmt.Println("Name can't be empty.")
		return
	}

	var signedResp api.SignedParticipantResponse
	err := callAPI("GET", fmt.Sprintf("/participants?id=%s", name), nil, &signedResp)
	if err != nil {
		fmt.Printf("error while fetching user '%s': %v", name, err)
		return
	}

	resp := signedResp.Data
	dataBytes, _ := json.Marshal(resp)
	if !ed25519.Verify(db.ServerPub, dataBytes, signedResp.Signature) {
		fmt.Println("Invalid response signature.")
		return
	}

	if resp.Epoch < db.DirectoryEpoch {
		fmt.Println("Obsolete epoch.")
		return
	}

	db.Contacts[name] = hex.EncodeToString(resp.PublicKey)
	db.DirectoryEpoch = resp.Epoch
	saveDB(db)

	fmt.Printf("Added friend '%s'.\n", name)
}

func listCreatedWallets(db *LocalDB) {
	fmt.Println("\n--- [WALLETS YOU CREATED] ---")
	if len(db.MyWallets) == 0 {
		fmt.Println("No wallets created yet.")
		return
	}
	for pubHex, name := range db.MyWallets {
		fmt.Printf("NAME: %-15s | PUBKEY: %s\n", name, pubHex)
	}
}

func readInput(r *bufio.Reader) string {
	input, _ := r.ReadString('\n')
	return strings.TrimSpace(input)
}

func saveDB(db *LocalDB) {
	encData, err := encryptDB(db)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to encrypt database before saving: %v\n", err)
		return
	}
	os.WriteFile(DBFile, encData, 0600)
}
