package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"threshold-recovery/internal/api"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/keyexchange"
	"time"

	"filippo.io/edwards25519"
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

	db, err := InitDB(reader)
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
		PrintMenu(db)
		fmt.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			ShowIdentity(db)
		case "2":
			AddContact(reader, db)
		case "3":
			CreateWallet(reader, db)
		case "4":
			InitializePartialSign(db)
		case "5":
			ListCreatedWallets(db)
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
		switch msg.Type {
		case keyexchange.M1:
			state, err := keyexchange.HandleM1(msg, dir.MyIdentity.Name, provider, dir, sender, myPriv)
			if err != nil {
				fmt.Printf("[RELAY] Error: failed to handle M1 message from %s: %v\n", msg.From, err)
				continue
			}
			activeSessions[msg.From] = state
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
				fmt.Printf("Share is not consistent.")
				continue
			}

			share := Share{
				Username:  message.Username,
				WalletPub: message.WalletPub,
				Value: partShare.Bytes(),
				Index: message.Index,
			}

			db.ReceivedShares = append(db.ReceivedShares, share)

			delete(activeSessions, msg.From)
			SaveDB(db)
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

func CreateWallet(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- [CREATE NEW THRESHOLD WALLET] ---")

	// Get n and k
	// Remember that one share goes to the server, this n is just the friends
	fmt.Print("Enter number of shares for friends, at least 2 (n): ")
	n, err := strconv.Atoi(ReadInput(r))
	if err != nil || n < 2 {
		fmt.Println("Error: n must be a number >= 2.")
		return
	}

	// Same as with n, this is just the friends, server would constitute one shareholder
	fmt.Print("Enter threshold, at least 2 (k): ")
	k, err := strconv.Atoi(ReadInput(r))
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
	chosenStr := ReadInput(r)
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
	timeoutDur, err := time.ParseDuration(ReadInput(r))
	if err != nil {
		fmt.Println("Error: Invalid duration format. Use 's', 'm' or 'h'.")
		return
	}

	fmt.Print("Give this wallet a local nickname: ")
	walletName := ReadInput(r)

	// We generate an ed25519 key
	// In a real application the user would input his wallet's key
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
	}

	wHex := hex.EncodeToString(walletPubkey)
	db.MyWallets[wHex] = walletName
	SaveDB(db)

	// zeroize the secret
	zero := make([]byte, 64)
	secret.SetCanonicalBytes(zero)

	fmt.Println("\nSUCCESS: Wallet registered on the server.")
	fmt.Printf("WALLET PUBLIC KEY (HEX): %s\n", wHex)
	fmt.Println("Handshakes succesfully initiated")
}
