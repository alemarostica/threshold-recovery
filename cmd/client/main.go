package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
var pendingShares = make(map[string][]byte)

// Configuration
const (
	ServerURL = "https://localhost:8443"
	DBFile    = "client_db.json"
)

// Local storage models
type LocalDB struct {
	MyIdentity     *Identity           `json:"my_identity"`
	Contacts       map[string]string   `json:"contacts"`
	WatchList      map[string]string   `json:"watchlist"`
	MyWallets      map[string]string   `json:"my_wallets"`
	DirectoryEpoch uint64              `json:"directory_epoch"`
	ServerPub      ed25519.PublicKey   `json:"server_pub"`
	Alpha          edwards25519.Scalar `json:"alpha"`
}

type Identity struct {
	Name       string             `json:"name"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

type ClientSender struct{}

// Main
func main() {
	db := loadDB()
	reader := bufio.NewReader(os.Stdin)

	// First run
	if db.MyIdentity == nil {
		setupIdentity(reader, db)
	}

	startMessagePoller(db)

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
			// recoverShare(reader, db)
		case "5":
			listCreatedWallets(db)
		case "0":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("Invalid Option.")
		}
		fmt.Println("\nPress Enter to continue...")
		reader.ReadString('\n')
	}
}

func callAPI(method, path string, payload interface{}, out interface{}) error {
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

func startMessagePoller(db *LocalDB) {
	ticker := time.NewTicker(3 * time.Second) // Frequenza di polling
	go func() {
		for range ticker.C {
			pollRelay(db)
		}
	}()
}

func pollRelay(db *LocalDB) {
	if db.MyIdentity == nil {
		return // skippa se non registrato
	}

	var msgs []keyexchange.Message
	err := callAPI("GET", "/relay/messages?user_id="+db.MyIdentity.Name, nil, &msgs)
	if err != nil {
		fmt.Printf("Failed to fetch messages from relay: %v\n", err)
		return
	}
	if len(msgs) == 0 {
		return // no messages
	}

	provider := crypto.NewDefaultProvider()
	dir := &ClientDirectory{DB: db}
	sender := &ClientSender{}
	myPriv := db.MyIdentity.PrivateKey

	for _, msg := range msgs {
		fmt.Printf("\n[RELAY] Received message %s from %s\n", msg.Type, msg.From)

		switch msg.Type {
		case keyexchange.M1:
			state, err := keyexchange.HandleM1(msg, db.MyIdentity.Name, provider, dir, sender, myPriv)
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
			shareBlob, ok := pendingShares[msg.From]
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
			delete(pendingShares, msg.From)
		case keyexchange.M3:
			// We are shareholder, dealer sent us encrypted share with M3
			state, ok := activeSessions[msg.From]
			if !ok {
				fmt.Printf("Non active session found for M3 from %s\n", msg.From)
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
				fmt.Printf("Could not unmarshal the share: %v\n")
				continue
			}

			// Verification
			protocol := crypto.NewProtocol(&db.Alpha, message.PubParams.K, message.PubParams.N)
			if !protocol.VerifyShare(crypto.ParticipantID(message.Index), message.Share, message.Commitments) {
				// TODO: fuck implementare Message interface per differenti messaggi
				fmt.Printf("share did not verify")
				continue
			}

			delete(activeSessions, msg.From)
		}

		// the prompt
		fmt.Print("\nSelect an option: ")
	}
}

func startLivenessPinger(db *LocalDB) {
	ticker := time.NewTicker(1 * time.Minute)

	go func() {
		for range ticker.C {
			if db.MyIdentity == nil || len(db.MyWallets) == 0 {
				// Either ID not setup or no wallet registered
				continue
			}
			pingAllWallets(db)
		}
	}()
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

func (cs *ClientSender) Send(msg keyexchange.Message) error {
	err := callAPI("POST", "/relay/send", msg, nil)
	if err != nil {
		return fmt.Errorf("failed to send relay message: %v", err)
	}
	return nil
}

type ClientDirectory struct {
	DB *LocalDB
}

func (cd *ClientDirectory) GetUsernames() ([]byte, error) {
	return nil, nil
}

func (cd *ClientDirectory) GetPublicKey(userID string) (ed25519.PublicKey, error) {
	if userID == cd.DB.MyIdentity.Name {
		return cd.DB.MyIdentity.PublicKey, nil
	}

	hexKey, exists := cd.DB.Contacts[userID]
	if !exists {
		return nil, fmt.Errorf("user %s not found in local contacts", userID)
	}

	return hex.DecodeString(hexKey)
}

func (cd *ClientDirectory) GetEpoch() uint64 {
	return cd.DB.DirectoryEpoch
}

func generateRandomScalar(n int, r *bufio.Reader) ([]crypto.Scalar, error) {
	scalars := make([]crypto.Scalar, n)

	buf := make([]byte, 64)

	for i := 0; i < n; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("failed to read random bytes: %w", err)
		}

		s, err := edwards25519.NewScalar().SetUniformBytes(buf[:])
		if err != nil {
			return nil, errors.New("failed to generate a random scalar")
		}
		scalars[i] = *s
	}
	return scalars, nil
}

func createWallet(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- [CREATE NEW THRESHOLD WALLET] ---")

	// Get n and k
	// Remember that one share goes to the server, this n is just the friends
	fmt.Print("Enter number of shares for friends, at least 2 (n): ")
	n, err := strconv.Atoi(readInput(r))
	if err != nil {
		fmt.Println("Error: n must be a number >= 2.")
		return
	}

	// Same as with n, this is just the friends, server would constitute one shareholder
	fmt.Print("Enter threshold, at least 2 (k): ")
	k, err := strconv.Atoi(readInput(r))
	if err != nil || k < 2 || k > n {
		fmt.Printf("Error: k must be between 2 and %d\n", n)
		return
	}

	fmt.Println("\nYour contacts:")
	var names []string
	for name := range db.Contacts {
		names = append(names, name)
		fmt.Printf("- %s\n", name)
	}

	fmt.Printf("Enter %d friend names, comma separated: ", n-1)
	chosenStr := readInput(r)
	chosenStr = strings.TrimSpace(chosenStr)
	chosenNames := strings.Split(chosenStr, ",")

	var friendKeys [][]byte
	for _, cn := range chosenNames {
		name := strings.TrimSpace(cn)
		keyHex, ok := db.Contacts[name]
		if !ok {
			fmt.Printf("Error: Contact '%s' not found.\n", name)
			return
		}
		kb, _ := hex.DecodeString(keyHex)
		friendKeys = append(friendKeys, kb)
	}

	if len(friendKeys) != n-1 {
		fmt.Printf("Error: You must select exactly %d friends (one share is for the server).\n", n-1)
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
	walletPubkey, _, err := ed25519.GenerateKey(r)
	if err != nil {
		fmt.Printf("Failed to generate wallet keys: %v\n", err)
		return
	}

	secretScalarBytes := make([]byte, 64)
	if _, err := io.ReadFull(r, secretScalarBytes); err != nil {
		fmt.Println("Failed to generate secret scalar")
		return
	}

	digest := sha512.Sum512(secretScalarBytes)
	lowerHalf := digest[:32]

	lowerHalf[0] &= 248
	lowerHalf[31] &= 127
	lowerHalf[31] |= 64

	secretScalar, err := edwards25519.NewScalar().SetBytesWithClamping(lowerHalf)
	if err != nil {
		panic(err)
	}

	// scalar array for LSSS, first item is scalar from privKey
	secretVector_raw, err := generateRandomScalar(k+1, r)
	if err != nil {
		fmt.Printf("Error while generating scalars: %v", err)
		return
	}
	// I hope this is not problematic lol
	secretVector_raw[0] = *secretScalar

	matrix := crypto.BuildM(&db.Alpha, k+1, n+1)

	// pubParams e alpha devono arrivare al ricevente per fare il protocol
	// con cui verificare lo share

	pubParams := &crypto.PublicParams{
		K: k + 1,
		N: n + 1,
		M: matrix,
	}

	protocol := crypto.NewProtocol(&db.Alpha, k+1, n+1)

	secretVector := crypto.SecretVector{
		S:  secretVector_raw[0],
		R2: secretVector_raw[1],
		T:  secretVector_raw[2:],
	}
	dealerShares := protocol.Distribute(secretVector)
	commitments := protocol.GenerateCommitments(secretVector)

	regReq := api.RegisterRequest{
		Username:            db.MyIdentity.Name,
		PublicKey:           walletPubkey,
		ServerShare:         dealerShares.ServerShare,
		PubParams:           *pubParams,
		Commitments:         commitments,
		InactivityThreshold: timeoutDur,
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

	provider := crypto.NewDefaultProvider()
	dir := &ClientDirectory{DB: db}
	sender := &ClientSender{}
	myPriv := db.MyIdentity.PrivateKey

	fmt.Println("starting key exchange...")

	for i, cn := range chosenNames {
		friendName := strings.TrimSpace(cn)

		share := keyexchange.ShareMessage{
			Index:       i + 1,
			Share:       dealerShares.ParticipantShares[i],
			Commitments: commitments,
			PubParams:   *pubParams,
		}

		shareBlob, err := keyexchange.MarshalShare(share)
		if err != nil {
			fmt.Printf("Marshal error for share %s: %v\n", friendName, err)
			continue
		}

		pendingShares[friendName] = shareBlob

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

	fmt.Println("\nSUCCESS: Wallet registered on the server.")
	fmt.Printf("WALLET PUBLIC KEY (HEX): %s\n", wHex)
	fmt.Println("Handshakes succesfully initiated")
}

func setupIdentity(r *bufio.Reader, db *LocalDB) {
Begin:
	fmt.Print("Choose username: ")
	name := readInput(r)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate identity keys: %v\n", err)
		return
	}

	db.MyIdentity = &Identity{
		Name:       name,
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}

	var resp api.RegisterParticipantResponse
	req := api.RegisterParticipantRequest{ID: name, PublicKey: pubKey}
	if err := callAPI("POST", "/participants", req, &resp); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		// goto jumpscare
		// Però dai, nel kernel di Linux lo usano in questa maniera quindi ci sta
		goto Begin
	}
	db.ServerPub = resp.ServerPublicKey
	db.Alpha = resp.Alpha

	saveDB(db)
}

// Helpers
func loadDB() *LocalDB {
	db := &LocalDB{
		Contacts:       make(map[string]string),
		WatchList:      make(map[string]string),
		MyWallets:      make(map[string]string),
		DirectoryEpoch: 0,
	}
	data, err := os.ReadFile(DBFile)
	if err == nil {
		json.Unmarshal(data, db)
	}
	// Check if file existed but lacked map
	if db.MyWallets == nil {
		db.MyWallets = make(map[string]string)
	}
	return db
}

// Menu functions
func printMenu(db *LocalDB) {
	fmt.Print("\033[H\033[2J")
	fmt.Println("==================================================================")
	fmt.Printf(" USER: %s | CONTACTS: %d | WATCHING: %d | CREATED: %d\n",
		db.MyIdentity.Name, len(db.Contacts), len(db.WatchList), len(db.MyWallets))
	fmt.Println("==================================================================")
	fmt.Println(" 1. Show My Identity (for Dealer)    4. Recover Share [DEPR]")
	fmt.Println(" 2. Add a Contact                    5. List My Created Wallets")
	fmt.Println(" 3. Create New Wallet (Dealer)       0. Exit")
	fmt.Println("==================================================================")
	fmt.Printf("Server Pub: %s\n", db.ServerPub)
}

func showIdentity(db *LocalDB) {
	fmt.Println("\n--- Identity ---")
	fmt.Printf("Username:   %s\n", db.MyIdentity.Name)
	fmt.Printf("Public Key: %s\n", db.MyIdentity.PublicKey)
	fmt.Println("\n(Send this public key to shareholder so they can add you")
}

func addContact(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Inserisci il nome (ID) dell'amico da aggiungere: ")
	name := readInput(r)
	if name == "" {
		fmt.Println("Il nome non puó essere vuoto.")
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
	data, _ := json.MarshalIndent(db, "", "  ")
	os.WriteFile(DBFile, data, 0600)
}
