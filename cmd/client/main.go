package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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
)

// Ricorda lo stato delle sessioni di handshake in corso
var activeSessions = make(map[string]*keyexchange.SessionState)

// Salva temporaneamente le share in attesa che l'handshake finisca
var pendingShares = make(map[string][]byte)

// Configuration
const (
	ServerURL             = "https://localhost:8443"
	DBFile                = "client_db.json"
	PinnedServerPubKeyHex = ""
)

// Local storage models
type LocalDB struct {
	MyIdentity     *Identity         `json:"my_identity"`
	Contacts       map[string]string `json:"contacts"`
	WatchList      map[string]string `json:"watchlist"`
	MyWallets      map[string]string `json:"my_wallets"`
	DirectoryEpoch uint64            `json:"directory_epoch"`
}

type Identity struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
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
			addToWatchlist(reader, db)
		case "5":
			checkWallets(db)
		case "6":
			recoverShare(reader, db)
		case "7":
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

	// TODO: actually check certificates
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
	myPriv, _ := hex.DecodeString(db.MyIdentity.PrivateKey)

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
			plaintextShare, err := keyexchange.HandleM3(state, msg, provider)
			if err != nil {
				fmt.Printf("Failed to decrypt M3 from %s: %v\n", msg.From, err)
				continue
			}

			// We received the share
			// TODO: Save?
			fmt.Printf("Succesfully received share from %s.", msg.From)

			// Temporary print
			if len(plaintextShare) > 16 {
				fmt.Printf("share preview: %x...\n", plaintextShare[:16])
			}

			delete(activeSessions, msg.From)
		}

		// the prompt
		fmt.Print("\nSelect an option: ")
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

func (cd *ClientDirectory) GetPublicKey(userID string) ([]byte, error) {
	if userID == cd.DB.MyIdentity.Name {
		return hex.DecodeString(cd.DB.MyIdentity.PublicKey)
	}

	hexKey, exists := cd.DB.Contacts[userID]
	if !exists {
		return nil, fmt.Errorf("user %s not found in local contacts", userID)
	}

	return hex.DecodeString(hexKey)
}

// TODO: this is a demo
func (cd *ClientDirectory) GetEpoch() uint64 {
	return 1
}

func createWallet(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- [CREATE NEW THRESHOLD WALLET] ---")

	if len(db.Contacts) == 0 {
		fmt.Println("Error: You have no contacts. Add shareholders first.")
		return
	}

	// Get n and k
	fmt.Print("Enter total number of shares (n): ")
	n, err := strconv.Atoi(readInput(r))
	if err != nil {
		fmt.Println("Error: n must be a number >= 2.")
		return
	}

	fmt.Print("Enter threshold (k): ")
	k, err := strconv.Atoi(readInput(r))
	if err != nil || k < 2 || k > n {
		fmt.Printf("Error: k must be between 2 and %d\n", n)
		return
	}

	// Select friends
	fmt.Println("\nYour contacts:")
	var names []string
	for name := range db.Contacts {
		names = append(names, name)
		fmt.Printf("- %s\n", name)
	}

	fmt.Printf("Enter %d friend names, comma separated: ", n-1)
	chosenStr := readInput(r)
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

	// Initialize the curve context
	ctx := crypto.NewCurveCtx()
	// fmt.Printf("context: %v\n", ctx)

	// Generate the master secret (privKey)
	// In a real wallet this should be derived from a seed phrase
	// TODO: Should this actually be inputted by the user?
	privKey, _ := rand.Int(rand.Reader, ctx.N)
	pubKeyX, pubKeyY := ctx.Curve.ScalarBaseMult(privKey.Bytes())
	pubKeyBytes := elliptic.Marshal(ctx.Curve, pubKeyX, pubKeyY)

	shares, commitments, err := crypto.SplitVSS(ctx, privKey.Bytes(), n, k)
	if err != nil {
		fmt.Printf("Failed to split secret: %v", err)
		return
	}

	serverShare := shares[0]
	friendSharesRaw := shares[1:]

	req := api.RegisterRequest{
		PublicKey:           pubKeyBytes,
		ServerShare:         serverShare,
		Commitments:         commitments,
		InactivityThreshold: timeoutDur,
		FriendShares:        []api.FriendShareInput{}, // Vuota??
	}

	if err := callAPI("POST", "/register", req, nil); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		return
	}

	provider := crypto.NewDefaultProvider()
	dir := &ClientDirectory{DB: db}
	sender := &ClientSender{}
	myPriv, _ := hex.DecodeString(db.MyIdentity.PrivateKey)

	fmt.Println("starting key exchange...")

	for i, cn := range chosenNames {
		friendName := strings.TrimSpace(cn)

		shareBlob, err := crypto.MarshalShare(friendSharesRaw[i])
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

	wHex := hex.EncodeToString(pubKeyBytes)
	db.MyWallets[wHex] = walletName
	saveDB(db)

	fmt.Println("\nSUCCESS: Wallet registered on the server.")
	fmt.Printf("WALLET PUBLIC KEY (HEX): %s\n", wHex)
	fmt.Println("Handshakes succesfully initiated")
}

func checkWallets(db *LocalDB) {
	fmt.Println("\n--- Watchlist status ---")
	for name, keyHex := range db.WatchList {
		var status map[string]interface{}
		if err := callAPI("GET", "/status/"+keyHex, nil, &status); err != nil {
			fmt.Printf("%s: [Error]\n", name)
			continue
		}

		state := "ACTIVE"
		if status["recoverable"].(bool) {
			state = "DEAD (RECOVERABLE)"
		}

		fmt.Printf("%-15s | %s | Time left: %s\n", name, state, status["time_until_recovery"])
	}
}

func recoverShare(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- Recover share ---")
	// Simplified selection logic for brevity
	fmt.Print("Enter Wallet PubKey (Hex) to recover from: ")
	targetHex := readInput(r)
	targetKey, _ := hex.DecodeString(targetHex)
	// fmt.Printf("targetHex: %v\n", targetHex)
	myKey, _ := hex.DecodeString(db.MyIdentity.PublicKey)

	req := api.SharePickupRequest{
		PubKey:       targetKey,
		FriendPubKey: myKey,
	}

	var binBuffer bytes.Buffer
	if err := callAPI("POST", "/mailbox/pickup", req, &binBuffer); err != nil {
		fmt.Printf("Pickup failed: %v\n", err)
		return
	}

	data := binBuffer.Bytes()
	err := os.WriteFile("recovered_share.bin", data, 0600)
	if err != nil {
		fmt.Println("File error: %v\n", err)
		return
	}

	fmt.Println("Success! Share saved to recovered_share.bin")
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
		PublicKey:  hex.EncodeToString(pubKey),
		PrivateKey: hex.EncodeToString(privKey),
	}

	req := api.RegisterParticipantRequest{ID: name, PublicKey: pubKey}
	if err := callAPI("POST", "/participants", req, nil); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		// goto jumpscare
		// Però dai, nel kernel di Linux lo usano in questa maniera quindi ci sta
		goto Begin
	}
	saveDB(db)
}

// Helpers
func loadDB() *LocalDB {
	db := &LocalDB{
		Contacts:  make(map[string]string),
		WatchList: make(map[string]string),
		MyWallets: make(map[string]string),
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
	fmt.Println(" 1. Show My Identity (for Dealer)    5. Check Watchlist Status")
	fmt.Println(" 2. Add a Contact                    6. Recover / Download Share")
	fmt.Println(" 3. Create New Wallet (Dealer)       7. List My Created Wallets")
	fmt.Println(" 4. Watch an Existing Wallet         0. Exit")
	fmt.Println("==================================================================")
}

func showIdentity(db *LocalDB) {
	fmt.Println("\n--- Identity ---")
	fmt.Printf("Username:   %s\n", db.MyIdentity.Name)
	fmt.Printf("Public Key: %s\n", db.MyIdentity.PublicKey)
	fmt.Println("\n(Send this public key to shareholder so they can add you")
}

func addContact(r *bufio.Reader, db *LocalDB) {
	fmt.Printf("Friend's name: ")
	name, _ := r.ReadString('\n')
	name = strings.TrimSpace(name)

	var resp api.SignedParticipantResponse
	err := callAPI("GET", fmt.Sprintf("/participants?id=%s", name), nil, &resp)
	if err != nil {
		fmt.Printf("Failed to fetch participant %s: %v", name, err)
		return
	}

	dataBytes, _ := json.Marshal(resp.Data)
	// TODO: pubkey del server hardcoded, la facciamo inviare dal server?
	// Dovrebbe essere inviata con TLS quindi non dovrebbero esserci problemi.
	serverPubKey, _ := hex.DecodeString(PinnedServerPubKeyHex)

	if !ed25519.Verify(serverPubKey, dataBytes, resp.Signature) {
		fmt.Println("Invalid server signature!")
		return
	}

	if resp.Data.Epoch < db.DirectoryEpoch {
		fmt.Printf("Epoch rollback")
		return
	}

	db.DirectoryEpoch = resp.Data.Epoch
	db.Contacts[name] = hex.EncodeToString(resp.Data.PublicKey)
	saveDB(db)

	fmt.Printf("Contact '%s' fetched and verified.\n", name)
}

func addToWatchlist(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Wallet name (e.g. 'Alice Main'): ")
	name, _ := r.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Wallet public key (Hex): ")
	key, _ := r.ReadString('\n')
	key = strings.TrimSpace(key)

	db.WatchList[name] = key
	saveDB(db)
	fmt.Println("Wallet added to watchlist.")
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
