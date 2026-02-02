package main

import (
	"bufio"
	"bytes"
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
	"time"
)

// Configuration
const (
	ServerURL = "https://localhost:8443"
	DBFile    = "client_db.json"
)

// Local storage models
type LocalDB struct {
	MyIdentity *Identity         `json:"my_identity"`
	Contacts   map[string]string `json:"contacts"`
	WatchList  map[string]string `json:"watchlist"`
	MyWallets  map[string]string `json:"my_wallets"`
}

type Identity struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// Main
func main() {
	db := loadDB()
	reader := bufio.NewReader(os.Stdin)

	// First run
	if db.MyIdentity == nil {
		setupIdentity(reader, db)
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
	req.Header.Set("Content-Type", "application/json")

	// TODO: actually check certificates
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(errMsg))
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
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

	// Cryptography
	tss := crypto.NewTSS()
	walletPub, privKey := tss.GenerateIdentity()
	shares, err := tss.SplitSecret(privKey, n, k)
	if err != nil {
		fmt.Printf("Crypto error: %v\n", err)
		return
	}
	commitments := tss.ComputeCommitments(privKey, k)

	// Build payload

	var friendInputs []api.FriendShareInput
	for i, fKey := range friendKeys {
		// Mock encryption
		encBlob := append([]byte("ENC_FOR_FRIEND:"), shares[i+1].Value...)
		friendInputs = append(friendInputs, api.FriendShareInput{
			FriendPubKey:  fKey,
			EncryptedBlob: encBlob,
		})
	}

	// Mock encrypting logic
	req := api.RegisterRequest{
		PublicKey:           walletPub,
		EncryptedShare:      shares[0].Value,
		ShareCommitment:     commitments,
		InactivityThreshold: timeoutDur,
		FriendShares:        friendInputs,
	}

	if err := sendRequest("POST", "/register", req, nil); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		return
	}

	wHex := hex.EncodeToString(walletPub)
	db.MyWallets[wHex] = walletName
	saveDB(db)

	fmt.Println("SUCCESS: Wallet registered!")
	fmt.Printf("WALLET PUBLIC KEY (HEX): %s\n", wHex)
	fmt.Println("IMPORTANT: Give this hex key to your shareholders so they can watch it.")
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
	myKey, _ := hex.DecodeString(db.MyIdentity.PublicKey)

	req := api.SharePickupRequest{
		PublicKey:    targetKey,
		FriendPubKey: myKey,
	}

	// For downloading raw bytes, we use a slight variation of the API helper or custom logic
	resp, err := http.Post(ServerURL+"/mailbox/pickup", "application/json", bytes.NewBuffer([]byte{})) // Placeholder
	// Using callAPI for simplicity; you might want a specialized "Download" helper for binary data
	fmt.Println("Contacting server for share...")

	// Note: Since pickup returns raw bytes, we handle it manually here to preserve the binary share
	bz, _ := json.Marshal(req)
	resp, err = http.Post(ServerURL+"/mailbox/pickup", "application/json", bytes.NewBuffer(bz))
	if err != nil || resp.StatusCode != 200 {
		fmt.Println("Recovery failed. User might still be active.")
		return
	}
	data, _ := io.ReadAll(resp.Body)
	os.WriteFile("recovered_share.bin", data, 0600)
	fmt.Println("Success! Share saved to recovered_share.bin")
}

func setupIdentity(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Choose username: ")
	name := readInput(r)
	pk := make([]byte, 32) // Mock
	rand.Read(pk)
	db.MyIdentity = &Identity{Name: name, PublicKey: hex.EncodeToString(pk)}
	saveDB(db)

	req := api.RegisterParticipantRequest{ID: name, PublicKey: pk}
	if err := callAPI("POST", "/participants", req, nil); err != nil {
		fmt.Println("Server registration failed, but identity saved locally.")
	}
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
	fmt.Print("Friend's name: ")
	name, _ := r.ReadString('\n')
	name = strings.TrimSpace(name)

	fmt.Print("Friend's public key (Hex): ")
	key, _ := r.ReadString('\n')
	key = strings.TrimSpace(key)

	db.Contacts[name] = key
	saveDB(db)
	fmt.Println("Contact saved.")
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

func sendRequest(method, path string, payload interface{}, result interface{}) error {
	var body io.Reader
	if payload != nil {
		bz, _ := json.Marshal(payload)
		body = bytes.NewBuffer(bz)
	}

	req, err := http.NewRequest(method, ServerURL+path, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("network error (is the server running?): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func readInput(r *bufio.Reader) string {
	input, _ := r.ReadString('\n')
	return strings.TrimSpace(input)
}

func saveDB(db *LocalDB) {
	data, _ := json.MarshalIndent(db, "", "  ")
	os.WriteFile(DBFile, data, 0600)
}

func registerIdentity(id *Identity) {
	keyBytes, _ := hex.DecodeString(id.PublicKey)
	req := api.RegisterParticipantRequest{
		ID:        id.Name,
		PublicKey: keyBytes,
	}
	jsonData, _ := json.Marshal(req)
	http.Post(ServerURL+"/participants", "application/json", bytes.NewBuffer(jsonData))
}
