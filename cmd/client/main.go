package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
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
	MyIdentity *Identity              `json:"my_identity"`
	Contacts   map[string]string      `json:"contacts"`
	WatchList  map[string]string      `json:"watchlist"`
	MyWallets  map[string]WalletInfo `json:"my_wallets"` // Updated to store struct
}

type WalletInfo struct {
	Nickname     string `json:"nickname"`
	PublicKey    string `json:"public_key"`
	PrivateKey   string `json:"private_key"` // Hex encoded
}

type Identity struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func main() {
	db := loadDB()
	reader := bufio.NewReader(os.Stdin)

	if db.MyIdentity == nil {
		setupIdentity(reader, db)
	}

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
		case "8":
			pingAllWallets(db)
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

func pingAllWallets(db *LocalDB) {
	fmt.Println("\n--- [SENDING LIVENESS PINGS] ---")
	if len(db.MyWallets) == 0 {
		fmt.Println("No wallets found to ping.")
		return
	}

	curve := elliptic.P256()

	for pubHex, info := range db.MyWallets {
		fmt.Printf("Pinging for %s (%s)... ", info.Nickname, pubHex[:8])

		// 1. Reconstruct Private Key
		privBytes, _ := hex.DecodeString(info.PrivateKey)
		pubBytes, _ := hex.DecodeString(info.PublicKey)
		
		d := new(big.Int).SetBytes(privBytes)
		x, y := elliptic.Unmarshal(curve, pubBytes)
		
		priv := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			},
			D: d,
		}

		// 2. Prepare Message (PubKeyHex:Timestamp)
		timestamp := time.Now().Unix()
		msg := fmt.Sprintf("%s:%d", info.PublicKey, timestamp)

		// 3. Sign
		r, s, err := ecdsa.Sign(rand.Reader, priv, []byte(msg))
		if err != nil {
			fmt.Printf("Sign error: %v\n", err)
			continue
		}

		// Concat R and S for the signature field
		signature := append(r.Bytes(), s.Bytes()...)

		// 4. Send Request
		req := api.LivenessRequest{
			PublicKey: pubBytes,
			Timestamp: timestamp,
			Signature: signature,
		}

		if err := callAPI("POST", "/liveness", req, nil); err != nil {
			fmt.Printf("FAILED: %v\n", err)
		} else {
			fmt.Println("SUCCESS")
		}
	}
}

func createWallet(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- [CREATE NEW THRESHOLD WALLET] ---")

	if len(db.Contacts) == 0 {
		fmt.Println("Error: You have no contacts. Add shareholders first.")
		return
	}

	fmt.Print("Enter total number of shares (n): ")
	n, _ := strconv.Atoi(readInput(r))
	fmt.Print("Enter threshold (k): ")
	k, _ := strconv.Atoi(readInput(r))

	fmt.Println("\nYour contacts:")
	for name := range db.Contacts {
		fmt.Printf("- %s\n", name)
	}

	fmt.Printf("Enter %d friend names, comma separated: ", n-1)
	chosenNames := strings.Split(readInput(r), ",")

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

	fmt.Print("Enter inactivity timeout (e.g. 30s, 24h): ")
	timeoutDur, _ := time.ParseDuration(readInput(r))
	fmt.Print("Give this wallet a local nickname: ")
	walletName := readInput(r)

	// --- CRYPTO ---
	curve := elliptic.P256()
	privKey, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	walletPub := elliptic.Marshal(curve, x, y)
	secretInt := new(big.Int).SetBytes(privKey)

	coeffs := make([]*big.Int, k)
	coeffs[0] = secretInt
	for i := 1; i < k; i++ {
		c, _ := rand.Int(rand.Reader, curve.Params().N)
		coeffs[i] = c
	}

	var commitmentBlob []byte
	for _, c := range coeffs {
		cx, cy := curve.ScalarBaseMult(c.Bytes())
		commitmentBlob = append(commitmentBlob, elliptic.Marshal(curve, cx, cy)...)
	}

	shares := make([]crypto.Share, n)
	for i := 1; i <= n; i++ {
		val := calculatePoly(curve, coeffs, i)
		shares[i-1] = crypto.Share{Index: i, Value: val.Bytes()}
	}

	var friendInputs []api.FriendShareInput
	for i, fKey := range friendKeys {
		shareObj := shares[i+1]
		encBlob := append([]byte("ENC:"), shareObj.Value...) // Placeholder for ECIES
		friendInputs = append(friendInputs, api.FriendShareInput{
			FriendPubKey:  fKey,
			EncryptedBlob: encBlob,
		})
	}

	req := api.RegisterRequest{
		PublicKey:           walletPub,
		EncryptedShare:      shares[0].Value,
		ShareCommitment:     commitmentBlob,
		InactivityThreshold: timeoutDur,
		FriendShares:        friendInputs,
	}

	if err := sendRequest("POST", "/register", req, nil); err != nil {
		fmt.Printf("Server registration failed: %v\n", err)
		return
	}

	wHex := hex.EncodeToString(walletPub)
	// SAVE PRIVATE KEY TO DB
	db.MyWallets[wHex] = WalletInfo{
		Nickname:   walletName,
		PublicKey:  wHex,
		PrivateKey: hex.EncodeToString(privKey),
	}
	saveDB(db)

	fmt.Println("SUCCESS: Wallet registered!")
}

// ... (calculatePoly, checkWallets, recoverShare, setupIdentity, callAPI remain mostly same) ...

func calculatePoly(curve elliptic.Curve, coeffs []*big.Int, x int) *big.Int {
	xBig := big.NewInt(int64(x))
	val := new(big.Int).Set(coeffs[0])
	order := curve.Params().N
	for i := 1; i < len(coeffs); i++ {
		pow := new(big.Int).Exp(xBig, big.NewInt(int64(i)), order)
		term := new(big.Int).Mul(coeffs[i], pow)
		term.Mod(term, order)
		val.Add(val, term)
		val.Mod(val, order)
	}
	return val
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
		if status["recoverable"].(bool) { state = "DEAD (RECOVERABLE)" }
		fmt.Printf("%-15s | %s | Time left: %s\n", name, state, status["time_until_recovery"])
	}
}

func recoverShare(r *bufio.Reader, db *LocalDB) {
	fmt.Println("\n--- Recover share ---")
	fmt.Print("Enter Wallet PubKey (Hex): ")
	targetHex := readInput(r)
	targetKey, _ := hex.DecodeString(targetHex)
	myKey, _ := hex.DecodeString(db.MyIdentity.PublicKey)

	req := api.SharePickupRequest{PublicKey: targetKey, FriendPubKey: myKey}
	
	jsonPayload, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", ServerURL+"/mailbox/pickup", bytes.NewBuffer(jsonPayload))
	httpReq.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Do(httpReq)
	if err != nil { fmt.Printf("Error: %v\n", err); return }
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed: %s\n", msg)
		return
	}

	data, _ := io.ReadAll(resp.Body)
	filename := fmt.Sprintf("share_%s.bin", targetHex[:8])
	os.WriteFile(filename, data, 0600)
	fmt.Printf("SUCCESS! Share saved to '%s'\n", filename)
}

func setupIdentity(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Choose username: ")
	name := readInput(r)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	db.MyIdentity = &Identity{Name: name, PublicKey: hex.EncodeToString(pubBytes)}
	saveDB(db)
	req := api.RegisterParticipantRequest{ID: name, PublicKey: pubBytes}
	callAPI("POST", "/participants", req, nil)
}

func loadDB() *LocalDB {
	db := &LocalDB{
		Contacts:  make(map[string]string),
		WatchList: make(map[string]string),
		MyWallets: make(map[string]WalletInfo),
	}
	data, err := os.ReadFile(DBFile)
	if err == nil { json.Unmarshal(data, db) }
	return db
}

func printMenu(db *LocalDB) {
	fmt.Println("\n==================================================================")
	fmt.Printf(" USER: %s | CONTACTS: %d | WATCHING: %d | OWNED: %d\n",
		db.MyIdentity.Name, len(db.Contacts), len(db.WatchList), len(db.MyWallets))
	fmt.Println("==================================================================")
	fmt.Println(" 1. Show My Identity              5. Check Watchlist Status")
	fmt.Println(" 2. Add a Contact                 6. Recover / Download Share")
	fmt.Println(" 3. Create New Wallet (Dealer)    7. List My Created Wallets")
	fmt.Println(" 4. Watch an Existing Wallet      8. PING ALL WALLETS (I'm Alive)")
	fmt.Println(" 0. Exit")
	fmt.Println("==================================================================")
}

func showIdentity(db *LocalDB) {
	fmt.Printf("\nUsername: %s\nPublic Key: %s\n", db.MyIdentity.Name, db.MyIdentity.PublicKey)
}

func addContact(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Friend's name: "); name := readInput(r)
	fmt.Print("Friend's public key (Hex): "); key := readInput(r)
	db.Contacts[name] = key
	saveDB(db)
}

func addToWatchlist(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Wallet name: "); name := readInput(r)
	fmt.Print("Wallet public key (Hex): "); key := readInput(r)
	db.WatchList[name] = key
	saveDB(db)
}

func listCreatedWallets(db *LocalDB) {
	for _, info := range db.MyWallets {
		fmt.Printf("NAME: %-15s | PUBKEY: %s\n", info.Nickname, info.PublicKey)
	}
}

func callAPI(method, path string, payload interface{}, out interface{}) error {
	bz, _ := json.Marshal(payload)
	req, _ := http.NewRequest(method, ServerURL+path, bytes.NewBuffer(bz))
	req.Header.Set("Content-Type", "application/json")
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Timeout: 10 * time.Second, Transport: tr}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("error %d: %s", resp.StatusCode, msg)
	}
	if out != nil { return json.NewDecoder(resp.Body).Decode(out) }
	return nil
}

func sendRequest(method, path string, payload interface{}, result interface{}) error {
	return callAPI(method, path, payload, result)
}

func readInput(r *bufio.Reader) string {
	input, _ := r.ReadString('\n')
	return strings.TrimSpace(input)
}

func saveDB(db *LocalDB) {
	data, _ := json.MarshalIndent(db, "", "  ")
	os.WriteFile(DBFile, data, 0600)
}
