package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/api"
)

// Configuration for the dealer
const ServerURL = "http://localhost:8080"

// Mock pinning, should we remove it?
var trustedFingerprints = map[string]string{
	// These would be the SHA256 hashes of the keys the friends gave us offline
	// For this prototype, we will just print warnings if we don't recognize them.
}

func main() {
	// Usage string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This tool generates a wallet, splits the key and registers one share with the server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n %s, -n 3 -k 2 -timeout 30s -friends alice,bob,charlie\n", os.Args[0])
	}

	// Parse CLI arguments
	n := flag.Int("n", 0, "Total number of shares")
	k := flag.Int("k", 0, "Threshold required to recover")
	friendsList := flag.String("friends", "", "Comma-separated list of friend IDs (e.g. alice,bob)")
	thresholdDur := flag.Duration("timeout", 0, "Inactivity timeout (e.g. 24h, 30s)")

	flag.Parse()
	friendIDs := strings.Split(*friendsList, ",")

	// Validate arguments, I love this
	if *n == 0 || *k == 0 || *thresholdDur == 0 || *k > *n || *k < 1 || *friendsList == "" || len(friendIDs) != *n-1 {
		if *k > *n {
			fmt.Fprintf(os.Stderr, "Error: Threshold (k) cannot be greater than total shares (n).\n\n")
		} else if *k <= 1 && *k != 0 {
			fmt.Fprintf(os.Stderr, "Error: Threshold (k) must be at least 2 for a threshold scheme.\n\n")
		} else if len(friendIDs) != *n-1 {
			fmt.Fprintf(os.Stderr, "Error: You requested n=%d but provided %d friends, 1 share goes to server", *n, len(friendIDs))
		}
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("=== THRESHOLD WALLET DEALER ===")
	fmt.Printf("Scheme: %d of %d\n", *k, *n)
	fmt.Printf("Timeout: %s\n", *thresholdDur)

	// Retrieve the friends' keys
	fmt.Println("\n[1] Fetching friend keys from directory...")
	friendKeys, err := fetchFriendKeys(friendIDs)
	if err != nil {
		log.Fatalf("Failed to fetch friend keys: %v", err)
	}

	// Crypto logic
	tss := crypto.NewTSS()

	// Generate the secret
	fmt.Println("\n[2] Generating and splitting Master Key...")
	pubKey, privKey := tss.GenerateIdentity()
	fmt.Printf("   -> Public Key: %x\n", pubKey)
	fmt.Printf("   -> Private Key: [HIDDEN] (simulated)\n")
	shares, err := tss.SplitSecret(privKey, *n, *k)
	if err != nil {
		log.Fatalf("Error splitting secret: %v", err)
	}
	commitments := tss.ComputeCommitments(privKey, *k)

	// Encrypt shares for specific friends
	var friendInputs []api.FriendShareInput
	//Share 0 goes to server, shares 1..n go to friends
	for i, fID := range friendIDs {
		// Get the share
		rawShare := shares[i+1]
		targetPubKey := friendKeys[fID]

		// Pinning check
		fingerprint := sha256.Sum256(targetPubKey)
		fingerprintHex := hex.EncodeToString(fingerprint[:])
		fmt.Printf("   -> Encrypting share #%d for '%s' (Fingerprint: %s...)\n", rawShare.Index, fID, fingerprintHex[:8])

		// Encrypting with friend's PubKey
		// This is a mock
		encryptedBlob := append([]byte("ENC_FOR_"+fID+":"), rawShare.Value...)

		friendInputs = append(friendInputs, api.FriendShareInput{
			FriendPubKey:  targetPubKey,
			EncryptedBlob: encryptedBlob,
		})
	}

	// Register
	fmt.Println("\n[4] Uploading to server...")
	payload := api.RegisterRequest{
		PublicKey:           pubKey,
		EncryptedShare:      shares[0].Value, // Arbitrarily give share no.1 no server, can we make it random?
		ShareCommitment:     commitments,
		InactivityThreshold: *thresholdDur,
		FriendShares:        friendInputs,
	}

	if err := registerWithServer(payload); err != nil {
		log.Fatalf("Failed to register with server: %v", err)
	}
	fmt.Println("   -> Success! Server is now keeping share #1.")

	fmt.Println("\n=== SETUP COMPLETE ===")
	fmt.Println("The wallet is live. The server is monitoring.")
	fmt.Printf("You need %d more share(s) combined with the server to recover.\n", *k-1)
}

func fetchFriendKeys(ids []string) (map[string][]byte, error) {
	joined := strings.Join(ids, ",")
	resp, err := http.Get(ServerURL + "/participants?ids=" + joined)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error: %s", resp.Status)
	}

	var keys map[string][]byte
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	// Did we get everyone?
	for _, id := range ids {
		if _, ok := keys[id]; !ok {
			return nil, fmt.Errorf("server did not return a key for user: %s", id)
		}
	}
	return keys, nil
}

func registerWithServer(req api.RegisterRequest) error {
	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	resp, err := http.Post(ServerURL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned status: %s", resp.Status)
	}
	return nil
}
