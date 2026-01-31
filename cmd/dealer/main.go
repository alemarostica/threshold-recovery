package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"threshold-recovery/internal/crypto"
	"time"
)

// Configuration for the dealer
const (
	ServerURL = "http://localhost:8080"
	OutDir    = "./dist_shares"
)

type RegisterRequest struct {
	PublicKey           []byte        `json:"public_key"`
	EncryptedShare      []byte        `json:"encrypted_share"`
	ShareCommitment     []byte        `json:"share_commitment"`
	InactivityThreshold time.Duration `json:"inactivity_threshold"`
}

func main() {
	// Usage string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This tool generates a wallet, splits the key and registers one share with the server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n %s, -n 3 -k 2 -timeout 30s\n", os.Args[0])
	}

	// Parse CLI arguments
	n := flag.Int("n", 0, "Total number of shares")
	k := flag.Int("k", 0, "Threshold required to recover")
	thresholdDur := flag.Duration("timeout", 0, "Inactivity timeout (e.g. 24h, 30s)")
	flag.Parse()

	// Validate arguments, I love this
	if *n == 0 || *k == 0 || *thresholdDur == 0 || *k > *n || *k < 1 {
		if *k > *n {
			fmt.Fprintf(os.Stderr, "Error: Threshold (k) cannot be greater than total shares (n).\n\n")
		} else if *k <= 1 && *k != 0 {
			fmt.Fprintf(os.Stderr, "Error, Threshold (k) must be at least 2 for a threshold scheme.\n\n")
		}
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("=== THRESHOLD WALLET DEALER ===")
	fmt.Printf("Scheme: %d of %d\n", *k, *n)
	fmt.Printf("Timeout: %s\n", *thresholdDur)

	// Crypto logic
	tss := crypto.NewTSS()

	// Generate the secret
	fmt.Println("\n[1] Generating Master Keypair...")
	pubKey, privKey := tss.GenerateIdentity()
	fmt.Printf("   -> Public Key: %x\n", pubKey)
	fmt.Printf("   -> Private Key: [HIDDEN] (simulated)\n")

	// Split the key
	fmt.Println("\n[2] Splitting secret into shares...")
	shares, err := tss.SplitSecret(privKey, *n, *k)
	if err != nil {
		log.Fatalf("Error splitting secret: %v", err)
	}

	commitments := tss.ComputeCommitments(privKey, *k)

	fmt.Println("\n[3] Registering Share #1 with recovery server...")

	// Distribute Share #1 to the server
	// I think any share can be given to the server?
	serverShare := shares[0]

	payload := RegisterRequest{
		PublicKey:           pubKey,
		EncryptedShare:      serverShare.Value,
		ShareCommitment:     commitments,
		InactivityThreshold: *thresholdDur,
	}

	if err := registerWithServer(payload); err != nil {
		log.Fatalf("Failed to register with server: %v", err)
	}
	fmt.Println("   -> Success! Server is now keeping share #1.")

	// Distribute remaining shares
	fmt.Println("\n[4] Distributing remaining shares to local storage...")
	if err := os.MkdirAll(OutDir, 0755); err != nil {
		log.Fatal(err)
	}

	for i := 1; i < len(shares); i++ {
		share := shares[i]
		fileName := fmt.Sprintf("share_%d_pub_%x.json", share.Index, pubKey[:4])
		filePath := filepath.Join(OutDir, fileName)

		// Create a file meant for a shareholder
		shareFileContent := map[string]interface{}{
			"share_index": share.Index,
			"share_value": hex.EncodeToString(share.Value),
			"public_key":  hex.EncodeToString(pubKey),
			"commitment":  hex.EncodeToString(commitments),
		}

		fileData, _ := json.MarshalIndent(shareFileContent, "", "  ")
		if err := os.WriteFile(filePath, fileData, 0600); err != nil {
			log.Printf("Error saving share %d: %v", share.Index, err)
		} else {
			fmt.Printf("   -> Saved share #%d to %s\n", share.Index, filePath)
		}
	}

	fmt.Println("\n=== SETUP COMPLETE ===")
	fmt.Println("The wallet is live. The server is monitoring.")
	fmt.Printf("You need %d more share(s) combined with the server to recover.\n", *k-1)
}

func registerWithServer(req RegisterRequest) error {
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
