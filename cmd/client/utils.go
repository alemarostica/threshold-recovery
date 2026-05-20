package main

import (
	"bufio"
	"bytes"
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
	"runtime"
	"strings"
	"syscall"
	"threshold-recovery/internal/api"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// Sends a generic HTTP request to the server API.
func callAPI(method, path string, payload any, out any) error {
	var body io.Reader

	// Serialize request payload if present
	if payload != nil {
		bz, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal error: %w", err)
		}
		body = bytes.NewBuffer(bz)
	}

	// Build the HTTP request.
	req, err := http.NewRequest(method, ServerURL+path, body)
	if err != nil {
		return err
	}

	// Set JSON content type for POST requests.
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Configure TLS transport for self-signed certificates
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	}}

	// Create HTTP client with timeout.
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// Execute the request.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	// Handle server-side errors.
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		errMsg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(errMsg))
	}

	// Decode response body if an output object is provided.
	if out != nil {

		// Stream raw response into writer if supported.
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

// Derives a symmetric encryption key from a password using Argon2id.
func deriveKey(password []byte, salt []byte) []byte {

	// Recommended Argon2id configuration for interactive logins.

	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

// Encrypts the local database before persisting it to disk.
func encryptDB(db *LocalDB) ([]byte, error) {

	// Serialize database into JSON format.
	plaintext, err := json.Marshal(db)
	if err != nil {
		return nil, err
	}

	// Initialize ChaCha20-Poly1305 AEAD cipher.
	aead, err := chacha20poly1305.New(db.SessionKey)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce.
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate database contents.
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Build encrypted database container.
	env := EncryptedDB{
		Salt:       db.Salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	return json.MarshalIndent(env, "", "  ")
}

// Decrypts the encrypted database using the derived session key.
func decryptDB(env *EncryptedDB, key []byte) ([]byte, error) {

	// Initialize AEAD cipher instance.
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt and authenticate database contents.
	// Failure may indicate either an invalid password or tampered data.
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Initializes the local database by either loading or creating it.
func InitDB(r *bufio.Reader) (*LocalDB, error) {

	// Attempt to read encrypted database file.
	data, err := os.ReadFile(DBFile)

	// Create a new database if none exists.
	if os.IsNotExist(err) || len(data) == 0 {
		db := &LocalDB{
			Contacts:       make(map[string]string),
			MyWallets:      make(map[string]string),
			DirectoryEpoch: 0,
		}
		SetupIdentity(r, db)
		return db, nil
	} else if err != nil {
		return nil, err
	}

	// Decode encrypted database container.
	var env EncryptedDB
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("failed to parse encrypted database format")
	}

	// Attempt user login and database decryption.
	return loginAndUnlock(&env)
}

// Creates and registers a new user identity.
func SetupIdentity(r *bufio.Reader, db *LocalDB) {
	for {
		// Read desired username.
		fmt.Print("Choose username: ")
		name := ReadInput(r)

		// Read password securely from terminal.
		fmt.Printf("Choose password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Println("Something went wrong while reading password. Please try again.")
			continue
		}

		// Generate random salt for password derivation.
		salt := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			fmt.Printf("Failed to generate salt: %v\n", err)
			continue
		}

		// Generate Ed25519 identity key pair.
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Printf("Failed to generate identity keys: %v\n", err)
			continue
		}

		fmt.Print("Registering with server...")

		// Register participant on the server.
		var resp api.RegisterParticipantResponse
		req := api.RegisterParticipantRequest{
			ID: name, PublicKey: pubKey,
		}
		if err := callAPI("POST", "/participants", req, &resp); err != nil {
			fmt.Printf("Server registration failed: %v\n", err)

			// Zeroize password from memory.
			clear(bytePassword)
			runtime.KeepAlive(bytePassword)
			continue
		}

		// Derive session encryption key from password.
		db.Salt = salt
		db.SessionKey = deriveKey(bytePassword, salt)
		// Zeroize password after key derivation.
		clear(bytePassword)
		runtime.KeepAlive(bytePassword)

		// Store generated identity locally.
		db.MyIdentity = &Identity{
			Name:       name,
			PublicKey:  pubKey,
			PrivateKey: privKey,
		}
		db.ServerPub = resp.ServerPublicKey

		// Persist encrypted database to disk.
		SaveDB(db)

		return
	}
}

// Attempts user login and decrypts the local database.
func loginAndUnlock(env *EncryptedDB) (*LocalDB, error) {
	fmt.Println("Encrypted database found.")

	// Allow at most three login attempts.
	for range 3 {
		// Read password securely from terminal.
		fmt.Printf("Enter password to login: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return nil, err
		}

		start := time.Now()
		targetDuration := 2 * time.Second

		// Derive decryption key from password.
		key := deriveKey(passwordBytes, env.Salt)

		// Zeroize password after derivation
		clear(passwordBytes)
		runtime.KeepAlive(passwordBytes)

		// Attempt database decryption.
		plaintext, err := decryptDB(env, key)

		if err == nil {

			// Rebuild database structure from JSON.
			var db LocalDB
			if err := json.Unmarshal(plaintext, &db); err != nil {
				return nil, errors.New("database decrypted, but JSON is corrupted")
			}

			db.SessionKey = key
			db.Salt = env.Salt
			// Initialize missing maps if necessary.
			if db.MyWallets == nil {
				db.MyWallets = make(map[string]string)
			}
			if db.Contacts == nil {
				db.Contacts = make(map[string]string)
			}

			fmt.Printf("Welcome back, %s!\n", db.MyIdentity.Name)
			return &db, nil
		}

		// Artificial delay to slow down brute-force attempts.
		elapsed := time.Since(start)
		if elapsed < targetDuration {
			time.Sleep(targetDuration - elapsed)
		}

		fmt.Println("Incorrect password or corrupt database. Please try again.")
	}
	return nil, errors.New("maximum login attempts reached")
}

// Displays the interactive client menu.
func PrintMenu(db *LocalDB) {

	// Clear terminal screen.
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

// Displays information about the current user identity.
func ShowIdentity(db *LocalDB) {
	fmt.Println("\n--- Identity ---")
	fmt.Printf("Username:   %s\n", db.MyIdentity.Name)
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(db.MyIdentity.PublicKey))
}

// Adds a trusted contact to the local directory.
func AddContact(r *bufio.Reader, db *LocalDB) {

	// Read target username.
	fmt.Print("Type ID of friend to add: ")
	name := ReadInput(r)
	// Prevent self-registration as contact.
	if name == db.MyIdentity.Name {
		fmt.Printf("You can't be friends with yourself! (...maybe?)")
		return
	}

	if name == "" {
		fmt.Println("Name can't be empty.")
		return
	}

	// Retrieve participant information from server.
	var signedResp api.SignedParticipantResponse
	err := callAPI("GET", fmt.Sprintf("/participants?id=%s", name), nil, &signedResp)
	if err != nil {
		fmt.Printf("error while fetching user '%s': %v", name, err)
		return
	}

	resp := signedResp.Data

	// Verify server signature authenticity.
	dataBytes, _ := json.Marshal(resp)
	if !ed25519.Verify(db.ServerPub, dataBytes, signedResp.Signature) {
		fmt.Println("Invalid response signature.")
		return
	}

	// Reject stale directory responses.
	if resp.Epoch < db.DirectoryEpoch {
		fmt.Println("Obsolete epoch.")
		return
	}

	// Store contact locally.
	db.Contacts[name] = hex.EncodeToString(resp.PublicKey)
	db.DirectoryEpoch = resp.Epoch
	SaveDB(db)

	fmt.Printf("Added friend '%s'.\n", name)
}

// Displays wallets created by the current user.
func ListCreatedWallets(db *LocalDB) {
	fmt.Println("\n--- [WALLETS YOU CREATED] ---")
	if len(db.MyWallets) == 0 {
		fmt.Println("No wallets created yet.")
		return
	}
	for pubHex, name := range db.MyWallets {
		fmt.Printf("NAME: %-15s | PUBKEY: %s\n", name, pubHex)
	}
}

// Reads and trims a line of input from standard input.
func ReadInput(r *bufio.Reader) string {
	input, _ := r.ReadString('\n')
	return strings.TrimSpace(input)
}

// Encrypts and persists the local database to disk.
func SaveDB(db *LocalDB) {
	encData, err := encryptDB(db)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to encrypt database before saving: %v\n", err)
		return
	}
	os.WriteFile(DBFile, encData, 0600)
}
