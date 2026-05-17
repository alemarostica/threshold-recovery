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
	"strings"
	"syscall"
	"threshold-recovery/internal/api"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

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

func InitDB(r *bufio.Reader) (*LocalDB, error) {
	data, err := os.ReadFile(DBFile)

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

	var env EncryptedDB
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("failed to parse encrypted database format")
	}

	return loginAndUnlock(&env)
}

func SetupIdentity(r *bufio.Reader, db *LocalDB) {
Begin:
	fmt.Print("Choose username: ")
	name := ReadInput(r)

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

	SaveDB(db)
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
				return nil, errors.New("database decrypted, but JSON is corrupted")
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
func PrintMenu(db *LocalDB) {
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

func ShowIdentity(db *LocalDB) {
	fmt.Println("\n--- Identity ---")
	fmt.Printf("Username:   %s\n", db.MyIdentity.Name)
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(db.MyIdentity.PublicKey))
}

func AddContact(r *bufio.Reader, db *LocalDB) {
	fmt.Print("Type ID of friend to add: ")
	name := ReadInput(r)
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
	SaveDB(db)

	fmt.Printf("Added friend '%s'.\n", name)
}

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

func ReadInput(r *bufio.Reader) string {
	input, _ := r.ReadString('\n')
	return strings.TrimSpace(input)
}

func SaveDB(db *LocalDB) {
	encData, err := encryptDB(db)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to encrypt database before saving: %v\n", err)
		return
	}
	os.WriteFile(DBFile, encData, 0600)
}
