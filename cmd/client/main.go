package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	baseURL       = "http://localhost:8080"
	testThreshold = 5 * time.Second
)

func main() {
	pubKey := []byte("mock_pub_key_123")
	pubKeyHex := fmt.Sprintf("%x", pubKey)

	fmt.Println("STARTING SCENARIO: Threshold Recovery Simulation")
	fmt.Println("------------------------------------------------")

	// Register
	fmt.Printf("\n[1] Registering wallet '%s' with %s inactivity threshold...\n", pubKey, testThreshold)

	registerPayload := map[string]interface{}{
		"public_key":           pubKey,
		"encrypted_share":      []byte("mock_secret_share"),
		"share_commitment":     []byte("mock_commitment"),
		"inactivity_threshold": testThreshold.Nanoseconds(),
	}

	if status := sendRequest("POST", "/register", registerPayload); status != http.StatusCreated {
		log.Fatalf("Registration failed with status: %d", status)
	}

	// Check status
	// Should not be recoverable
	fmt.Println("\n [2] Checking status immediately...")
	checkStatus(pubKeyHex)

	// Send liveness ping
	fmt.Println("\n[3] Sending liveness signal...")

	ts := time.Now().Unix()
	// Works because of MockVerifier
	livenessPayload := map[string]interface{}{
		"public_key": pubKey,
		"timestamp":  ts,
		"signature":  []byte("valid_signature_placeholder"),
	}

	if status := sendRequest("POST", "/liveness", livenessPayload); status != 200 {
		log.Fatalf("Liveness update failed: %s)", status)
	}

	// Attempt early recovery, should fail
	fmt.Println("\n[4] Attempting recovery too early...")
	signPayload := map[string]interface{}{
		"public_key": pubKey,
		"message": "transaction_payload_hex",
	}
	// 403 Forbidden is expected
	sendRequest("POST", "/recover", signPayload)

	// Wait for timeout
	fmt.Printf("\n[5] Waiting %v for Dead Man switch to trigger...\n", testThreshold)
	time.Sleep(testThreshold + 2*time.Second)

	// Check status after timeout, should be recoverable
	fmt.Println("\n[6] Checking status after timeout...")
	checkStatus(pubKeyHex)

	// Attempt recovery
	fmt.Println("\n[7] Attempting recovery after timeout...")
	sendRequest("POST", "/recover", signPayload)

	fmt.Println("------------------------------------------------")
	fmt.Println("SCENARIO COMPLETED")
}

func sendRequest(method, endpoint string, data interface{}) int {
	jsonData, _ := json.Marshal(data)
	req, _ := http.NewRequest(method, baseURL+endpoint, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Request error: %v", err)
		return 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("   -> %s %s | Status: %s\n", method, endpoint, resp.Status)
	if len(body) > 0 {
		fmt.Printf("   -> Response: %s\n", string(body))
	}
	return resp.StatusCode
}

func checkStatus(id string) {
	resp, err := http.Get(baseURL + "/status/" + id)
	if err != nil {
		log.Printf("Error getting status: %v", err)
		return
	}

	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("   -> Status check: %s\n", string(body))
}
