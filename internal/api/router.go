// This is the CONTROLLER, or the handler of HTTP requests
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/crypto"
	"time"
)

// Define what the backend can do
// Interface to swap memory more easily
// Every WalletService var implements the following functions implicitly
type WalletService interface {
	GetWallet(id string) (*core.Wallet, error)
	UpdateLiveness(id string) error
	RegisterWallet(w *core.Wallet) error
}

type Handler struct {
	Service  WalletService
	Verifier crypto.Verifier
	Audit    core.AuditLogger
}

func NewHandler(s WalletService, v crypto.Verifier, a core.AuditLogger) *Handler {
	return &Handler{
		Service:  s,
		Verifier: v,
		Audit:    a,
	}
}

// Register the endpoints
// Every specific endpoint will execute the specific handler
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /liveness", h.handleLiveness)
	mux.HandleFunc("GET /status/{id}", h.handleStatus)
	mux.HandleFunc("POST /recover", h.handleSignRecovery)
}

// Returns the status of a specific wallet
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Decode the request
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate the input
	if req.ID == "" || len(req.PublicKey) == 0 {
		http.Error(w, "Missing ID or Publick Key", http.StatusBadRequest)
		return
	}

	// Validate Cryptography
	if !h.Verifier.VerifyShare(req.EncryptedShare, req.ShareCommitment) {
		http.Error(w, "Invalid Share Commitment", http.StatusForbidden)
		return
	}

	// Map the received DTO to the model
	wallet := &core.Wallet{
		ID:                  req.ID,
		PublicKey:           req.PublicKey,
		EncryptedShare:      req.EncryptedShare,
		LastActivity:        time.Now(),
		InactivityThreshold: req.InactivityThreshold,
		// Default expiration = Now + Threshold
		// TODO: change if necessary
		ExpirationDate: time.Now().Add(req.InactivityThreshold),
	}

	// Save it
	if err := h.Service.RegisterWallet(wallet); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	details := fmt.Sprintf("PKey: %s, share: %s, threshold: %s, exp: %s",
		wallet.PublicKey,
		wallet.EncryptedShare,
		wallet.InactivityThreshold,
		wallet.ExpirationDate,
	)
	h.Audit.Log(wallet.ID, core.EventRegister, details)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Decode the request
	var req LivenessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Let's try to prevent replay attacks
	requestTime := time.Unix(req.Timestamp, 0)
	now := time.Now()

	// 5 minute window for clock skew/latency
	window := 5 * time.Minute
	if requestTime.Before(now.Add(-window)) || requestTime.After(now.Add(window)) {
		h.Audit.Log(req.ID, core.EventLiveness, "REPLAY ATTACK DETECTED: Timestamp outside window")
		http.Error(w, "Request timestamp is too old or too far in the future", http.StatusUnauthorized)
		return
	}

	// Retrieve the wallet
	wallet, err := h.Service.GetWallet(req.ID)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// Verify the signature
	msg := fmt.Sprintf("%s:%d", req.ID, req.Timestamp)
	if !h.Verifier.VerifySignature(wallet.PublicKey, []byte(msg), req.Signature) {
		h.Audit.Log(req.ID, core.EventLiveness, "Invalid signature for liveness")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Update Liveness
	if err := h.Service.UpdateLiveness(req.ID); err != nil {
		http.Error(w, "Failed to update liveness", http.StatusInternalServerError)
		return
	}

	h.Audit.Log(req.ID, core.EventLiveness, "Liveness updated via signed timestamp")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"liveness_updated"}`))
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	wallet, err := h.Service.GetWallet(id)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":                  wallet.ID,
		"recoverable":         wallet.IsRecoverable(),
		"last_activity":       wallet.LastActivity,
		"time_until_recovery": time.Until(wallet.LastActivity.Add(wallet.InactivityThreshold)).String(),
	}

	h.Audit.Log(wallet.ID, core.EventStatus, "")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleSignRecovery(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Recover wallet
	wallet, err := h.Service.GetWallet(req.ID)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// Verify if user is dead
	if !wallet.IsRecoverable() {
		h.Audit.Log(wallet.ID, core.EventSignBlocked, "Somebody tried to recover wallet while user is still alive!")
		http.Error(w, "RECOVERY LOCKED: User is active", http.StatusForbidden)
		return
	}

	// Here dead-man switch must have triggered
	// Server accepts using its share

	msgBytes := []byte(req.Message)

	partialSig, err := h.Verifier.SignPartial(wallet.EncryptedShare, msgBytes)
	if err != nil {
		h.Audit.Log(wallet.ID, core.EventSignAttempt, "")
		http.Error(w, "Signing failed", http.StatusInternalServerError)
		return
	}

	h.Audit.Log(wallet.ID, core.EventSignSuccess, "")
	// Answer with partial signature
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "recovery_success",
		"partial_signature": partialSig,
	})
}
