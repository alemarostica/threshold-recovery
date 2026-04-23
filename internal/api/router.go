// This is the CONTROLLER, or the handler of HTTP requests
package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/keyexchange"
	"time"
)

var (
	inbox      = make(map[string][]keyexchange.Message)
	inboxMutex sync.RWMutex
)

// Define what the backend can do
// Interface to swap memory more easily
// Every WalletService var implements the following functions implicitly
type WalletService interface {
	GetWallet(pubKey []byte) (*core.Wallet, error)
	UpdateLiveness(pubKey []byte) error
	RegisterWallet(w *core.Wallet) error
	DeriveFriendSlot(walletPubKey, friendPubKey []byte) string
	SaveParticipant(p *core.Participant) error
	GetParticipant(id string) (*core.Participant, uint64, error)
}

type Handler struct {
	Service  WalletService
	Verifier crypto.Verifier
	Audit    core.AuditLogger
	PrivKey  ed25519.PrivateKey
}

func NewHandler(
	s WalletService,
	v crypto.Verifier,
	a core.AuditLogger,
	privKey ed25519.PrivateKey,
) *Handler {
	return &Handler{
		Service:  s,
		Verifier: v,
		Audit:    a,
		PrivKey:  privKey,
	}
}

// Register the endpoints
// Every specific endpoint will execute the specific handler
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegister)
	// mux.HandleFunc("POST /liveness", h.handleLiveness)
	mux.HandleFunc("GET /status/{id}", h.handleStatus)
	mux.HandleFunc("POST /recover", h.handleSignRecovery)
	mux.HandleFunc("POST /mailbox/pickup", h.handleMailboxPickup)
	mux.HandleFunc("POST /participants", h.handleParticipantRegister)
	mux.HandleFunc("GET /participants", h.handleGetParticipants)
	mux.HandleFunc("POST /relay/send", h.handlePostMessage)
	mux.HandleFunc("GET /relay/messages", h.handleGetMessages)
}

func (h *Handler) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	var msg keyexchange.Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}

	inboxMutex.Lock()
	inbox[msg.To] = append(inbox[msg.To], msg)
	inboxMutex.Unlock()

	w.WriteHeader(http.StatusAccepted)
	// TODO: remove
	fmt.Printf("[Relay] Message %s from %s to %s stored\n", msg.Type, msg.From, msg.To)
}

func (h *Handler) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "user_id is required", http.StatusBadRequest)
		return
	}

	inboxMutex.Lock()
	msgs := inbox[userID]
	delete(inbox, userID)
	inboxMutex.Unlock()

	if msgs == nil {
		msgs = []keyexchange.Message{}
	}

	json.NewEncoder(w).Encode(msgs)
}

func (h *Handler) handleMailboxPickup(w http.ResponseWriter, r *http.Request) {
	var req SharePickupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// fmt.Printf("req.WalletID: %v\n", req.PubKey)

	wallet, err := h.Service.GetWallet(req.PubKey)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// Derive the slot ID from the provided friend's public key
	slotID := h.Service.DeriveFriendSlot([]byte(wallet.PublicKey), req.FriendPubKey)

	// Gatekeep is the user is not dead
	if !wallet.IsRecoverable() {
		h.Audit.Log(wallet.ID, core.EventSharePickupDenied, "Slot "+slotID+" tried to pick up share too early")
		http.Error(w, "RECOVERY LOCKED: User is still active.", http.StatusForbidden)
		return
	}

	// Authentication will have to be here, which kind?
	shareBlob, ok := wallet.FriendShares[slotID]
	if !ok {
		http.Error(w, "No share found for this ID", http.StatusNotFound)
		return
	}

	h.Audit.Log(wallet.ID, core.EventSharePickup, "Friend "+slotID+" collected share")

	resp := SharePickupResponse{
		ShareBlob: shareBlob,
		Comms:     wallet.Commitments,
	}

	json.NewEncoder(w).Encode(resp)
}

// Returns the status of a specific wallet
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit, protects against DoS

	// Decode the request
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate the input
	if len(req.PublicKey) == 0 {
		http.Error(w, "Missing Public Key", http.StatusBadRequest)
		return
	}

	// Validate Cryptography
	if !h.Verifier.VerifyShare(req.ServerShare, req.Commitments) {
		http.Error(w, "Invalid Share Commitment", http.StatusForbidden)
		return
	}

	mailbox := make(map[string][]byte)
	for _, item := range req.FriendShares {
		slotID := h.Service.DeriveFriendSlot(req.PublicKey, item.FriendPubKey)
		mailbox[slotID] = item.EncryptedBlob
	}

	// Map the received DTO to the model
	wallet := &core.Wallet{
		PublicKey:           req.PublicKey,
		ServerShare:         req.ServerShare,
		Commitments:         req.Commitments,
		LastActivity:        time.Now(),
		InactivityThreshold: req.InactivityThreshold,
		// Default expiration = Now + Threshold
		// TODO: change if necessary
		ExpirationDate: time.Now().Add(req.InactivityThreshold),
		FriendShares:   mailbox,
	}

	// Save it
	if err := h.Service.RegisterWallet(wallet); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	pubKeyHex := hex.EncodeToString(wallet.PublicKey)
	h.Audit.Log(pubKeyHex, core.EventRegister, "Success")

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

// É meglio che il
func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Decode the request
	var req LivenessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Let's try to prevent replay attacks
	requestTime := time.Unix(req.Timestamp, 0)
	if time.Since(requestTime).Abs() > 5*time.Minute {
		http.Error(w, "Invalid timestamp", http.StatusUnauthorized)
		return
	}

	// Retrieve the wallet
	if _, err := h.Service.GetWallet(req.PublicKey); err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	// The verification

	// Update Liveness
	if err := h.Service.UpdateLiveness(req.PublicKey); err != nil {
		http.Error(w, "Failed to update liveness", http.StatusInternalServerError)
		return
	}

	h.Audit.Log(string(req.PublicKey), core.EventLiveness, "Liveness updated via signed timestamp")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"liveness_updated"}`))
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	pubKeyHex := r.PathValue("id")
	pubKey, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		http.Error(w, "Invalid Public Key Hex", http.StatusBadRequest)
		return
	}

	wallet, err := h.Service.GetWallet(pubKey)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	response := map[string]any{
		"recoverable":         wallet.IsRecoverable(),
		"last_activity":       wallet.LastActivity,
		"time_until_recovery": time.Until(wallet.LastActivity.Add(wallet.InactivityThreshold)).String(),
	}

	h.Audit.Log(pubKeyHex, core.EventStatus, "")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleSignRecovery(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Recover wallet
	wallet, err := h.Service.GetWallet(req.PublicKey)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	pubKeyHex := hex.EncodeToString(wallet.PublicKey)

	// Verify if user is dead
	if !wallet.IsRecoverable() {
		h.Audit.Log(pubKeyHex, core.EventSignBlocked, "Somebody tried to recover wallet while user is still alive!")
		http.Error(w, "RECOVERY LOCKED", http.StatusForbidden)
		return
	}

	// Here dead-man switch must have triggered
	// Server accepts using its share

	partialSig, err := h.Verifier.SignPartial(wallet.ServerShare, []byte(req.Message))
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

func (h *Handler) handleParticipantRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterParticipantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validation
	if req.ID == "" || len(req.PublicKey) == 0 {
		http.Error(w, "ID or PublicKey required", http.StatusBadRequest)
		return
	}

	p := &core.Participant{
		ID:        req.ID,
		PublicKey: req.PublicKey,
		CreatedAt: time.Now(),
	}

	if err := h.Service.SaveParticipant(p); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) handleGetParticipants(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	p, epoch, err := h.Service.GetParticipant(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	respData := ParticipantResponse{
		ID:        p.ID,
		PublicKey: p.PublicKey,
		Epoch:     epoch,
	}

	dataBytes, _ := json.Marshal(respData)
	signature := ed25519.Sign(h.PrivKey, dataBytes)

	signedResp := SignedParticipantResponse{
		Data:      respData,
		Signature: signature,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signedResp)
}
