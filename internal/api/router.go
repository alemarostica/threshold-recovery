// This is the CONTROLLER, or the handler of HTTP requests
package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/keyexchange"
	"time"

	"filippo.io/edwards25519"
)

type PendingSign struct {
	WalletPubKeyHex string
	Threshold       int
	TotalN          int
	Participants    []crypto.ParticipantID
}

var (
	inbox      = make(map[string][]keyexchange.Message)
	inboxMutex sync.RWMutex

	// a bit controintuitivo perché il signer ha dentro la sessione e non viceversa
	// but oh well
	activeSignings  = make(map[string]*crypto.ServerSigner)
	pendingSignings = make(map[string]*PendingSign)
	signMu          sync.Mutex
)

// Define what the backend can do
// Interface to swap memory more easily
// Every WalletService var implements the following functions implicitly
type WalletService interface {
	GetWallet(pubKey []byte, userPubKey ed25519.PublicKey) (*core.Wallet, error)
	UpdateLiveness(pubKey []byte, userPubKey ed25519.PublicKey) error
	RegisterWallet(w *core.Wallet, userPubKey ed25519.PublicKey) error
	DeriveFriendSlot(walletPubKey, friendPubKey []byte) string
	SaveParticipant(p *core.Participant) error
	GetParticipant(id string) (*core.Participant, uint64, error)
}

type Handler struct {
	Service WalletService
	Audit   core.AuditLogger
	PrivKey ed25519.PrivateKey
	Alpha   *edwards25519.Scalar
}

func NewHandler(
	s WalletService,
	a core.AuditLogger,
	privKey ed25519.PrivateKey,
	alpha *edwards25519.Scalar,
) *Handler {
	return &Handler{
		Service: s,
		Audit:   a,
		PrivKey: privKey,
		Alpha:   alpha,
	}
}

// Register the endpoints
// Every specific endpoint will execute the specific handler
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /liveness", h.handleLiveness)
	mux.HandleFunc("POST /participants", h.handleParticipantRegister)
	mux.HandleFunc("GET /participants", h.handleGetParticipants)
	mux.HandleFunc("POST /relay/send", h.handlePostMessage)
	mux.HandleFunc("GET /relay/messages", h.handleGetMessages)
	mux.HandleFunc("POST /sign/init", h.handleSignInit)
}

func (h *Handler) handleSignInit(w http.ResponseWriter, r *http.Request) {
	var req SignInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	participant, _, err := h.Service.GetParticipant(req.WalletUsername)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	wallet, err := h.Service.GetWallet(req.WalletPubKey, participant.PublicKey)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	if !wallet.IsRecoverable() {
		h.Audit.Log(hex.EncodeToString(req.WalletPubKey), core.EventSignBlocked, "Attempted to sign before expiration.")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:  "active",
			Message: "The wallet is still active. recovery is not yet allowed",
		})
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	walletHex := hex.EncodeToString(req.WalletPubKey)

	if signingSession, active := activeSignings[walletHex]; active {
		session := signingSession.GetSession()
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:    "ready",
			Message:   "Session already active",
			SessionID: session.GetID(),
			VectorV:   session.GetIndices(),
		})
		return
	}

	// has session been formed?
	pending, exists := pendingSignings[walletHex]
	if !exists {
		pending = &PendingSign{
			WalletPubKeyHex: walletHex,
			Threshold:       wallet.ThresholdParams.K,
			TotalN:          wallet.ThresholdParams.N,
			Participants:    []crypto.ParticipantID{crypto.ServerID},
		}
		pendingSignings[walletHex] = pending
	}

	// Il partecipante partecipa già?
	alreadyJoined := slices.Contains(pending.Participants, req.ParticipantID)
	if !alreadyJoined {
		pending.Participants = append(pending.Participants, req.ParticipantID)
	}

	// hit threshold?
	if len(pending.Participants) >= pending.Threshold {
		session, err := crypto.NewSession(pending.Participants, pending.Threshold, pending.TotalN)
		if err != nil {
			http.Error(w, "Failed to create crypto session", http.StatusInternalServerError)
			return
		}

		var serverPart crypto.Server
		serverPart.SetShare(wallet.ServerShare)
		serverPart.SetParams(&wallet.ThresholdParams)

		var ss crypto.ServerSigner
		ss.SetServer(serverPart)
		ss.SetIndices(session.GetIndices())
		ss.SetSession(session)
		ss.SetLagrangeCoefficient()
		point, _ := new(crypto.Point).SetBytes(wallet.P)
		ss.SetP(*point)

		// what is this indexhash all about?
		session.SetIndexHash(ss.GetIndices())
		session.SetID(nil) // bit ugly?

		activeSignings[walletHex] = &ss
		delete(pendingSignings, walletHex)

		var nonce crypto.NonceShare
		if err := nonce.SetIndex(crypto.ServerID); err != nil {
			http.Error(w, "Signing error: index", http.StatusInternalServerError)
			return
		}

		if err := nonce.Setri(); err != nil {
			http.Error(w, "Signing error: ri", http.StatusInternalServerError)
			return
		}

		if err := nonce.SetRi(); err != nil {
			http.Error(w, "Signing error: Ri", http.StatusInternalServerError)
			return
		}

		nonce.SetCommit(session)
		ss.SetNonce(nonce)

		ci, err := nonce.GetCommit()
		if err != nil {
			http.Error(w, "Signing error: m1", http.StatusInternalServerError)
			return
		}
		
		var m1 crypto.MaterialToSend1
		m1.SetIndex(nonce.GetIndex())
		m1.SetCommit(ci)

		ss.SetMaterialToSend1(m1)

		Ri, err := nonce.GetRi()
		if err != nil {
			http.Error(w, "Signing error, m2", http.StatusInternalServerError)
			return
		}

		var m2 crypto.MaterialToSend2
		m2.SetIndex(nonce.GetIndex())
		m2.SetRi(*Ri)

		ss.SetMaterialToSend2(m2)

		h.Audit.Log(walletHex, core.EventSignAttempt, "Recovery threshold reached, session started.")
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:      "ready",
			Message:     "Threshold reached, session started.",
			VectorV:     session.GetIndices(),
			JoinedCount: len(pending.Participants),
			Threshold:   pending.Threshold,
			SessionID:   session.GetID(),
			// Ci va il point anche qua
		})
	}

	json.NewEncoder(w).Encode(SignInitResponse{
		Status:      "waiting",
		Message:     "waiting for more participants",
		JoinedCount: len(pending.Participants),
		Threshold:   pending.Threshold,
	})
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

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit, protects against DoS

	// Decode the request
	var signedReq SignedRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil {
		http.Error(w, "Participant does not exist", http.StatusForbidden)
		return
	}

	if !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		http.Error(w, "Invalid request signature", http.StatusUnauthorized)
		return
	}

	// Validate the input
	if len(req.PublicKey) == 0 {
		http.Error(w, "Missing Public Key", http.StatusBadRequest)
		return
	}

	var serverShare crypto.Scalar
	if _, err := serverShare.SetCanonicalBytes(req.ServerShare); err != nil {
		http.Error(w, "Invalid server share encoding", http.StatusBadRequest)
		return
	}

	var rebuiltCommitments crypto.Commitment
	for _, b := range req.Commitments {
		p, _ := edwards25519.NewIdentityPoint().SetBytes(b)
		rebuiltCommitments = append(rebuiltCommitments, *p)
	}

	var serverPart crypto.Server
	serverPart.SetShare(serverShare)
	if ok, err := serverPart.VerifyConsistency(&rebuiltCommitments); err != nil {
		http.Error(w, "Error while verifying share.", http.StatusInternalServerError)
		return
	} else if !ok {
		http.Error(w, "Share is not consistent.", http.StatusNotAcceptable)
		return
	}

	// Map the received DTO to the model
	wallet := &core.Wallet{
		PublicKey:           req.PublicKey,
		ServerShare:         serverShare,
		Commitments:         rebuiltCommitments,
		LastActivity:        time.Now(),
		InactivityThreshold: req.InactivityThreshold,
		// Default expiration = Now + Threshold
		// TODO: change if necessary
		ExpirationDate:  time.Now().Add(req.InactivityThreshold),
		ThresholdParams: req.PubParams,
	}

	// Save it
	if err := h.Service.RegisterWallet(wallet, participant.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	pubKeyHex := hex.EncodeToString(wallet.PublicKey)
	h.Audit.Log(pubKeyHex, core.EventRegister, "Success")

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Decode the request
	var signedReq SignedLivenessRequest
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil {
		fmt.Printf("Could not retrieve participant '%s': %v\n", req.Username, err)
		return
	}

	if !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		http.Error(w, "Invalid request signature", http.StatusUnauthorized)
		return
	}

	// Let's try to prevent replay attacks
	requestTime := time.Unix(req.Timestamp, 0)
	if time.Since(requestTime).Abs() < time.Minute {
		http.Error(w, "Invalid timestamp", http.StatusUnauthorized)
		return
	}

	// Update Liveness
	if err := h.Service.UpdateLiveness(req.PublicKey, participant.PublicKey); err != nil {
		http.Error(w, "Failed to update liveness", http.StatusInternalServerError)
		return
	}

	h.Audit.Log(string(req.PublicKey), core.EventLiveness, "Liveness updated via signed timestamp")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"liveness_updated"}`))
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
		return
	}

	serverPubKey := h.PrivKey.Public().(ed25519.PublicKey)

	resp := RegisterParticipantResponse{
		ServerPublicKey: serverPubKey,
		Alpha:           *h.Alpha,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
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
