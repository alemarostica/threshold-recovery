// This is the CONTROLLER, or the handler of HTTP requests
package api

import (
	"bytes"
	"cmp"
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

var (
	inbox      = make(map[string][]keyexchange.Message)
	inboxMutex sync.RWMutex

	// a bit controintuitivo perché il signer ha dentro la sessione e non viceversa
	// but oh well
	activeSignings  = make(map[string]*SigningSession)
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

// TODO: bisogna signare tipo tutte le richieste della signature e verificare, damn
// E aggiornare il logging con la roba signata

// Register the endpoints
// Every specific endpoint will execute the specific handler
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /liveness", h.handleLiveness)
	mux.HandleFunc("POST /participants", h.handleParticipantRegister)
	mux.HandleFunc("GET /participants", h.handleGetParticipants)
	mux.HandleFunc("POST /shares/send", h.handlePostMessage)
	mux.HandleFunc("GET /shares/messages", h.handleGetMessages)
	mux.HandleFunc("POST /sign/init", h.handleSignInit)
	mux.HandleFunc("POST /sign/setm1", h.handleSetM1)
	mux.HandleFunc("POST /sign/setm2", h.handleSetM2)
	mux.HandleFunc("POST /sign/getm1", h.handleGetM1)
	mux.HandleFunc("POST /sign/getm2", h.handleGetM2)
	mux.HandleFunc("POST /sign/part", h.handleSendPart)
	mux.HandleFunc("POST /sign/getSign", h.handleGetSign)
}

func (h *Handler) handleGetSign(w http.ResponseWriter, r *http.Request) {
	var req GetPartialSigns
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	if !(len(foundSession.Materials1) == len(foundSession.Signer.GetIndices())) ||
		!(len(foundSession.Materials2) == len(foundSession.Signer.GetIndices())) {
		http.Error(w, "Not all material is present", http.StatusServiceUnavailable)
		return
	}

	if len(foundSession.PartialSignatures) == len(foundSession.Signer.GetIndices()) {
		// sort
		slices.SortFunc(foundSession.PartialSignatures, func(a, b crypto.PartialSignature) int {
			return cmp.Compare(a.GetIndex(), b.GetIndex())
		})
	} else {
		http.Error(w, "Not all partial signatures recevied yet.", http.StatusServiceUnavailable)
		return
	}

	resp := &GetPartialSignsResp{
		PartialSignatures: foundSession.PartialSignatures,
	}

	// TODO: aggiungere logica che elimina la sessione quando quando tutti hanno retrievato la signature

	log := fmt.Sprintf("SIGNATURE: %s tried to retrieve signature\n", "USERNAME_PLACEHOLDER")
	h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignatureRetrive, log)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleSendPart(w http.ResponseWriter, r *http.Request) {
	var req SendPartialSign
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	if !(len(foundSession.Materials1) == len(foundSession.Signer.GetIndices())) ||
		!(len(foundSession.Materials2) == len(foundSession.Signer.GetIndices())) {
		http.Error(w, "Not all material is present", http.StatusServiceUnavailable)
		return
	}

	foundSession.PartialSignatures = append(foundSession.PartialSignatures, req.PartialSignature)

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleGetM1(w http.ResponseWriter, r *http.Request) {
	var req GetM1Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	if !(len(foundSession.Materials1) == len(foundSession.Signer.GetIndices())) ||
		!(len(foundSession.Materials2) == len(foundSession.Signer.GetIndices())) {
		http.Error(w, "Not all material is present", http.StatusServiceUnavailable)
		return
	}

	if !foundSession.Sorted {
		sortMaterials(foundSession)
	}

	if !foundSession.Verified {
		if err := verifyNonces(foundSession); err != nil {
			http.Error(w, "Failure verifying nonces", http.StatusExpectationFailed)
			return
		}
	}

	var resp_array []M1_dto
	for _, item := range foundSession.Materials1 {
		resp_array = append(resp_array, M1_dto{
			Ci:    item.GetCommit(),
			Index: item.GetIndex(),
		})
	}
	resp := &GetM1Response{
		M1Array: resp_array,
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleGetM2(w http.ResponseWriter, r *http.Request) {
	var req GetM2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	if !(len(foundSession.Materials1) == len(foundSession.Signer.GetIndices())) ||
		!(len(foundSession.Materials2) == len(foundSession.Signer.GetIndices())) {
		http.Error(w, "Not all material is present", http.StatusServiceUnavailable)
		return
	}

	if !foundSession.Sorted {
		sortMaterials(foundSession)
	}

	if !foundSession.Verified {
		if err := verifyNonces(foundSession); err != nil {
			http.Error(w, "Failure verifying nonces", http.StatusExpectationFailed)
			return
		}
	}

	var resp_array []M2_dto
	for _, item := range foundSession.Materials2 {
		resp_array = append(resp_array, M2_dto{
			Index: item.GetIndex(),
			Ri:    item.Ri.Bytes(),
		})
	}
	resp := &GetM2Response{
		M2Array: resp_array,
	}

	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) handleSetM1(w http.ResponseWriter, r *http.Request) {
	var req SetM1Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	var m1 crypto.MaterialToSend1
	m1.SetIndex(crypto.ParticipantID(req.Index))
	m1.SetCommit(req.Ci)
	foundSession.Materials1 = append(foundSession.Materials1, m1)

	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleSetM2(w http.ResponseWriter, r *http.Request) {
	var req SetM2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	found := ""
	var foundSession *SigningSession
	for i, signingSession := range activeSignings {
		session := signingSession.Signer.GetSession()
		if bytes.Equal(session.GetID(), req.SessionID) {
			found = i
			foundSession = signingSession
		}
	}

	if found == "" {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	var m2 crypto.MaterialToSend2
	m2.SetIndex(crypto.ParticipantID(req.Index))
	Ri, _ := new(crypto.Point).SetBytes(req.Ri)
	m2.SetRi(*Ri)
	foundSession.Materials2 = append(foundSession.Materials2, m2)

	slices.SortFunc(foundSession.Materials2, func(a, b crypto.MaterialToSend2) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})

	w.WriteHeader(http.StatusOK)
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
		session := signingSession.Signer.GetSession()
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:    "ready",
			Message:   "Session already active",
			SessionID: session.GetID(),
			VectorV:   session.GetIndices(),
			Usernames: session.GetUsernames(),
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
		pending.Usernames = append(pending.Usernames, req.WalletUsername)
	}

	// hit threshold?
	if len(pending.Participants) >= pending.Threshold {
		session, err := crypto.NewSession(pending.Participants, pending.Usernames, pending.Threshold, pending.TotalN)
		if err != nil {
			http.Error(w, "Failed to create crypto session", http.StatusInternalServerError)
			return
		}

		var serverPart crypto.Server
		share, err := new(crypto.Scalar).SetCanonicalBytes(wallet.ServerShare)
		if err != nil {
			http.Error(w, "Could not rebuild server share", http.StatusInternalServerError)
		}
		serverPart.SetShare(*share)
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

		signingSession := &SigningSession{
			Signer:            ss,
			Materials1:        *new([]crypto.MaterialToSend1),
			Materials2:        *new([]crypto.MaterialToSend2),
			PartialSignatures: *new([]crypto.PartialSignature),
			Message:           []byte("transaction to sign"),
			Sorted:            false,
			Verified:          false,
			WalletPubKeyHex:   walletHex,
		}

		activeSignings[walletHex] = signingSession
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

		// Should they be ordered?
		signingSession.Materials1 = append(signingSession.Materials1, m1)
		signingSession.Materials2 = append(signingSession.Materials2, m2)

		ss.SetPartialSignature(signingSession.Message)
		sPartialSign := ss.GetPartialSignature()
		signingSession.PartialSignatures = append(signingSession.PartialSignatures, sPartialSign)

		h.Audit.Log(walletHex, core.EventSignAttempt, "Recovery threshold reached, session started.")
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:      "ready",
			Message:     "Threshold reached, session started.",
			VectorV:     session.GetIndices(),
			JoinedCount: len(pending.Participants),
			Threshold:   pending.Threshold,
			SessionID:   session.GetID(),
			P:           point.Bytes(),
			Usernames:   session.GetUsernames(),
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
		ServerShare:         req.ServerShare,
		Commitments:         req.Commitments,
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
