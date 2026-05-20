// Package api contains the HTTP handlers used by the recovery server.
package api

import (
	"cmp"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"threshold-recovery/internal/core"
	"threshold-recovery/internal/crypto"
	"threshold-recovery/internal/keyexchange"
	"time"

	"filippo.io/edwards25519"
)

var (
	// inbox temporarily stores key-exchange messages until the recipient polls them.
	//
	// This is an in-memory relay used by the prototype. Messages are not persisted
	// and are removed after retrieval.
	inbox      = make(map[string][]keyexchange.Message)
	inboxMutex sync.RWMutex

	// activeSignings stores signing sessions that have already reached the
	// recovery threshold. pendingSignings stores recovery attempts that are still
	// waiting for enough participants.
	activeSignings  = make(map[string]*SigningSession)
	pendingSignings = make(map[string]*PendingSign)
	signMu          sync.Mutex
)

// WalletService defines the storage operations required by the HTTP handlers.
//
// The interface keeps the API layer independent from the concrete storage
// backend used by the prototype.
type WalletService interface {
	GetWallet(pubKey []byte, userPubKey ed25519.PublicKey) (*core.Wallet, error)
	UpdateLiveness(pubKey []byte, userPubKey ed25519.PublicKey) error
	RegisterWallet(w *core.Wallet, userPubKey ed25519.PublicKey) error
	DeriveFriendSlot(walletPubKey, friendPubKey []byte) string
	SaveParticipant(p *core.Participant) error
	GetParticipant(id string) (*core.Participant, uint64, error)
	DeleteWallet(w *core.Wallet, userPubKey ed25519.PublicKey) error
}

// Handler groups the server dependencies used by the HTTP endpoints.
type Handler struct {
	Service WalletService
	Audit   core.AuditLogger
	PrivKey ed25519.PrivateKey
}

// NewHandler creates an API handler with the given storage service, audit
// logger, and server signing key.
func NewHandler(
	s WalletService,
	a core.AuditLogger,
	privKey ed25519.PrivateKey,
) *Handler {
	return &Handler{
		Service: s,
		Audit:   a,
		PrivKey: privKey,
	}
}

// RegisterRoutes registers all HTTP endpoints exposed by the recovery server.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegisterWallet)
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

// handleGetSign returns all partial signatures once the signing session is complete.
func (h *Handler) handleGetSign(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedGetPartialSigns
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
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

	signMu.Lock()
	defer signMu.Unlock()

	// Reject requests for unknown or expired signing sessions.
	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	// Check if the nonces have been verified
	if !foundSession.Verified {
		http.Error(w, "Session nonces not verified yet", http.StatusUnauthorized)
		return
	}

	if err := foundSession.Signer.SetR(foundSession.Materials2); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set aggregate R: %v", err), http.StatusInternalServerError)
		return
	}

	// Make the server's partial signature and add it
	err = foundSession.Signer.SetPartialSignature(foundSession.Message)
	if err != nil {
		http.Error(w, "Failed to set partial signature", http.StatusInternalServerError)
		return
	}
	serverPartialSig := foundSession.Signer.GetPartialSignature()

	serverSigAdded := false
	for _, sig := range foundSession.PartialSignatures {
		if sig.GetIndex() == serverPartialSig.GetIndex() {
			serverSigAdded = true
			break
		}
	}

	if !serverSigAdded {
		foundSession.PartialSignatures = append(foundSession.PartialSignatures, serverPartialSig)
	}

	expected := expectedSigningMaterialCount(foundSession)

	// Check if all necessary data has been submitted by clients
	if len(foundSession.Materials1) != expected ||
		len(foundSession.Materials2) != expected {
		http.Error(w, "Not all material is present", http.StatusUnauthorized)
		return
	}

	if len(foundSession.PartialSignatures) == expected {
		// Sort partial signatures by participant index before returning them.
		slices.SortFunc(foundSession.PartialSignatures, func(a, b crypto.PartialSignature) int {
			return cmp.Compare(a.GetIndex(), b.GetIndex())
		})
	} else {
		http.Error(w, "Not all partial signatures received yet.", http.StatusUnauthorized)
		return
	}

	var dtoSignatures []PartialSigMessage
	for _, sig := range foundSession.PartialSignatures {
		zScalar := sig.GetZ()
		dtoSignatures = append(dtoSignatures, PartialSigMessage{
			ParticipantID: sig.GetIndex(),
			Z:             zScalar.Bytes(),
		})
	}

	resp := &GetPartialSignsResp{
		PartialSignatures: dtoSignatures,
	}

	foundSession.RetrievedBy[req.Username] = true

	expectedFriends := expectedSigningMaterialCount(foundSession) - 1

	if len(foundSession.RetrievedBy) >= expectedFriends {
		// Once all participants have retrieved the partial signatures, the server
		// combines and verifies the final signature as a prototype consistency check.

		if err := foundSession.Signer.CombineSignature(foundSession.PartialSignatures); err != nil {
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Failure combining signature.")
		}

		bool, err := crypto.VerifySignature(foundSession.Signer.P, foundSession.Message, foundSession.Signer.GetSignature(), foundSession.Signer.GetSession())
		if err != nil {
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Could not verify signature.")
		}

		if bool {
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignSuccess, "Successfully verified signature!")
		} else {
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Signature did not verify.")
		}

		// After a successful recovery, remove the recovered wallet from persistent storage.
		walletOwner, _, err := h.Service.GetParticipant(foundSession.WalletOwner)
		if err != nil {
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Could not find wallet owner to delete wallet")
		} else {
			walletPubKey, _ := hex.DecodeString(foundSession.WalletPubKeyHex)

			wallet, err := h.Service.GetWallet(walletPubKey, walletOwner.PublicKey)

			if err != nil || wallet == nil {
				h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Failed to load wallet for deletion from persistent storage")
			} else {
				if err := h.Service.DeleteWallet(wallet, walletOwner.PublicKey); err != nil {
					h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignFail, "Failed to remove wallet from persistent storage")
				} else {
					h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignSuccess, "Successfully deleted wallet")
				}

				// Zeroize sensitive fields
				if wallet.ServerShare != nil {
					clear(wallet.ServerShare)
					runtime.KeepAlive(wallet.ServerShare)
				}
				if wallet.Commitments != nil {
					for i := range wallet.Commitments {
						clear(wallet.Commitments[i])
						runtime.KeepAlive(wallet.Commitments[i])
					}
					clear(wallet.Commitments)
					runtime.KeepAlive(wallet.Commitments)
				}
			}
		}

		// Close the signing session after the recovery flow has completed.
		delete(activeSignings, foundSession.WalletPubKeyHex)
		log := fmt.Sprintf("%s retrieved the last signature. Session closed.", req.Username)
		h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignSuccess, log)
	} else {
		log := fmt.Sprintf("%s retrieved signature (%d/%d)", req.Username, len(foundSession.RetrievedBy), expectedFriends)
		h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignatureRetrive, log)
	}

	json.NewEncoder(w).Encode(resp)
}

// handleSendPart receives a participant partial signature for an active session.
func (h *Handler) handleSendPart(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedSendPartialSign
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignAttempt, "Unauthorized attempt to send partial signatures")
		http.Error(w, "Participant does not exist", http.StatusUnauthorized)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	expected := expectedSigningMaterialCount(foundSession)

	if len(foundSession.Materials1) != expected ||
		len(foundSession.Materials2) != expected {
		http.Error(w, "Not all material is present", http.StatusServiceUnavailable)
		return
	}

	idx := req.PartialSignature.ParticipantID
	sess := foundSession.Signer.GetSession()

	if idx == crypto.ServerID {
		http.Error(w, "server partial signature is managed internally", http.StatusForbidden)
		return
	}

	if !sess.HasSigner(idx) {
		http.Error(w, "partial signature index is not part of this session", http.StatusForbidden)
		return
	}

	for _, existing := range foundSession.PartialSignatures {
		if existing.GetIndex() == idx {
			http.Error(w, "partial signature for this index already submitted", http.StatusConflict)
			return
		}
	}
	var z crypto.Scalar
	if _, err := z.SetCanonicalBytes(req.PartialSignature.Z); err != nil {
		http.Error(w, "Invalid Z scalar encoding", http.StatusBadRequest)
		return
	}

	var partSign crypto.PartialSignature
	partSign.SetIndex(&idx)
	partSign.SetZ(&z)

	foundSession.PartialSignatures = append(foundSession.PartialSignatures, partSign)

	w.WriteHeader(http.StatusOK)
}

// handleGetM1 returns the nonce commitments submitted for a signing session.
func (h *Handler) handleGetM1(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedGetM1Request
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
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

	signMu.Lock()
	defer signMu.Unlock()

	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}
	expected := expectedSigningMaterialCount(foundSession)

	if len(foundSession.Materials1) != expected {
		http.Error(w, "Not all m1 material is present", http.StatusServiceUnavailable)
		return
	}

	if !foundSession.Sorted {
		sortMaterials(foundSession)
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

// handleGetM2 verifies nonce openings and returns the revealed nonces.
func (h *Handler) handleGetM2(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedGetM2Request
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
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

	signMu.Lock()
	defer signMu.Unlock()
	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	expected := expectedSigningMaterialCount(foundSession)

	if len(foundSession.Materials1) != expected ||
		len(foundSession.Materials2) != expected {
		http.Error(w, "Not all nonce material is present", http.StatusServiceUnavailable)
		return
	}

	if !foundSession.Sorted {
		sortMaterials(foundSession)
	}

	if !foundSession.Verified {
		if err := verifyNonces(foundSession); err != nil {
			// Destroy session if nonce verification failed
			delete(activeSignings, foundSession.WalletPubKeyHex)
			h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignBlocked, "Nonce verification failed, session destroyed.")

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

// handleSetM1 receives a participant nonce commitment.
func (h *Handler) handleSetM1(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedSetM1Request
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignAttempt, "Unauthorized M1 set attempt")
		http.Error(w, "Participant does not exist", http.StatusForbidden)
		return
	}

	signMu.Lock()
	defer signMu.Unlock()

	idx := crypto.ParticipantID(req.Index)

	sess := foundSession.Signer.GetSession()
	if idx == crypto.ServerID {
		http.Error(w, "server material is managed internally", http.StatusForbidden)
		return
	}

	if !sess.HasSigner(idx) {
		http.Error(w, "index is not a signer of this session", http.StatusForbidden)
		return
	}

	for _, existing := range foundSession.Materials1 {
		if existing.GetIndex() == idx {
			http.Error(w, "m1 for this index already submitted", http.StatusConflict)
			return
		}
	}

	var m1 crypto.MaterialToSend1
	err = m1.SetIndex(idx)
	if err != nil {
		http.Error(w, "Failed to set m1 index while rebuilding m1", http.StatusInternalServerError)
		return
	}
	err = m1.SetCommit(req.Ci)
	if err != nil {
		http.Error(w, "Failed to set m1 commit while rebuilding m1", http.StatusInternalServerError)
		return
	}

	foundSession.Materials1 = append(foundSession.Materials1, m1)
	foundSession.Sorted = false
	foundSession.Verified = false

	h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignAttempt, fmt.Sprintf("Participant %s uploaded M1 commitments", req.Username))

	w.WriteHeader(http.StatusOK)
}

// handleSetM2 receives a participant nonce reveal.
func (h *Handler) handleSetM2(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedSetM2Request
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	foundSession, ok := findSigningSessionByID(req.SessionID)
	if !ok {
		http.Error(w, "A session with such ID does not exist", http.StatusNotFound)
		return
	}

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignAttempt, "Unauthorized M2 set attempt")
		http.Error(w, "Participant does not exist", http.StatusForbidden)
		return
	}
	signMu.Lock()
	defer signMu.Unlock()

	idx := crypto.ParticipantID(req.Index)

	sess := foundSession.Signer.GetSession()
	if idx == crypto.ServerID {
		http.Error(w, "server material is managed internally", http.StatusForbidden)
		return
	}

	if !sess.HasSigner(idx) {
		http.Error(w, "index is not a signer of this session", http.StatusForbidden)
		return
	}

	for _, existing := range foundSession.Materials2 {
		if existing.GetIndex() == idx {
			http.Error(w, "m2 for this index already submitted", http.StatusConflict)
			return
		}
	}

	Ri, err := new(crypto.Point).SetBytes(req.Ri)
	if err != nil {
		http.Error(w, "invalid Ri encoding", http.StatusBadRequest)
		return
	}

	var m2 crypto.MaterialToSend2
	err = m2.SetIndex(idx)
	if err != nil {
		http.Error(w, "Failed to set m2 index while rebuilding m2", http.StatusInternalServerError)
		return
	}
	err = m2.SetRi(*Ri)
	if err != nil {
		http.Error(w, "Failed to set m2 Ri while rebuilding m2", http.StatusInternalServerError)
		return
	}

	foundSession.Materials2 = append(foundSession.Materials2, m2)
	foundSession.Sorted = false
	foundSession.Verified = false

	h.Audit.Log(foundSession.WalletPubKeyHex, core.EventSignAttempt, fmt.Sprintf("Participant %s uploaded M2 commitments", req.Username))

	w.WriteHeader(http.StatusOK)
}

// handleSignInit joins a participant to a recovery attempt and creates the
// signing session once the threshold is reached.
func (h *Handler) handleSignInit(w http.ResponseWriter, r *http.Request) {
	var signedReq SignedSignInitRequest
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	dataBytes, _ := json.Marshal(req)

	participant, _, err := h.Service.GetParticipant(req.Requester)
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(req.Requester, core.EventSignBlocked, fmt.Sprintf("Unauthorized signature initialization attempt by %s", req.Requester))
		http.Error(w, "Participant does not exist", http.StatusForbidden)
		return
	}

	walletOwner, _, err := h.Service.GetParticipant(req.WalletUsername)
	if err != nil {
		http.Error(w, "Invalid wallet parameters", http.StatusBadRequest)
		return
	}

	wallet, err := h.Service.GetWallet(req.WalletPubKey, walletOwner.PublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("Wallet not found: %v", err), http.StatusNotFound)
		return
	}

	// Check if the wallet is recoverable, otherwise deny the request
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

	// If the threshold has already been reached, return the active signing session.
	if signingSession, active := activeSignings[walletHex]; active {
		session := signingSession.Signer.GetSession()
		vectorV := session.GetIndices()
		slices.Sort(vectorV)
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:      "ready",
			Message:     "Threshold reached, session started.",
			VectorV:     vectorV,
			JoinedCount: session.GetNumParticipants(),
			SessionID:   session.GetID(),
			P:           signingSession.Signer.P.Bytes(),
			Usernames:   session.GetUsernames(),
		})
		return
	}

	// Create a pending recovery attempt if this is the first participant joining.
	pending, exists := pendingSignings[walletHex]
	if !exists {
		pending = &PendingSign{
			WalletPubKeyHex: walletHex,
			Threshold:       wallet.ThresholdParams.K,
			TotalN:          wallet.ThresholdParams.N,
			Participants:    []crypto.ParticipantID{},
			Usernames:       []string{},
		}
		pendingSignings[walletHex] = pending
	}

	// Index 0 is reserved for the recovery server and cannot be claimed by clients.
	if req.ParticipantID == crypto.ServerID {
		http.Error(w, "server cannot join as a participant", http.StatusBadRequest)
		return
	}

	// Add the participant only if the index has not already joined this attempt.
	alreadyJoined := slices.Contains(pending.Participants, req.ParticipantID)
	if !alreadyJoined {
		pending.Participants = append(pending.Participants, req.ParticipantID)
		pending.Usernames = append(pending.Usernames, req.WalletUsername)
	}

	// Create the signing session once the recovery threshold is reached.
	if len(pending.Participants) >= pending.Threshold {
		session := &crypto.Session{}

		var err error

		// Bind the session to the selected participant indices.
		indices := append([]crypto.ParticipantID(nil), pending.Participants...)
		slices.Sort(indices)

		err = session.SetIndices(indices)
		if err != nil {
			http.Error(w, "Failed to set session indices", http.StatusInternalServerError)
			return
		}

		if err := session.SetID(nil); err != nil {
			http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
			return
		}

		err = session.SetIndexHash(session.GetIndices())
		if err != nil {
			http.Error(w, "Failed to session IndexHash", http.StatusInternalServerError)
			return
		}

		var serverPart crypto.Server
		share, err := new(crypto.Scalar).SetCanonicalBytes(wallet.ServerShare)
		if err != nil {
			http.Error(w, "Could not rebuild server share", http.StatusInternalServerError)
			return
		}

		err = serverPart.SetShare(*share)
		if err != nil {
			http.Error(w, "Failed to set server share", http.StatusInternalServerError)
			return
		}
		err = serverPart.SetParams(&wallet.ThresholdParams)
		if err != nil {
			http.Error(w, "Failed to set server parameters", http.StatusInternalServerError)
			return
		}

		var ss crypto.ServerSigner
		ss.SetServer(serverPart)
		err = ss.SetIndices(session.GetIndices())
		if err != nil {
			http.Error(w, "Failed to set signer indices", http.StatusInternalServerError)
			return
		}
		err = ss.SetSession(session)
		if err != nil {
			http.Error(w, "Failed to set signer session", http.StatusInternalServerError)
			return
		}
		err = ss.SetLagrangeCoefficient()
		if err != nil {
			http.Error(w, "Failed to set Lagrange coefficients", http.StatusInternalServerError)
			return
		}

		point, err := new(crypto.Point).SetBytes(wallet.P)
		if err != nil {
			http.Error(w, "Could not rebuild wallet public key", http.StatusInternalServerError)
			return
		}

		err = ss.SetP(*point)
		if err != nil {
			http.Error(w, "Failed to set signer public point", http.StatusInternalServerError)
			return
		}

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

		err = nonce.SetCommit(session)
		if err != nil {
			http.Error(w, "Failed to set server nonce commit", http.StatusInternalServerError)
			return
		}
		err = ss.SetNonce(nonce)
		if err != nil {
			http.Error(w, "Failed to set signer nonce", http.StatusInternalServerError)
			return
		}

		ci, err := nonce.GetCommit()
		if err != nil {
			http.Error(w, "Signing error: m1", http.StatusInternalServerError)
			return
		}

		var m1 crypto.MaterialToSend1
		err = m1.SetIndex(nonce.GetIndex())
		if err != nil {
			http.Error(w, "Failed to set m1 index", http.StatusInternalServerError)
			return
		}
		err = m1.SetCommit(ci)
		if err != nil {
			http.Error(w, "Failed to set m1 commit", http.StatusInternalServerError)
			return
		}
		err = ss.SetMaterialToSend1(m1)
		if err != nil {
			http.Error(w, "Failed to set server m1", http.StatusInternalServerError)
			return
		}

		Ri, err := nonce.GetRi()
		if err != nil {
			http.Error(w, "Signing error: m2", http.StatusInternalServerError)
			return
		}

		var m2 crypto.MaterialToSend2
		err = m2.SetIndex(nonce.GetIndex())
		if err != nil {
			http.Error(w, "Failed to set m2 index", http.StatusInternalServerError)
			return
		}
		err = m2.SetRi(*Ri)
		if err != nil {
			http.Error(w, "Failed to set m2 Ri", http.StatusInternalServerError)
			return
		}
		err = ss.SetMaterialToSend2(m2)
		if err != nil {
			http.Error(w, "Failed to set server m2", http.StatusInternalServerError)
			return
		}

		// Create session instance
		signingSession := &SigningSession{
			Signer:            ss,
			Materials1:        []crypto.MaterialToSend1{m1},
			Materials2:        []crypto.MaterialToSend2{m2},
			PartialSignatures: []crypto.PartialSignature{},
			Message:           []byte("transaction to sign"),
			Sorted:            false,
			Verified:          false,
			WalletPubKeyHex:   walletHex,
			WalletOwner:       req.WalletUsername,
			RetrievedBy:       make(map[string]bool),
		}

		activeSignings[walletHex] = signingSession
		delete(pendingSignings, walletHex)

		h.Audit.Log(walletHex, core.EventSignThreshold, fmt.Sprintf("Threshold for wallet %s reached, session started", walletHex))

		// Expire inactive signing sessions after five minutes.
		go func(wHex string) {
			time.Sleep(5 * time.Minute)
			signMu.Lock()
			defer signMu.Unlock()
			if _, exists := activeSignings[wHex]; exists {
				delete(activeSignings, wHex)
				h.Audit.Log(wHex, core.EventSignBlocked, "Session timed out and was cleaned.")
			}
		}(walletHex)

		h.Audit.Log(walletHex, core.EventSignAttempt, "Recovery threshold reached, session started.")
		vectorV := session.GetIndices()
		slices.Sort(vectorV)
		json.NewEncoder(w).Encode(SignInitResponse{
			Status:      "ready",
			Message:     "Threshold reached, session started.",
			VectorV:     vectorV,
			JoinedCount: len(pending.Participants),
			SessionID:   session.GetID(),
			P:           point.Bytes(),
			Usernames:   session.GetUsernames(),
		})
		return
	} else {
		// The session is active, but not enough participants showed up yet
		resp := &SignInitResponse{
			Status:  "waiting",
			Message: "waiting for participants",
		}
		json.NewEncoder(w).Encode(resp)
	}

	json.NewEncoder(w).Encode(SignInitResponse{
		Status:      "waiting",
		Message:     "waiting for more participants",
		JoinedCount: len(pending.Participants),
	})
}

// handlePostMessage relays a key-exchange message to the recipient inbox.
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

// handleGetMessages returns and clears the pending key-exchange messages for a user.
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

// handleRegisterWallet registers a wallet after verifying the owner signature
// and the consistency of the server share.
func (h *Handler) handleRegisterWallet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit, protects against DoS

	// Decode the request
	var signedReq SignedRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&signedReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req := signedReq.Data
	walletHex := hex.EncodeToString(req.PublicKey)
	dataBytes, _ := json.Marshal(req)

	participant, _, err := h.Service.GetParticipant(req.Username)
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(walletHex, core.EventWalletRegisterFail, "Unauthorized wallet creation attempt")
		http.Error(w, "Participant does not exist", http.StatusUnauthorized)
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
		p, err := edwards25519.NewIdentityPoint().SetBytes(b)
		if err != nil {
			http.Error(w, "invalid commitment encoding", http.StatusBadRequest)
			return
		}
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
		// Can be changed to have a specific date
		ExpirationDate:  time.Now().Add(req.InactivityThreshold),
		ThresholdParams: req.PubParams,
		P:               req.P,
	}

	// Persist the verified wallet record.
	if err := h.Service.RegisterWallet(wallet, participant.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	pubKeyHex := hex.EncodeToString(wallet.PublicKey)
	h.Audit.Log(pubKeyHex, core.EventRegister, "Success")

	h.Audit.Log(walletHex, core.EventRegister, fmt.Sprintf("Wallet successfully registered by %s", req.Username))

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

// handleLiveness updates the wallet activity timestamp after verifying a signed request.
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
	if err != nil || !ed25519.Verify(participant.PublicKey, dataBytes, signedReq.Signature) {
		h.Audit.Log(req.Username, core.EventLivenessUpdateFail, "Liveness update rejected, invalid signature.")
		http.Error(w, fmt.Sprintf("Participant %q does not exist", req.Username), http.StatusForbidden)
		return
	}

	// Reject stale liveness requests to reduce replay risk.
	requestTime := time.Unix(req.Timestamp, 0)
	if time.Since(requestTime).Abs() > time.Minute {
		http.Error(w, "Invalid timestamp", http.StatusUnauthorized)
		return
	}

	// Update Liveness
	if err := h.Service.UpdateLiveness(req.PublicKey, participant.PublicKey); err != nil {
		http.Error(w, "Failed to update liveness", http.StatusInternalServerError)
		return
	}

	h.Audit.Log(hex.EncodeToString(req.PublicKey), core.EventLiveness, "Liveness updated via signed timestamp")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"liveness_updated"}`))
}

// handleParticipantRegister registers a new participant public key.
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
		h.Audit.Log(req.ID, core.EventParticipantRegisterFail, fmt.Sprintf("Registration failed: %v", err))
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	serverPubKey := h.PrivKey.Public().(ed25519.PublicKey)

	resp := RegisterParticipantResponse{
		ServerPublicKey: serverPubKey,
	}

	h.Audit.Log(req.ID, core.EventParticipantRegister, "Participant registered successfully")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// handleGetParticipants returns a signed participant public key record.
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
