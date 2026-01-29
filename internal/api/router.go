// This is the CONTROLLER, or the handler of HTTP requests
package api

import (
	"encoding/json"
	"net/http"
	"threshold-recovery/internal/core"
	// "time"
)

// Define what the backend can do
// Interface to swap memory more easily
type WalletService interface {
	GetWallet(id string) (*core.Wallet, error)
	UpdateLiveness(id string) error
	RegisterWallet(w *core.Wallet) error
}

type Handler struct {
	Service WalletService
}

func NewHandler(s WalletService) *Handler {
	return &Handler{Service: s}
}

// Register the endpoints
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("POST /liveness", h.handleLiveness)
	mux.HandleFunc("GET /status/{id}", h.handleStatus)
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	wallet, err := h.Service.GetWallet(id)
	if err != nil {
		http.Error(w, "Wallet not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":            wallet.ID,
		"recoverable":   wallet.IsRecoverable(),
		"last_activity": wallet.LastActivity,
	}

	json.NewEncoder(w).Encode(response)
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	// This will receive the VSS share
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Bro I'm not that fast"))
}

func (h *Handler) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Will verify signature
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Liveness is still not live lmao"))
}
