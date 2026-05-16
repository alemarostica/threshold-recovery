package core

import (
	"fmt"
	"os"
	"time"
)

type AuditEvent string

const (
	// TODO: Facciamo il loggin per bene su tutto
	EventStatus                  AuditEvent = "STATUS"
	EventRegister                AuditEvent = "REGISTER"
	EventLiveness                AuditEvent = "LIVENESS_UPDATE"
	EventSignAttempt             AuditEvent = "SIGN_ATTEMPT"
	EventSignSuccess             AuditEvent = "SIGN_SUCCESS"
	EventSignBlocked             AuditEvent = "SIGN_BLOCKED_ACTIVE"
	EventSignThreshold           AuditEvent = "SIGN_THRESH_REACHED"
	EventSignatureRetrive        AuditEvent = "SIGN_RETRIEVE"
	EventParticipantRegisterFail AuditEvent = "PART_REG_FAILURE"
	EventParticipantRegister     AuditEvent = "PART_REG"
	EventWalletRegisterFail      AuditEvent = "WALL_REG_FAIL"
	EventLivenessUpdateFail      AuditEvent = "LIV_UPDATE_FAIL"
)

// Every security log is appended to a file
type AuditLogger struct {
	FilePath string
}

func NewAuditLogger(path string) *AuditLogger {
	return &AuditLogger{FilePath: path}
}

// Basically the function that logs everything
func (l *AuditLogger) Log(walletID string, event AuditEvent, details string) {
	entry := fmt.Sprintf("[%s] WALLET:%s EVENT:%s MSG:%s\n",
		time.Now().Format(time.RFC3339), walletID, event, details)

	// Open in append mode
	f, err := os.OpenFile(l.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to write audit log: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		fmt.Printf("CRITICAL: Failed to write entry: %v\n", err)
	}
}
