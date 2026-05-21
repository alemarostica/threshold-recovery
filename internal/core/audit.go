package core

import (
	"fmt"
	"os"
	"time"
)

type AuditEvent string

const (
	EventStatus                  AuditEvent = "STATUS"
	EventRegister                AuditEvent = "REGISTER"
	EventLiveness                AuditEvent = "LIVENESS_UPDATE"
	EventSignAttempt             AuditEvent = "SIGN_ATTEMPT"
	EventSignSuccess             AuditEvent = "SIGN_SUCCESS"
	EventSignBlocked             AuditEvent = "SIGN_BLOCKED_ACTIVE"
	EventSignThreshold           AuditEvent = "SIGN_THRESH_REACHED"
	EventSignFail                AuditEvent = "SIGN_COMB_FAIL"
	EventSignatureRetrive        AuditEvent = "SIGN_RETRIEVE"
	EventParticipantRegisterFail AuditEvent = "PART_REG_FAILURE"
	EventParticipantRegister     AuditEvent = "PART_REG"
	EventWalletRegisterFail      AuditEvent = "WALL_REG_FAIL"
	EventLivenessUpdateFail      AuditEvent = "LIV_UPDATE_FAIL"
)

// AuditLogger appends security-relevant events to an audit log file.
type AuditLogger struct {
	FilePath string
}

// NewAuditLogger creates an AuditLogger that writes entries to the given path.
func NewAuditLogger(path string) *AuditLogger {
	return &AuditLogger{FilePath: path}
}

// Log appends a timestamped audit entry for the given wallet and event.
//
// Audit logging is best-effort in this prototype: failures are reported to
// stdout, but they do not interrupt the main protocol execution.
func (l *AuditLogger) Log(walletID string, event AuditEvent, details string) {
	entry := fmt.Sprintf("[%s] WALLET:%s EVENT:%s MSG:%s\n",
		time.Now().Format(time.RFC3339), walletID, event, details)

	// Open in append mode
	f, err := os.OpenFile(l.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("CRITICAL: Failed to write audit log: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		fmt.Printf("CRITICAL: Failed to write entry: %v\n", err)
	}
}
