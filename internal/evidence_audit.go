package internal

// evidence_audit.go provides a per-import tamper-evident audit trail for
// derived operations and human assertions. It supplements, never replaces,
// H1/H2/H3 source custody. A local hash chain detects modification when
// verified; an external signed checkpoint is required for independent proof.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const AuditCanonV1 = "sbv-audit-sha256-chain-v1"

var auditWriteMu sync.Mutex

type auditHashPayload struct {
	ImportID     int64           `json:"import_id"`
	OperationID  string          `json:"operation_id"`
	Actor        string          `json:"actor"`
	EventType    string          `json:"event_type"`
	SubjectType  string          `json:"subject_type"`
	SubjectID    string          `json:"subject_id"`
	Details      json.RawMessage `json:"details"`
	OccurredAt   string          `json:"occurred_at"`
	PreviousHash string          `json:"previous_hash"`
	Canon        string          `json:"canon"`
}

type ImportAuditEvent struct {
	ID int64 `json:"id"`
	auditHashPayload
	EventHash string `json:"event_hash"`
}

func newOperationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return hex.EncodeToString(b)
}

func AppendImportAuditEvent(db *sql.DB, importID int64, operationID, actor, eventType, subjectType, subjectID string, details interface{}) (ImportAuditEvent, error) {
	auditWriteMu.Lock()
	defer auditWriteMu.Unlock()
	if operationID == "" {
		operationID = newOperationID()
	}
	detailBytes, err := json.Marshal(details)
	if err != nil {
		return ImportAuditEvent{}, err
	}
	previous := ""
	_ = db.QueryRow(`SELECT event_hash FROM import_audit_events WHERE import_id = ? ORDER BY id DESC LIMIT 1`, importID).Scan(&previous)
	payload := auditHashPayload{ImportID: importID, OperationID: operationID, Actor: actor,
		EventType: eventType, SubjectType: subjectType, SubjectID: subjectID,
		Details: detailBytes, OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
		PreviousHash: previous, Canon: AuditCanonV1}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return ImportAuditEvent{}, err
	}
	eventHash := HashBytesSHA256(canonical)
	result, err := db.Exec(`INSERT INTO import_audit_events
		(import_id, operation_id, actor, event_type, subject_type, subject_id, details_json,
		 occurred_at, previous_hash, event_hash, canon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		importID, operationID, actor, eventType, subjectType, subjectID, string(detailBytes),
		payload.OccurredAt, previous, eventHash, AuditCanonV1)
	if err != nil {
		return ImportAuditEvent{}, err
	}
	id, _ := result.LastInsertId()
	return ImportAuditEvent{ID: id, auditHashPayload: payload, EventHash: eventHash}, nil
}

func ListImportAuditEvents(db *sql.DB, importID int64) ([]ImportAuditEvent, error) {
	rows, err := db.Query(`SELECT id, operation_id, actor, event_type, subject_type,
		COALESCE(subject_id,''), details_json, occurred_at, previous_hash, event_hash, canon
		FROM import_audit_events WHERE import_id = ? ORDER BY id`, importID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ImportAuditEvent, 0)
	for rows.Next() {
		var event ImportAuditEvent
		event.ImportID = importID
		if err := rows.Scan(&event.ID, &event.OperationID, &event.Actor, &event.EventType,
			&event.SubjectType, &event.SubjectID, &event.Details, &event.OccurredAt,
			&event.PreviousHash, &event.EventHash, &event.Canon); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func VerifyImportAuditEvents(events []ImportAuditEvent) (bool, int64, string) {
	previous := ""
	for _, event := range events {
		if event.PreviousHash != previous || event.Canon != AuditCanonV1 {
			return false, event.ID, "previous hash or canon mismatch"
		}
		canonical, err := json.Marshal(event.auditHashPayload)
		if err != nil || HashBytesSHA256(canonical) != event.EventHash {
			return false, event.ID, "event hash mismatch"
		}
		previous = event.EventHash
	}
	return true, 0, ""
}
