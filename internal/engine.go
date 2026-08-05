package internal

// engine.go — the universal import engine.
//
// One import = one immutable identity (imports row, created BEFORE parsing) +
// one format importer streaming raw logical source records through this engine.
// The engine owns everything an importer must not: custody hashing (H2 per raw
// record, H3 chain fold in encounter order), the import-scoped canonical record
// store (import_records / import_rejections), accepted/rejected/deduplicated
// accounting, claimed-vs-encountered reconciliation, and progress — bound to
// the import id, never to "latest" or whole-account state.
//
// FORENSIC ORDERING (owner-verified, unchanged from the XML-only fork):
//
//	H1 (raw file) -> H2 (raw per-record) -> H3 (chain) -> (only THEN) normalize
//
// H2 is computed over each record's EXACT raw source bytes before any decoding;
// the H3 chain folds the ordered H2s of every hashed record (accepted AND
// deduplicated, and rejected when their exact raw span is recoverable — the
// chain proves what the source contained). A partial/unrecoverable rejected
// span is durable but cannot honestly receive H2 or enter H3.

import (
	"bufio"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// progressFlushEvery controls how often live counters are flushed to the
// imports row for by-id progress polling.
const progressFlushEvery = 250

// ImportSummary is the terminal result of one engine run.
type ImportSummary struct {
	ImportID       int64  `json:"import_id"`
	Format         string `json:"format"`
	ChainHash      string `json:"chain_hash"` // H3 over the ordered H2s (genesis-empty LF fold)
	Claimed        *int   `json:"claimed_count"`
	Encountered    int    `json:"encountered_count"`
	Accepted       int    `json:"accepted_count"`
	Rejected       int    `json:"rejected_count"`
	Deduplicated   int    `json:"deduplicated_count"`
	Hashed         int    `json:"hashed_count"`
	Reconciliation string `json:"reconciliation"`

	// Legacy per-kind counters (the ParseSMSBackupStreaming return values).
	MessageCount int `json:"message_count,omitempty"`
	CallCount    int `json:"call_count,omitempty"`
}

// importExecutionMu keeps all paths that write to the per-user SQLite stores
// sequential. Import IDs already isolate reads; serialization additionally
// protects the legacy global progress singleton and deterministic dedup status.
var importExecutionMu sync.Mutex

// RunImportSequential is the production entry point for API and automation
// imports. RunImport remains lock-free so focused unit tests can exercise the
// engine directly without hidden global state.
func RunImportSequential(userDB *sql.DB, r io.Reader, opts ImportOptions) (*ImportSummary, error) {
	importExecutionMu.Lock()
	defer importExecutionMu.Unlock()
	return RunImport(userDB, r, opts)
}

// ImportOptions configures one engine run.
type ImportOptions struct {
	// ImportID binds the run to a pre-created import row (upload path). Zero
	// means the engine creates the row itself before parsing.
	ImportID int64
	// Format forces a specific importer ("" = detect from content + filename).
	Format   string
	Filename string
	// FileHash is the H1 custody hash of the source file (computed by the caller
	// over the ORIGINAL bytes before anything parses them).
	FileHash string
	// OriginalPath is where the preserved source artifact lives (informational).
	OriginalPath string
	// ArtifactRoot is the authenticated user's private artifact directory. The
	// engine appends import-<id>; callers must never share this root between
	// users because SQLite import ids are only unique within one user database.
	ArtifactRoot string
	// UpdateGlobalProgress mirrors counters into the legacy global upload
	// progress singleton so the pre-existing /api/progress contract keeps working.
	UpdateGlobalProgress bool
}

// engineSink is the ImportSink implementation backing one run.
type engineSink struct {
	userDB   *sql.DB
	importID int64
	format   string

	chain        string // incremental H3 fold (genesis "")
	claimed      *int
	seq          int // encounter counter (records + rejections, in source order)
	accepted     int
	rejected     int
	deduplicated int
	hashed       int            // exact raw spans folded into H3, regardless of disposition
	kindHashed   map[string]int // accepted+deduplicated per kind (reconciliation)

	updateGlobal    bool
	sinceFlush      int
	insertRecord    *sql.Stmt
	insertRejection *sql.Stmt
	artifactDir     string
}

func (s *engineSink) ImportID() int64 { return s.importID }

func (s *engineSink) ArtifactDir() (string, error) {
	if s.artifactDir == "" {
		s.artifactDir = filepath.Join(dataDirPath(), "artifacts", fmt.Sprintf("import-%d", s.importID))
	}
	if err := os.MkdirAll(s.artifactDir, 0700); err != nil {
		return "", err
	}
	return s.artifactDir, nil
}

func (s *engineSink) Claim(n int) {
	if s.claimed == nil {
		v := 0
		s.claimed = &v
	}
	*s.claimed += n
	if s.updateGlobal {
		uploadProgressLock.Lock()
		if uploadProgress != nil {
			uploadProgress.mu.Lock()
			uploadProgress.TotalMessages = *s.claimed
			uploadProgress.mu.Unlock()
		}
		uploadProgressLock.Unlock()
	}
}

func (s *engineSink) encountered() int {
	return s.accepted + s.rejected + s.deduplicated
}

// Record accepts (or deduplicates) one raw logical source record: H2 over the
// raw bytes, optional legacy-table projection, canonical-store row, chain fold.
func (s *engineSink) Record(rec *SourceRecord) error {
	if rec.PrecomputedH2 == "" && len(rec.Raw) > maxRawRecordBytes {
		return s.Reject(rec.SourcePos,
			fmt.Sprintf("record exceeds size bound (%d > %d bytes)", len(rec.Raw), maxRawRecordBytes),
			rec.Raw, true)
	}

	// H2 — hash the RAW source bytes BEFORE any use of the decoded projection.
	h2 := rec.PrecomputedH2
	if h2 == "" {
		h2 = HashRecordH2(rec.Raw)
	} else if decoded, err := hex.DecodeString(h2); err != nil || len(decoded) != 32 {
		return fmt.Errorf("invalid precomputed H2 for %s", rec.SourcePos)
	}

	kind := rec.Kind
	if kind == "" {
		kind = KindRow
	}
	canon := rec.RawCanon
	if canon == "" {
		canon = RecordHashCanonRawV1
	}

	// Decide accepted vs deduplicated.
	var dedup bool
	var legacyRowID *int64
	switch {
	case rec.LegacyMessage != nil:
		// XML vertical: the legacy messages table's unique index IS the dedup
		// authority (unchanged legacy semantics — normalized-field identity).
		rec.LegacyMessage.ContentHash = h2
		inserted, err := insertMessageOutcome(s.userDB, rec.LegacyMessage)
		if err != nil {
			return fmt.Errorf("insert message: %w", err)
		}
		dedup = !inserted
		if inserted {
			id := rec.LegacyMessage.ID
			legacyRowID = &id
		}
	case rec.LegacyCall != nil:
		rec.LegacyCall.ContentHash = h2
		inserted, err := insertCallLogOutcome(s.userDB, rec.LegacyCall)
		if err != nil {
			return fmt.Errorf("insert call: %w", err)
		}
		dedup = !inserted
		if inserted {
			id := rec.LegacyCall.ID
			legacyRowID = &id
		}
	default:
		// Format-neutral dedup: an identical raw record (same H2) of the same
		// format+kind already accepted anywhere in the store (including earlier
		// in this same import) is a duplicate of stored content.
		var one int
		err := s.userDB.QueryRow(
			`SELECT 1 FROM import_records WHERE record_hash = ? AND format = ? AND kind = ? AND status = 'accepted' LIMIT 1`,
			h2, s.format, kind).Scan(&one)
		switch err {
		case nil:
			dedup = true
		case sql.ErrNoRows:
			dedup = false
		default:
			return fmt.Errorf("dedup lookup: %w", err)
		}
	}

	status := "accepted"
	if dedup {
		status = "deduplicated"
	}

	// Canonical record row — bound to the import id, in encounter order.
	s.seq++
	var occurredAt interface{}
	if rec.OccurredAt != nil {
		occurredAt = rec.OccurredAt.Unix()
	}
	var participantsJSON, metadataJSON interface{}
	if len(rec.Participants) > 0 {
		b, err := json.Marshal(rec.Participants)
		if err != nil {
			return fmt.Errorf("marshal participants: %w", err)
		}
		participantsJSON = string(b)
	}
	if len(rec.Metadata) > 0 {
		b, err := json.Marshal(rec.Metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		metadataJSON = string(b)
	}
	var legacyID interface{}
	if legacyRowID != nil {
		legacyID = *legacyRowID
	}
	rawSize := rec.RawSize
	if rawSize == 0 {
		rawSize = int64(len(rec.Raw))
	}
	if _, err := s.insertRecord.Exec(
		s.importID, s.seq, kind, s.format, status, rec.SourcePos, h2, canon,
		occurredAt, participantsJSON, rec.Content, metadataJSON, legacyID, rawSize,
	); err != nil {
		return fmt.Errorf("insert import record: %w", err)
	}
	for _, attachment := range rec.Attachments {
		if err := s.insertAttachment(s.seq, h2, attachment); err != nil {
			return err
		}
	}
	for _, ref := range rec.AttachmentReferences {
		if err := s.insertAttachmentReference(s.seq, h2, ref); err != nil {
			return err
		}
	}

	// H3 — fold the H2 into the chain incrementally (genesis "", LF separator).
	s.chain = HashBytesSHA256([]byte(s.chain + "\n" + h2))
	s.hashed++

	if dedup {
		s.deduplicated++
	} else {
		s.accepted++
	}
	s.kindHashed[kind]++

	if s.updateGlobal {
		switch kind {
		case KindCall:
			uploadProgressLock.Lock()
			if uploadProgress != nil {
				uploadProgress.mu.Lock()
				uploadProgress.TotalCalls++
				uploadProgress.ProcessedCalls = s.kindHashed[KindCall]
				uploadProgress.mu.Unlock()
			}
			uploadProgressLock.Unlock()
		default:
			UpdateMessageProgress(s.kindHashed[KindMessage] + s.kindHashed[KindRow] + s.kindHashed[KindObject])
		}
	}

	return s.maybeFlush()
}

func (s *engineSink) insertAttachment(recordSeq int, h2 string, attachment AttachmentArtifact) error {
	root, err := s.ArtifactDir()
	if err != nil {
		return err
	}
	attachment = prepareAttachmentDerivative(root, attachment, defaultAttachmentConverter())
	stored, err := safeArtifactRelative(root, attachment.StoredPath)
	if err != nil {
		return err
	}
	derived := ""
	if attachment.DerivedPath != "" {
		derived, err = safeArtifactRelative(root, attachment.DerivedPath)
		if err != nil {
			return err
		}
	}
	_, err = s.userDB.Exec(`INSERT INTO import_attachments
		(import_id, record_seq, record_hash, original_name, mime_type, decoded_hash,
		 byte_count, stored_path, conversion_status, derived_path, derived_hash,
		 derived_mime_type, derived_byte_count, conversion_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.importID, recordSeq, h2, attachment.OriginalName, attachment.MIME,
		attachment.DecodedHash, attachment.ByteCount, stored,
		attachment.ConversionStatus, derived, attachment.DerivedHash,
		attachment.DerivedMIME, attachment.DerivedByteCount, attachment.ConversionError)
	return err
}

func (s *engineSink) insertAttachmentReference(recordSeq int, h2 string, ref AttachmentReference) error {
	_, err := s.userDB.Exec(`INSERT INTO import_attachment_references
		(import_id, record_seq, record_hash, kind, uri_original, uri, display_text,
		 resolution_status, safe_relative, source_reported_missing, resolved_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.importID, recordSeq, h2, ref.Kind, ref.URIOriginal, ref.URI, ref.DisplayText,
		ref.ResolutionStatus, ref.SafeRelative, ref.SourceReportedMissing, ref.ResolvedHash)
	return err
}

func safeArtifactRelative(root, path string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("attachment path escapes import artifact root")
	}
	return filepath.ToSlash(rel), nil
}

// Reject records one encountered-but-unacceptable source record with its reason
// and position. A complete raw span receives H2 and enters H3 before its bounded
// excerpt is stored; partial raw spans are explicitly left unhashed.
func (s *engineSink) Reject(sourcePos, reason string, raw []byte, rawComplete bool) error {
	s.seq++
	s.rejected++
	excerpt := raw
	if len(excerpt) > rejectExcerptBytes {
		excerpt = excerpt[:rejectExcerptBytes]
	}
	var h2, canon interface{}
	if rawComplete {
		hash := HashRecordH2(raw)
		h2 = hash
		canonName := RecordHashCanonRawV1
		if s.format == FormatSMSBackupXML {
			canonName = RecordHashCanonVersion
		}
		canon = canonName
		s.chain = HashBytesSHA256([]byte(s.chain + "\n" + hash))
		s.hashed++
	}
	if _, err := s.insertRejection.Exec(s.importID, s.seq, sourcePos, reason, string(excerpt), h2, canon); err != nil {
		return fmt.Errorf("insert rejection: %w", err)
	}
	slog.Warn("Import record rejected", "import_id", s.importID, "pos", sourcePos, "reason", reason)
	return s.maybeFlush()
}

func (s *engineSink) RejectHashed(sourcePos, reason, h2, canon string, _ int64) error {
	decoded, err := hex.DecodeString(h2)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("invalid streamed rejection H2 for %s", sourcePos)
	}
	if canon == "" {
		canon = RecordHashCanonRawV1
	}
	s.seq++
	s.rejected++
	s.hashed++
	s.chain = HashBytesSHA256([]byte(s.chain + "\n" + h2))
	if _, err := s.insertRejection.Exec(s.importID, s.seq, sourcePos, reason, "", h2, canon); err != nil {
		return fmt.Errorf("insert streamed rejection: %w", err)
	}
	slog.Warn("Streamed import record rejected", "import_id", s.importID, "pos", sourcePos, "reason", reason)
	return s.maybeFlush()
}

func (s *engineSink) maybeFlush() error {
	s.sinceFlush++
	if s.sinceFlush < progressFlushEvery {
		return nil
	}
	s.sinceFlush = 0
	return UpdateImportProgress(s.userDB, s.importID, s.claimed,
		s.encountered(), s.accepted, s.rejected, s.deduplicated)
}

// reconcile derives the reconciliation verdict from the source's claimed count
// vs what was actually encountered. The claimed count of an SMS Backup &
// Restore file covers only its own record family (smses count = sms+mms;
// calls count = calls), so a kind-family match also reconciles.
func (s *engineSink) reconcile() string {
	if s.claimed == nil {
		return ReconciliationUnverified
	}
	enc := s.encountered()
	if *s.claimed == enc {
		return ReconciliationReconciled
	}
	if *s.claimed == s.kindHashed[KindMessage]+s.rejectedOfKindEstimate(KindMessage) ||
		*s.claimed == s.kindHashed[KindCall]+s.rejectedOfKindEstimate(KindCall) {
		return ReconciliationReconciled
	}
	return ReconciliationDiscrepancy
}

// rejectedOfKindEstimate: rejections are not kind-attributed (a record that
// failed to decode has no reliable kind), so the kind-family reconciliation
// only matches exactly when there were no rejections. With any rejection the
// per-kind claim cannot be verified record-for-record; the total-count branch
// above still applies.
func (s *engineSink) rejectedOfKindEstimate(string) int {
	if s.rejected == 0 {
		return 0
	}
	return -1 // force non-match: a rejected record makes the family claim unverifiable
}

// RunImport executes one full import: resolve the importer, bind the immutable
// import identity, stream the source through the sink, finalize custody +
// accounting. It NEVER deletes or modifies the source. On parse failure the
// import row is finalized with status=error and the partial accounting kept.
func RunImport(userDB *sql.DB, r io.Reader, opts ImportOptions) (*ImportSummary, error) {
	br := bufio.NewReaderSize(r, 64<<10)

	// Resolve the importer: explicit format wins; otherwise detect from content.
	var imp Importer
	if opts.Format != "" {
		var ok bool
		if imp, ok = ImporterByFormat(opts.Format); !ok {
			return recordImportPreflightFailure(userDB, opts,
				fmt.Errorf("unknown import format %q", opts.Format))
		}
	} else {
		head, _ := br.Peek(detectPeekBytes)
		if imp = DetectImporter(head, opts.Filename); imp == nil {
			return recordImportPreflightFailure(userDB, opts,
				fmt.Errorf("unable to detect import format for %q", opts.Filename))
		}
	}

	// Immutable identity — the row exists before the first record is parsed.
	importID := opts.ImportID
	if importID == 0 {
		var err error
		importID, err = CreateImport(userDB, opts.Filename, imp.Format(), opts.FileHash, opts.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("create import row: %w", err)
		}
	}

	if opts.UpdateGlobalProgress {
		uploadProgressLock.Lock()
		uploadProgress = &UploadProgress{Status: "parsing", StartTime: time.Now()}
		uploadProgressLock.Unlock()
	}

	sink := &engineSink{
		userDB:       userDB,
		importID:     importID,
		format:       imp.Format(),
		kindHashed:   make(map[string]int),
		updateGlobal: opts.UpdateGlobalProgress,
	}
	if opts.ArtifactRoot != "" {
		sink.artifactDir = filepath.Join(opts.ArtifactRoot, fmt.Sprintf("import-%d", importID))
	}

	var err error
	sink.insertRecord, err = userDB.Prepare(`INSERT INTO import_records
		(import_id, seq, kind, format, status, source_pos, record_hash, record_hash_canon,
		 occurred_at, participants, content, metadata, legacy_row_id, raw_size)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = FinalizeImport(userDB, importID, ImportStatusError, err.Error(), "",
			nil, 0, 0, 0, 0, 0, ReconciliationDiscrepancy)
		return nil, fmt.Errorf("prepare record insert: %w", err)
	}
	defer sink.insertRecord.Close()
	sink.insertRejection, err = userDB.Prepare(`INSERT INTO import_rejections
		(import_id, seq, source_pos, reason, raw_excerpt, record_hash, record_hash_canon)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = FinalizeImport(userDB, importID, ImportStatusError, err.Error(), "",
			nil, 0, 0, 0, 0, 0, ReconciliationDiscrepancy)
		return nil, fmt.Errorf("prepare rejection insert: %w", err)
	}
	defer sink.insertRejection.Close()

	runErr := imp.Run(sink, br)

	status := ImportStatusCompleted
	errMsg := ""
	reconciliation := sink.reconcile()
	if runErr != nil {
		status = ImportStatusError
		errMsg = runErr.Error()
		reconciliation = ReconciliationDiscrepancy
	}
	if ferr := FinalizeImport(userDB, importID, status, errMsg, sink.chain,
		sink.claimed, sink.encountered(), sink.accepted, sink.rejected, sink.deduplicated, sink.hashed,
		reconciliation); ferr != nil {
		// A custody-row failure must not lose the parsed data, but it IS a
		// forensic gap — surface it loudly rather than swallowing it.
		slog.Error("Error finalizing import custody row", "import_id", importID, "error", ferr)
		if runErr == nil {
			runErr = ferr
		}
	}
	if _, auditErr := AppendImportAuditEvent(userDB, importID, newOperationID(), "system",
		"import_finalized", "import", fmt.Sprint(importID), map[string]interface{}{
			"filename": opts.Filename, "format": imp.Format(), "h1": opts.FileHash,
			"h3": sink.chain, "status": status, "error": errMsg,
			"claimed": sink.claimed, "encountered": sink.encountered(),
			"accepted": sink.accepted, "rejected": sink.rejected,
			"deduplicated": sink.deduplicated, "hashed": sink.hashed,
			"reconciliation": reconciliation,
		}); auditErr != nil {
		slog.Error("Import audit event failed", "import_id", importID, "error", auditErr)
		if runErr == nil {
			runErr = fmt.Errorf("append import audit event: %w", auditErr)
			_ = FinalizeImport(userDB, importID, ImportStatusError, runErr.Error(), sink.chain,
				sink.claimed, sink.encountered(), sink.accepted, sink.rejected, sink.deduplicated,
				sink.hashed, ReconciliationDiscrepancy)
		}
	}

	if opts.UpdateGlobalProgress {
		if runErr != nil {
			SetUploadProgress(0, 0, "error")
			uploadProgressLock.Lock()
			if uploadProgress != nil {
				uploadProgress.mu.Lock()
				uploadProgress.ErrorMessage = errMsg
				uploadProgress.mu.Unlock()
			}
			uploadProgressLock.Unlock()
		} else {
			total := sink.kindHashed[KindMessage] + sink.kindHashed[KindRow] + sink.kindHashed[KindObject]
			SetUploadProgress(total, total, "completed")
		}
	}

	return &ImportSummary{
		ImportID:       importID,
		Format:         imp.Format(),
		ChainHash:      sink.chain,
		Claimed:        sink.claimed,
		Encountered:    sink.encountered(),
		Accepted:       sink.accepted,
		Rejected:       sink.rejected,
		Deduplicated:   sink.deduplicated,
		Hashed:         sink.hashed,
		Reconciliation: reconciliation,
		MessageCount:   sink.kindHashed[KindMessage],
		CallCount:      sink.kindHashed[KindCall],
	}, runErr
}

// recordImportPreflightFailure gives an unsupported/corrupt source a durable
// import identity and terminal error row. Failed attempts therefore remain
// visible to operators instead of disappearing before the ledger begins.
func recordImportPreflightFailure(userDB *sql.DB, opts ImportOptions, cause error) (*ImportSummary, error) {
	format := opts.Format
	if format == "" {
		format = "unknown"
	}
	id := opts.ImportID
	if id == 0 {
		var err error
		id, err = CreateImport(userDB, opts.Filename, format, opts.FileHash, opts.OriginalPath)
		if err != nil {
			return nil, fmt.Errorf("%v; create failed import row: %w", cause, err)
		}
	}
	if err := FinalizeImport(userDB, id, ImportStatusError, cause.Error(), "",
		nil, 0, 0, 0, 0, 0, ReconciliationDiscrepancy); err != nil {
		return nil, fmt.Errorf("%v; finalize failed import row %d: %w", cause, id, err)
	}
	return &ImportSummary{
		ImportID: id, Format: format, Reconciliation: ReconciliationDiscrepancy,
	}, cause
}

// -----------------------------------------------------------------------------
// Canonical record store reads (the universal viewer's data source)
// -----------------------------------------------------------------------------

// ImportRecordRow is the API projection of one canonical stored record.
type ImportRecordRow struct {
	ID              int64                  `json:"id"`
	ImportID        int64                  `json:"import_id"`
	Seq             int                    `json:"seq"`
	Kind            string                 `json:"kind"`
	Format          string                 `json:"format"`
	Status          string                 `json:"status"` // accepted | deduplicated
	SourcePos       string                 `json:"source_pos"`
	RecordHash      string                 `json:"record_hash"` // H2
	RecordHashCanon string                 `json:"record_hash_canon"`
	OccurredAt      *int64                 `json:"occurred_at"` // unix seconds, null when unknown
	Participants    []string               `json:"participants,omitempty"`
	Content         string                 `json:"content,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	LegacyRowID     *int64                 `json:"legacy_row_id,omitempty"`
	RawSize         int64                  `json:"raw_size"`
}

// ImportRejectionRow is the API projection of one rejection.
type ImportRejectionRow struct {
	ID              int64  `json:"id"`
	ImportID        int64  `json:"import_id"`
	Seq             int    `json:"seq"`
	SourcePos       string `json:"source_pos"`
	Reason          string `json:"reason"`
	RawExcerpt      string `json:"raw_excerpt,omitempty"`
	RecordHash      string `json:"record_hash,omitempty"`
	RecordHashCanon string `json:"record_hash_canon,omitempty"`
}

// GetImportRecords returns one page of an import's canonical records in
// encounter order, optionally filtered by kind and/or status.
func GetImportRecords(userDB *sql.DB, importID int64, kind, status string, limit, offset int) ([]ImportRecordRow, error) {
	query := `SELECT id, import_id, seq, kind, format, status, source_pos, record_hash, record_hash_canon,
	                 occurred_at, COALESCE(participants, ''), COALESCE(content, ''), COALESCE(metadata, ''),
	                 legacy_row_id, COALESCE(raw_size, 0)
	          FROM import_records WHERE import_id = ?`
	args := []interface{}{importID}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, kind)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY seq ASC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := userDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ImportRecordRow, 0)
	for rows.Next() {
		var r ImportRecordRow
		var occurred, legacyID sql.NullInt64
		var participants, metadata string
		if err := rows.Scan(&r.ID, &r.ImportID, &r.Seq, &r.Kind, &r.Format, &r.Status,
			&r.SourcePos, &r.RecordHash, &r.RecordHashCanon,
			&occurred, &participants, &r.Content, &metadata, &legacyID, &r.RawSize); err != nil {
			return nil, err
		}
		if occurred.Valid {
			v := occurred.Int64
			r.OccurredAt = &v
		}
		if legacyID.Valid {
			v := legacyID.Int64
			r.LegacyRowID = &v
		}
		if participants != "" {
			_ = json.Unmarshal([]byte(participants), &r.Participants)
		}
		if metadata != "" {
			_ = json.Unmarshal([]byte(metadata), &r.Metadata)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountImportRecords returns the total canonical records for an import
// (optionally filtered), for pagination.
func CountImportRecords(userDB *sql.DB, importID int64, kind, status string) (int, error) {
	query := `SELECT COUNT(*) FROM import_records WHERE import_id = ?`
	args := []interface{}{importID}
	if kind != "" {
		query += " AND kind = ?"
		args = append(args, kind)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	var n int
	err := userDB.QueryRow(query, args...).Scan(&n)
	return n, err
}

// GetImportRejections returns one page of an import's rejections in encounter order.
func GetImportRejections(userDB *sql.DB, importID int64, limit, offset int) ([]ImportRejectionRow, error) {
	rows, err := userDB.Query(
		`SELECT id, import_id, seq, source_pos, reason, COALESCE(raw_excerpt, ''),
		        COALESCE(record_hash, ''), COALESCE(record_hash_canon, '')
		 FROM import_rejections WHERE import_id = ? ORDER BY seq ASC LIMIT ? OFFSET ?`,
		importID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ImportRejectionRow, 0)
	for rows.Next() {
		var r ImportRejectionRow
		if err := rows.Scan(&r.ID, &r.ImportID, &r.Seq, &r.SourcePos, &r.Reason,
			&r.RawExcerpt, &r.RecordHash, &r.RecordHashCanon); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountImportRejections returns the total rejections for an import.
func CountImportRejections(userDB *sql.DB, importID int64) (int, error) {
	var n int
	err := userDB.QueryRow(`SELECT COUNT(*) FROM import_rejections WHERE import_id = ?`, importID).Scan(&n)
	return n, err
}

// ImportAttachmentRow is the safe API projection of a file-backed child.
type ImportAttachmentRow struct {
	ID               int64  `json:"id"`
	ImportID         int64  `json:"import_id"`
	RecordSeq        int    `json:"record_seq"`
	RecordHash       string `json:"record_hash"`
	OriginalName     string `json:"original_name"`
	MIME             string `json:"mime_type"`
	DecodedHash      string `json:"decoded_hash"`
	ByteCount        int64  `json:"byte_count"`
	StoredPath       string `json:"stored_path"`
	ConversionStatus string `json:"conversion_status"`
	DerivedPath      string `json:"derived_path,omitempty"`
	DerivedHash      string `json:"derived_hash,omitempty"`
	DerivedMIME      string `json:"derived_mime_type,omitempty"`
	DerivedByteCount int64  `json:"derived_byte_count,omitempty"`
	ConversionError  string `json:"conversion_error,omitempty"`
	ResolutionStatus string `json:"resolution_status"`
}

func GetImportAttachments(userDB *sql.DB, importID int64) ([]ImportAttachmentRow, error) {
	rows, err := userDB.Query(`SELECT id, import_id, record_seq, record_hash,
		COALESCE(original_name,''), COALESCE(mime_type,''), COALESCE(decoded_hash,''),
		byte_count, stored_path, conversion_status, COALESCE(derived_path,''),
		COALESCE(derived_hash,''), COALESCE(derived_mime_type,''), COALESCE(derived_byte_count,0),
		COALESCE(conversion_error,'')
		FROM import_attachments WHERE import_id = ? ORDER BY record_seq, id`, importID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ImportAttachmentRow, 0)
	for rows.Next() {
		var item ImportAttachmentRow
		if err := rows.Scan(&item.ID, &item.ImportID, &item.RecordSeq, &item.RecordHash,
			&item.OriginalName, &item.MIME, &item.DecodedHash, &item.ByteCount,
			&item.StoredPath, &item.ConversionStatus, &item.DerivedPath, &item.DerivedHash,
			&item.DerivedMIME, &item.DerivedByteCount, &item.ConversionError); err != nil {
			return nil, err
		}
		item.ResolutionStatus = AttachmentResolved
		if item.ConversionStatus == "decode_failed" {
			item.ResolutionStatus = "decode_failed"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ImportAttachmentReferenceRow is the API projection of a source-declared
// companion pointer, including references whose bytes were not supplied.
type ImportAttachmentReferenceRow struct {
	ID                    int64  `json:"id"`
	ImportID              int64  `json:"import_id"`
	RecordSeq             int    `json:"record_seq"`
	RecordHash            string `json:"record_hash"`
	Kind                  string `json:"kind"`
	URIOriginal           string `json:"uri_original,omitempty"`
	URI                   string `json:"uri,omitempty"`
	DisplayText           string `json:"display_text,omitempty"`
	ResolutionStatus      string `json:"resolution_status"`
	SafeRelative          bool   `json:"safe_relative"`
	SourceReportedMissing bool   `json:"source_reported_missing"`
	ResolvedHash          string `json:"resolved_hash,omitempty"`
}

func GetImportAttachmentReferences(userDB *sql.DB, importID int64) ([]ImportAttachmentReferenceRow, error) {
	rows, err := userDB.Query(`SELECT id, import_id, record_seq, record_hash,
		COALESCE(kind,''), COALESCE(uri_original,''), COALESCE(uri,''), COALESCE(display_text,''),
		resolution_status, safe_relative, source_reported_missing, COALESCE(resolved_hash,'')
		FROM import_attachment_references WHERE import_id = ? ORDER BY record_seq, id`, importID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ImportAttachmentReferenceRow, 0)
	for rows.Next() {
		var item ImportAttachmentReferenceRow
		if err := rows.Scan(&item.ID, &item.ImportID, &item.RecordSeq, &item.RecordHash,
			&item.Kind, &item.URIOriginal, &item.URI, &item.DisplayText,
			&item.ResolutionStatus, &item.SafeRelative, &item.SourceReportedMissing,
			&item.ResolvedHash); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetImportAttachment(userDB *sql.DB, importID, attachmentID int64) (*ImportAttachmentRow, error) {
	var item ImportAttachmentRow
	err := userDB.QueryRow(`SELECT id, import_id, record_seq, record_hash,
		COALESCE(original_name,''), COALESCE(mime_type,''), COALESCE(decoded_hash,''),
		byte_count, stored_path, conversion_status, COALESCE(derived_path,''),
		COALESCE(derived_hash,''), COALESCE(derived_mime_type,''), COALESCE(derived_byte_count,0),
		COALESCE(conversion_error,'')
		FROM import_attachments WHERE import_id = ? AND id = ?`, importID, attachmentID).Scan(
		&item.ID, &item.ImportID, &item.RecordSeq, &item.RecordHash, &item.OriginalName,
		&item.MIME, &item.DecodedHash, &item.ByteCount, &item.StoredPath,
		&item.ConversionStatus, &item.DerivedPath, &item.DerivedHash, &item.DerivedMIME,
		&item.DerivedByteCount, &item.ConversionError)
	item.ResolutionStatus = AttachmentResolved
	if item.ConversionStatus == "decode_failed" {
		item.ResolutionStatus = "decode_failed"
	}
	return &item, err
}

func ResolveImportArtifact(artifactRoot string, importID int64, relative string) (string, error) {
	root := filepath.Join(artifactRoot, fmt.Sprintf("import-%d", importID))
	if strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, `\`) || filepath.VolumeName(relative) != "" {
		return "", fmt.Errorf("invalid attachment path")
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid attachment path")
	}
	path := filepath.Join(root, clean)
	if _, err := safeArtifactRelative(root, path); err != nil {
		return "", err
	}
	return path, nil
}
