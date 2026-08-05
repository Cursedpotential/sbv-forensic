package internal

// custody.go — forensic hashing for the SBV forensic fork.
//
// This file adds the H1/H2/H3 chain-of-custody hashes that the Python custody
// gate (server/evidence/custody.py + server/evidence/tools/sbv_sms.py) records
// into the append-only `evidence` schema. SBV holds NO database credentials for
// that Postgres store: it only COMPUTES these hashes over the RAW source bytes
// and exposes them over its REST API. The Python side re-computes H1 independently
// and cross-checks, then writes the evidence_hash / custody_event rows.
//
// ORDERING CONTRACT (owner-verified — hashing MUST precede normalization):
//
//	H1 (raw file)  ->  H2 (raw per-record)  ->  H3 (chain)  ->  (only then) normalize
//
// All three hashes are computed over the ORIGINAL source bytes, BEFORE any field
// decoding / transcoding / NormalizedRecord mapping, so they prove the source
// content is unaltered. See CUSTODY.md for the full, auditable specification.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"
)

// Canonicalization version tags — carried alongside every hash so a future
// change to the byte layout is detectable and auditable. MUST stay in lockstep
// with the strings the Python side stores (server/evidence/custody.py):
//
//	h1-rawbytes-v1   : H1 == sha256(raw file bytes)          — matches custody.py _sha256_file
//	h2-rawelement-v1 : H2 == sha256(raw XML element bytes)   — pre-normalization source record
//	h2-rawrecord-v1  : H2 == sha256(raw logical source-record bytes) — non-XML formats
//	                   (an NDJSON line without its terminator; a CSV record without its
//	                   terminator, quotes intact). Same primitive, format-specific span.
//	h3-chain-v1      : LEGACY chain tag — ambiguous (the Case Bible vault wrote a
//	                   different-but-valid construction under the same label). Rows
//	                   written before the 2026-08-02 crosswalk keep it; it is
//	                   read-only and never restamped.
//	h3-chain-sbv-genesisempty-v1 : the SAME computation this code has always done
//	                   (genesis = "", chain_i = sha256(chain_{i-1} + "\n" + H2_i)),
//	                   named precisely. All NEW import rows carry this tag; it
//	                   matches server/evidence/custody.py::H3_CANON.
const (
	FileHashCanonVersion   = "h1-rawbytes-v1"
	RecordHashCanonVersion = "h2-rawelement-v1"
	RecordHashCanonRawV1   = "h2-rawrecord-v1"
	ChainCanonVersion      = "h3-chain-v1" // legacy tag: pre-existing rows only
	ChainCanonVersionSBV   = "h3-chain-sbv-genesisempty-v1"
)

// HashFileH1 computes the H1 file-level custody hash: the lowercase hex SHA-256
// of the RAW file bytes, streamed in 1 MiB chunks. This MUST be byte-for-byte
// equal to server/evidence/custody.py::_sha256_file for the same file (both are
// a plain SHA-256 over the unmodified bytes — no reformatting, no canonicalization).
func HashFileH1(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return HashReaderH1(f)
}

// HashReaderH1 computes H1 from the reader's current position. Callers that
// retain an evidence file can hash and parse the same open descriptor, avoiding
// a path-based reopen window between custody and extraction.
func HashReaderH1(r io.Reader) (string, error) {
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(h, r, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashBytesSHA256 is the shared primitive: lowercase hex SHA-256 of raw bytes.
func HashBytesSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashRecordH2 computes the H2 per-record custody hash over the RAW SOURCE
// element bytes — the exact bytes of a single <sms .../>, <mms>...</mms>, or
// <call .../> element as they appear in the uploaded XML, from the opening '<'
// through the closing '>' inclusive, with surrounding inter-element whitespace
// excluded. It is hashed BEFORE any parsing/normalization so it proves the
// original record content is unaltered. (h2-rawelement-v1)
//
// Determinism: identical raw element bytes always yield the identical hash;
// any change to the source bytes — including whitespace or formatting our
// normalizer would later strip — changes the hash. That is the point.
func HashRecordH2(rawElement []byte) string {
	return HashBytesSHA256(rawElement)
}

// ChainH3 computes the H3 batch chain digest over the ordered per-record H2
// hashes, in source (parse) order. It is a left fold:
//
//	chain_0 = prevChain                                  (prevChain == "" for a fresh batch)
//	chain_i = hex(sha256( chain_{i-1} + "\n" + H2_i ))
//	H3      = chain_n
//
// The "\n" separator and the running-hex-then-append construction are fixed by
// h3-chain-v1. prevChain lets successive import batches be chained end-to-end
// if ever desired; pass "" for an independent per-import chain.
func ChainH3(orderedH2s []string, prevChain string) string {
	chain := prevChain
	for _, h2 := range orderedH2s {
		chain = HashBytesSHA256([]byte(chain + "\n" + h2))
	}
	return chain
}

// trimLeadingXMLSpace drops leading XML insignificant whitespace (space, tab,
// CR, LF) so a captured raw span begins exactly at the element's '<'. There is
// never trailing whitespace to trim: the capture ends at the element's '>'.
func trimLeadingXMLSpace(b []byte) []byte {
	i := 0
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return b[i:]
		}
	}
	return b[i:]
}

// rawCaptureReader wraps an io.Reader and retains a sliding buffer of the bytes
// the xml.Decoder pulls, so the RAW byte span of each element (identified by
// absolute input offset via xml.Decoder.InputOffset) can be extracted AFTER the
// decoder has consumed it. Memory stays bounded: discardBefore drops buffered
// bytes that precede a committed offset, so at most one element (plus the
// decoder read-ahead) is retained at a time — the same streaming footprint the
// decoder already has.
type rawCaptureReader struct {
	src  io.Reader
	buf  []byte
	base int64 // absolute input offset of buf[0]
	end  int64 // absolute input offset one past buf[len(buf)-1] == bytes read from src
}

func newRawCaptureReader(src io.Reader) *rawCaptureReader {
	return &rawCaptureReader{src: src}
}

func (c *rawCaptureReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
		c.end += int64(n)
	}
	return n, err
}

// slice returns a COPY of the raw bytes in absolute offsets [start, stop).
// Returns nil if the range is not fully buffered (should not happen given the
// decoder consumes sequentially and we only discard already-processed prefixes).
func (c *rawCaptureReader) slice(start, stop int64) []byte {
	if start < c.base || stop > c.end || start > stop {
		return nil
	}
	out := make([]byte, stop-start)
	copy(out, c.buf[start-c.base:stop-c.base])
	return out
}

// discardBefore drops buffered bytes preceding absolute offset off.
func (c *rawCaptureReader) discardBefore(off int64) {
	if off <= c.base {
		return
	}
	if off >= c.end {
		c.buf = c.buf[:0]
		c.base = c.end
		return
	}
	n := off - c.base
	c.buf = append(c.buf[:0], c.buf[n:]...)
	c.base = off
}

// -----------------------------------------------------------------------------
// imports table — one row per upload batch, holding H1 (file_hash) + H3
// (chain_hash) + record_count. Exposed over GET /api/hashes/{importID}.
// -----------------------------------------------------------------------------

// ImportRecord is the persisted + API-serialized custody + accounting summary
// for one import. The original five fields (import_id, file_hash, chain_hash,
// record_count, imported_at) plus the canon tags are the frozen legacy shape of
// GET /api/hashes/:importID; everything below them is additive (omitempty) and
// carried by the universal-import endpoints (/api/imports*).
//
// IMMUTABLE IDENTITY: an import row is created BEFORE parsing starts, so every
// record, rejection, count, and hash produced by that parse binds to this ID.
// "latest" remains available as a legacy convenience anchor but is never the
// authoritative binding — the ID is.
type ImportRecord struct {
	ID              int64  `json:"import_id"`
	FileHash        string `json:"file_hash"`  // H1 (raw file sha256 hex)
	ChainHash       string `json:"chain_hash"` // H3 (chain digest over ordered H2s)
	RecordCount     int    `json:"record_count"`
	ImportedAt      int64  `json:"imported_at"` // unix seconds
	FileHashCanon   string `json:"file_hash_canon"`
	RecordHashCanon string `json:"record_hash_canon"`
	ChainCanon      string `json:"chain_canon"` // read from the row — legacy rows keep h3-chain-v1

	// Universal-import identity + accounting (additive).
	Filename       string `json:"filename,omitempty"`
	Format         string `json:"format,omitempty"`
	Status         string `json:"status,omitempty"` // processing | completed | error
	Error          string `json:"error,omitempty"`
	OriginalPath   string `json:"original_path,omitempty"` // preserved source artifact
	ClaimedCount   *int   `json:"claimed_count"`           // what the source claims to contain (null = no claim)
	Encountered    int    `json:"encountered_count"`
	Accepted       int    `json:"accepted_count"`
	Rejected       int    `json:"rejected_count"`
	Deduplicated   int    `json:"deduplicated_count"`
	Reconciliation string `json:"reconciliation,omitempty"` // pending | reconciled | discrepancy | unverified
	StartedAt      int64  `json:"started_at,omitempty"`     // unix seconds
	FinishedAt     int64  `json:"finished_at,omitempty"`    // unix seconds
}

// Reconciliation states for an import's record accounting.
const (
	ReconciliationPending     = "pending"     // import still running
	ReconciliationReconciled  = "reconciled"  // claimed count matches encountered records
	ReconciliationDiscrepancy = "discrepancy" // claimed count does NOT match — investigate
	ReconciliationUnverified  = "unverified"  // source carries no claimed count to check against
)

// Import lifecycle states.
const (
	ImportStatusProcessing = "processing"
	ImportStatusCompleted  = "completed"
	ImportStatusError      = "error"
)

// importSelectColumns is the shared column list for every import read.
const importSelectColumns = `id, file_hash, record_count, chain_hash, imported_at,
	COALESCE(canon_version, 'h3-chain-v1'),
	COALESCE(filename, ''), COALESCE(format, ''), COALESCE(status, 'completed'),
	COALESCE(error, ''), COALESCE(original_path, ''),
	claimed_count,
	COALESCE(encountered_count, 0), COALESCE(accepted_count, 0),
	COALESCE(rejected_count, 0), COALESCE(deduplicated_count, 0),
	COALESCE(reconciliation, ''), COALESCE(started_at, 0), COALESCE(finished_at, 0)`

// CreateImport registers the immutable identity of a new import BEFORE any
// record is parsed. Everything the parse produces binds to the returned id.
// New rows always carry the precise chain canon tag (h3-chain-sbv-genesisempty-v1).
func CreateImport(userDB *sql.DB, filename, format, fileHash, originalPath string) (int64, error) {
	now := time.Now().Unix()
	res, err := userDB.Exec(
		`INSERT INTO imports (file_hash, record_count, chain_hash, canon_version, imported_at,
		                      filename, format, status, original_path,
		                      encountered_count, accepted_count, rejected_count, deduplicated_count,
		                      reconciliation, started_at)
		 VALUES (?, 0, '', ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?)`,
		fileHash, ChainCanonVersionSBV, now,
		filename, format, ImportStatusProcessing, originalPath,
		ReconciliationPending, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateImportProgress persists the live counters for an in-flight import so
// progress can be polled BY IMPORT ID, not via global state.
func UpdateImportProgress(userDB *sql.DB, id int64, claimed *int, encountered, accepted, rejected, deduplicated int) error {
	_, err := userDB.Exec(
		`UPDATE imports SET claimed_count = ?, encountered_count = ?, accepted_count = ?,
		        rejected_count = ?, deduplicated_count = ? WHERE id = ?`,
		claimed, encountered, accepted, rejected, deduplicated, id)
	return err
}

// FinalizeImport records the terminal state of an import: final counts, the H3
// chain over the ordered per-record H2s, the reconciliation verdict, and the
// error message if the run failed. record_count keeps its custody meaning — the
// number of complete raw spans whose H2s were folded into the chain, independent
// of accepted/deduplicated/rejected disposition.
func FinalizeImport(userDB *sql.DB, id int64, status, errMsg, chainHash string,
	claimed *int, encountered, accepted, rejected, deduplicated, hashed int, reconciliation string) error {
	_, err := userDB.Exec(
		`UPDATE imports SET status = ?, error = ?, chain_hash = ?, record_count = ?,
		        claimed_count = ?, encountered_count = ?, accepted_count = ?,
		        rejected_count = ?, deduplicated_count = ?, reconciliation = ?, finished_at = ?
		 WHERE id = ?`,
		status, errMsg, chainHash, hashed,
		claimed, encountered, accepted, rejected, deduplicated, reconciliation,
		time.Now().Unix(), id)
	return err
}

// SetImportOriginalPath updates the preserved-original pointer (used when the
// source artifact is relocated after import, e.g. auto-import's ingest/ ->
// complete/ move). The artifact itself is never deleted.
func SetImportOriginalPath(userDB *sql.DB, id int64, path string) error {
	_, err := userDB.Exec(`UPDATE imports SET original_path = ? WHERE id = ?`, path, id)
	return err
}

// RecordImport inserts one completed custody summary row and returns its id.
// LEGACY one-shot writer, kept for compatibility; the universal engine uses
// CreateImport + FinalizeImport so the import identity exists before parsing.
func RecordImport(userDB *sql.DB, fileHash string, recordCount int, chainHash string) (int64, error) {
	res, err := userDB.Exec(
		`INSERT INTO imports (file_hash, record_count, chain_hash, canon_version, imported_at, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		fileHash, recordCount, chainHash, ChainCanonVersionSBV, time.Now().Unix(), ImportStatusCompleted,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// rowScanner abstracts *sql.Row / *sql.Rows for the shared import scan.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanImport(row rowScanner) (*ImportRecord, error) {
	var r ImportRecord
	var claimed sql.NullInt64
	err := row.Scan(&r.ID, &r.FileHash, &r.RecordCount, &r.ChainHash, &r.ImportedAt,
		&r.ChainCanon,
		&r.Filename, &r.Format, &r.Status, &r.Error, &r.OriginalPath,
		&claimed, &r.Encountered, &r.Accepted, &r.Rejected, &r.Deduplicated,
		&r.Reconciliation, &r.StartedAt, &r.FinishedAt)
	if err != nil {
		return nil, err
	}
	if claimed.Valid {
		v := int(claimed.Int64)
		r.ClaimedCount = &v
	}
	r.FileHashCanon = FileHashCanonVersion
	if r.Format == FormatSMSBackupXML || r.Format == "" {
		r.RecordHashCanon = RecordHashCanonVersion
	} else {
		r.RecordHashCanon = RecordHashCanonRawV1
	}
	return &r, nil
}

// GetImport fetches one import row by id.
func GetImport(userDB *sql.DB, id int64) (*ImportRecord, error) {
	return scanImport(userDB.QueryRow(
		`SELECT `+importSelectColumns+` FROM imports WHERE id = ?`, id))
}

// GetLatestImport fetches the most recent import row (highest id). LEGACY
// convenience anchor for GET /api/hashes/latest — never the authoritative
// binding (the import id is); kept because the Python custody cross-check and
// older clients poll it after a single serialized upload.
func GetLatestImport(userDB *sql.DB) (*ImportRecord, error) {
	return scanImport(userDB.QueryRow(
		`SELECT ` + importSelectColumns + ` FROM imports ORDER BY id DESC LIMIT 1`))
}

// ListAllImports returns every import row, newest first.
func ListAllImports(userDB *sql.DB) ([]*ImportRecord, error) {
	rows, err := userDB.Query(`SELECT ` + importSelectColumns + ` FROM imports ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]*ImportRecord, 0)
	for rows.Next() {
		r, err := scanImport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ensureCustodyColumns is an idempotent migration: it adds the H2 content_hash
// column to an existing messages table, creates the imports table, widens it
// with the universal-import identity/accounting columns, and creates the
// import-scoped canonical record store (import_records + import_rejections).
// Fresh DBs get content_hash from the CREATE TABLE definition; this backfills
// upgraded DBs. Existing imports rows keep their stored canon_version
// ('h3-chain-v1' default) — legacy rows are never relabelled.
func ensureCustodyColumns(db *sql.DB) error {
	has, err := columnExists(db, "messages", "content_hash")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE messages ADD COLUMN content_hash TEXT`); err != nil {
			return fmt.Errorf("add content_hash column: %w", err)
		}
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS imports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_hash TEXT NOT NULL,
		record_count INTEGER NOT NULL,
		chain_hash TEXT NOT NULL,
		canon_version TEXT NOT NULL DEFAULT 'h3-chain-v1',
		imported_at INTEGER NOT NULL
	)`); err != nil {
		return err
	}

	// Universal-import identity + accounting columns (idempotent backfill).
	importCols := []struct{ name, ddl string }{
		{"filename", "filename TEXT"},
		{"format", "format TEXT"},
		{"status", "status TEXT NOT NULL DEFAULT 'completed'"},
		{"error", "error TEXT"},
		{"original_path", "original_path TEXT"},
		{"claimed_count", "claimed_count INTEGER"},
		{"encountered_count", "encountered_count INTEGER NOT NULL DEFAULT 0"},
		{"accepted_count", "accepted_count INTEGER NOT NULL DEFAULT 0"},
		{"rejected_count", "rejected_count INTEGER NOT NULL DEFAULT 0"},
		{"deduplicated_count", "deduplicated_count INTEGER NOT NULL DEFAULT 0"},
		{"reconciliation", "reconciliation TEXT"},
		{"started_at", "started_at INTEGER"},
		{"finished_at", "finished_at INTEGER"},
	}
	for _, col := range importCols {
		has, err := columnExists(db, "imports", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec("ALTER TABLE imports ADD COLUMN " + col.ddl); err != nil {
				return fmt.Errorf("add imports.%s column: %w", col.name, err)
			}
		}
	}

	// Import-scoped canonical record store: one row per encountered-and-hashed
	// source record, bound to its import id, in encounter order. Not forced into
	// SMS semantics — kind/participants/content/metadata are format-neutral;
	// legacy_row_id links back to the messages table when a legacy projection
	// was also written (the XML vertical).
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		seq INTEGER NOT NULL,
		kind TEXT NOT NULL,
		format TEXT NOT NULL,
		status TEXT NOT NULL,
		source_pos TEXT NOT NULL,
		record_hash TEXT NOT NULL,
		record_hash_canon TEXT NOT NULL,
		occurred_at INTEGER,
		participants TEXT,
		content TEXT,
		metadata TEXT,
		legacy_row_id INTEGER,
		raw_size INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_import_records_import ON import_records(import_id, seq)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_import_records_hash ON import_records(record_hash)`); err != nil {
		return err
	}
	has, err = columnExists(db, "import_records", "raw_size")
	if err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE import_records ADD COLUMN raw_size INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}

	// Rejections: every record the parser encountered but could not accept,
	// with the reason and the source position, bound to the import id.
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_rejections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		seq INTEGER NOT NULL,
		source_pos TEXT NOT NULL,
		reason TEXT NOT NULL,
		raw_excerpt TEXT,
		record_hash TEXT,
		record_hash_canon TEXT
	)`); err != nil {
		return err
	}
	for _, col := range []struct{ name, ddl string }{
		{"record_hash", "record_hash TEXT"},
		{"record_hash_canon", "record_hash_canon TEXT"},
	} {
		has, err := columnExists(db, "import_rejections", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec("ALTER TABLE import_rejections ADD COLUMN " + col.ddl); err != nil {
				return fmt.Errorf("add import_rejections.%s column: %w", col.name, err)
			}
		}
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_attachments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		record_seq INTEGER NOT NULL,
		record_hash TEXT NOT NULL,
		original_name TEXT,
		mime_type TEXT,
		decoded_hash TEXT,
		byte_count INTEGER NOT NULL DEFAULT 0,
		stored_path TEXT NOT NULL,
		conversion_status TEXT NOT NULL DEFAULT 'not_attempted',
		derived_path TEXT,
		derived_hash TEXT,
		derived_mime_type TEXT,
		derived_byte_count INTEGER NOT NULL DEFAULT 0,
		conversion_error TEXT
	)`); err != nil {
		return err
	}
	for _, col := range []struct{ name, ddl string }{
		{"derived_hash", "derived_hash TEXT"},
		{"derived_mime_type", "derived_mime_type TEXT"},
		{"derived_byte_count", "derived_byte_count INTEGER NOT NULL DEFAULT 0"},
	} {
		has, err := columnExists(db, "import_attachments", col.name)
		if err != nil {
			return err
		}
		if !has {
			if _, err := db.Exec("ALTER TABLE import_attachments ADD COLUMN " + col.ddl); err != nil {
				return fmt.Errorf("add import_attachments.%s column: %w", col.name, err)
			}
		}
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_import_attachments_import ON import_attachments(import_id, record_seq)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_attachment_references (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		record_seq INTEGER NOT NULL,
		record_hash TEXT NOT NULL,
		kind TEXT,
		uri_original TEXT,
		uri TEXT,
		display_text TEXT,
		resolution_status TEXT NOT NULL,
		safe_relative INTEGER NOT NULL DEFAULT 0,
		source_reported_missing INTEGER NOT NULL DEFAULT 0,
		resolved_hash TEXT
	)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_import_attachment_refs_import
		ON import_attachment_references(import_id, record_seq)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_companion_bundles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		filename TEXT NOT NULL,
		file_hash TEXT NOT NULL,
		stored_path TEXT NOT NULL,
		status TEXT NOT NULL,
		resolved_count INTEGER NOT NULL DEFAULT 0,
		missing_count INTEGER NOT NULL DEFAULT 0,
		conflict_count INTEGER NOT NULL DEFAULT 0,
		error TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_review_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		record_seq INTEGER,
		attachment_reference_id INTEGER,
		action TEXT NOT NULL,
		previous_value TEXT,
		resulting_value TEXT,
		reason TEXT NOT NULL,
		reviewer TEXT NOT NULL,
		operation_id TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS import_audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		import_id INTEGER NOT NULL,
		operation_id TEXT NOT NULL,
		actor TEXT NOT NULL,
		event_type TEXT NOT NULL,
		subject_type TEXT NOT NULL,
		subject_id TEXT,
		details_json TEXT NOT NULL,
		occurred_at TEXT NOT NULL,
		previous_hash TEXT NOT NULL,
		event_hash TEXT NOT NULL,
		canon TEXT NOT NULL
	)`); err != nil {
		return err
	}
	if _, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_import_audit_event_hash
		ON import_audit_events(import_id, event_hash)`); err != nil {
		return err
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_import_rejections_import ON import_rejections(import_id)`)
	return err
}

func columnExists(db *sql.DB, table, col string) (bool, error) {
	// #nosec G202 — table is an internal constant, never user input.
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}
