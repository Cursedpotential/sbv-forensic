package internal

// automation.go — Phase 5a automation service layer for the SBV forensic fork.
//
// This makes SBV natively HEADLESS: an agent (or the Python side) can kick off a
// custody-preserving extraction of a server-visible source file and poll it to
// completion over REST, instead of the facade proxy having to orchestrate an
// upload+wait loop. The HTTP handlers live in automation_handlers.go; the
// custody hashing lives in custody.go; this file owns the in-memory job registry
// and the extraction runner.
//
// CUSTODY CONTRACT (unchanged, owner-verified): an extraction runs the EXACT
// same hashing-BEFORE-normalization path the universal import API uses —
//
//	H1 (raw file, HashFileH1) -> immutable import ID -> H2 + H3 (RunImport)
//	 -> durable dispositions -> (only THEN) the importer projects fields.
//
// It never reorders, bypasses, or re-implements custody: it calls the same
// HashFileH1 and ParseSMSBackupStreaming the upload path calls. The source file
// is opened READ-ONLY and is NEVER deleted (it is an evidence artifact, unlike
// the upload path's throwaway temp file).

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ExtractJob is the tracked state of one headless extraction run. It is returned
// verbatim as the JSON body of POST /api/automation/extract and
// GET /api/automation/status/:id.
type ExtractJob struct {
	ID                string `json:"job_id"`
	Status            string `json:"status"` // queued | processing | completed | error
	SourcePath        string `json:"source_path"`
	Filename          string `json:"filename,omitempty"`
	MessageCount      int    `json:"message_count"`
	CallCount         int    `json:"call_count"`
	RecordCount       int    `json:"record_count"`
	ClaimedCount      *int   `json:"claimed_count"`
	AcceptedCount     int    `json:"accepted_count"`
	RejectedCount     int    `json:"rejected_count"`
	DeduplicatedCount int    `json:"deduplicated_count"`
	Reconciliation    string `json:"reconciliation,omitempty"`
	Format            string `json:"format,omitempty"`
	ImportID          int64  `json:"import_id,omitempty"`
	FileHash          string `json:"file_hash,omitempty"`  // H1 (raw file sha256 hex)
	ChainHash         string `json:"chain_hash,omitempty"` // H3 (chain digest over ordered H2s)
	FileHashCanon     string `json:"file_hash_canon,omitempty"`
	ChainCanon        string `json:"chain_canon,omitempty"`
	Error             string `json:"error,omitempty"`
	StartedAt         int64  `json:"started_at"`            // unix seconds (job created)
	FinishedAt        int64  `json:"finished_at,omitempty"` // unix seconds (terminal)
}

var (
	jobsMu sync.RWMutex
	jobs   = make(map[string]*ExtractJob)

	// extractMu keeps automation jobs FIFO. The engine binds custody by immutable
	// import ID, and its shared importExecutionMu also serializes these jobs with
	// interactive legacy/universal uploads to protect SQLite and global progress.
	extractMu sync.Mutex
)

// newJobID returns a random 16-byte hex token, matching the style of
// GenerateSessionID (auth.go).
func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// snapshotJob returns a COPY of the stored job so callers can serialize it to
// JSON without racing the extraction goroutine.
func snapshotJob(id string) (*ExtractJob, bool) {
	jobsMu.RLock()
	defer jobsMu.RUnlock()
	j, ok := jobs[id]
	if !ok {
		return nil, false
	}
	cp := *j
	return &cp, true
}

// mutateJob applies fn to the stored job under the write lock.
func mutateJob(id string, fn func(*ExtractJob)) {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	if j, ok := jobs[id]; ok {
		fn(j)
	}
}

// StartExtractJob validates the source path, registers a queued job, and launches
// the custody-preserving extraction in the background. It returns the queued job
// snapshot immediately (the caller decides whether to wait).
func StartExtractJob(userID, username, path, filename string) (*ExtractJob, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("source path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("source path not accessible: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("source path is a directory, not a file")
	}
	if filename == "" {
		filename = filepath.Base(path)
	}

	id, err := newJobID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate job id: %w", err)
	}

	job := &ExtractJob{
		ID:         id,
		Status:     "queued",
		SourcePath: path,
		Filename:   filename,
		StartedAt:  time.Now().Unix(),
	}
	jobsMu.Lock()
	jobs[id] = job
	jobsMu.Unlock()

	go runExtract(id, userID, username, path, filename)

	snap, _ := snapshotJob(id)
	return snap, nil
}

// runExtract performs the headless extraction for one job. It mirrors
// ProcessUploadedFile's custody ordering exactly, differing only in that (a) the
// source is a caller-supplied server-visible path rather than a multipart temp
// file, and (b) the source file is NEVER removed (it is evidence, not a scratch
// upload).
func runExtract(jobID, userID, username, path, filename string) {
	// Keep job execution FIFO; RunImportSequential performs the cross-entry-point
	// serialization and import-ID attribution.
	extractMu.Lock()
	defer extractMu.Unlock()

	mutateJob(jobID, func(j *ExtractJob) { j.Status = "processing" })
	slog.Info("Automation extract starting", "job", jobID, "path", path, "user", username)

	fail := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		slog.Error("Automation extract failed", "job", jobID, "error", msg)
		mutateJob(jobID, func(j *ExtractJob) {
			j.Status = "error"
			j.Error = msg
			j.FinishedAt = time.Now().Unix()
		})
	}

	// H1 — raw file custody hash, computed over the ORIGINAL bytes BEFORE the
	// parser opens the file. Byte-identical to the upload path (SaveUploadedFile)
	// and to server/evidence/custody.py::_sha256_file.
	fileHash, err := HashFileH1(path)
	if err != nil {
		fail("failed to compute H1 file hash: %v", err)
		return
	}

	userDB, err := GetUserDB(userID, username)
	if err != nil {
		fail("failed to get user database: %v", err)
		return
	}

	file, err := os.Open(path) // #nosec G304 — path is validated + auth-scoped; opened read-only, never written or deleted.
	if err != nil {
		fail("failed to open source file: %v", err)
		return
	}
	defer file.Close()

	// The universal engine detects a registered format plugin, creates the
	// immutable import row before parsing, and binds every H2/disposition/H3 to
	// that exact import ID. It never consults "latest" for attribution.
	summary, err := RunImportSequential(userDB, file, ImportOptions{
		Filename:     filename,
		FileHash:     fileHash,
		OriginalPath: path,
		ArtifactRoot: filepath.Join(dataDirPath(), userID, "artifacts"),
	})
	if err != nil {
		if summary != nil {
			mutateJob(jobID, func(j *ExtractJob) { j.ImportID = summary.ImportID })
		}
		fail("failed to parse backup: %v", err)
		return
	}

	// Fetch only the immutable ID returned by this run. Sequential execution is
	// a safety property, not an attribution mechanism.
	rec, rerr := GetImport(userDB, summary.ImportID)
	if rerr != nil || rec == nil {
		slog.Warn("Automation extract: could not read custody import row", "job", jobID, "error", rerr)
	}

	mutateJob(jobID, func(j *ExtractJob) {
		j.Status = "completed"
		j.MessageCount = summary.MessageCount
		j.CallCount = summary.CallCount
		j.Format = summary.Format
		j.ClaimedCount = summary.Claimed
		j.AcceptedCount = summary.Accepted
		j.RejectedCount = summary.Rejected
		j.DeduplicatedCount = summary.Deduplicated
		j.Reconciliation = summary.Reconciliation
		j.FileHash = fileHash
		j.FileHashCanon = FileHashCanonVersion
		j.ChainCanon = ChainCanonVersionSBV
		j.FinishedAt = time.Now().Unix()
		if rec != nil {
			j.ImportID = rec.ID
			j.ChainHash = rec.ChainHash
			j.RecordCount = rec.RecordCount
		}
	})
	slog.Info("Automation extract completed", "job", jobID, "import_id", summary.ImportID,
		"format", summary.Format, "accepted", summary.Accepted, "rejected", summary.Rejected, "h1", fileHash)
}

// waitForJob blocks until the job reaches a terminal state or the timeout
// elapses, returning the latest snapshot either way. Poll-based (jobs are
// in-process, short-lived, and few).
func waitForJob(id string, timeout time.Duration) (*ExtractJob, bool) {
	deadline := time.Now().Add(timeout)
	for {
		snap, ok := snapshotJob(id)
		if !ok {
			return nil, false
		}
		if snap.Status == "completed" || snap.Status == "error" {
			return snap, true
		}
		if time.Now().After(deadline) {
			return snap, true // return non-terminal snapshot; caller reports "processing"
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// -----------------------------------------------------------------------------
// Backup-artifact enumeration (GET /api/automation/backups)
// -----------------------------------------------------------------------------

// BackupFile describes one retained source artifact on disk (an original backup
// XML kept in the user's ingest/ or complete/ directory).
type BackupFile struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified"` // unix seconds
	Dir      string `json:"dir"`      // "ingest" | "complete"
}

// BackupsResponse lists the durable forensic backup artifacts for a user: the
// append-only custody import rows (H1/H3/count/time) plus the retained source
// files on disk.
type BackupsResponse struct {
	Imports []*ImportRecord `json:"imports"`
	Files   []BackupFile    `json:"files"`
}

// dataDirPath returns the SBV data root the same way main.go derives it
// (DB_PATH_PREFIX + "/data", default "./data").
func dataDirPath() string {
	p := os.Getenv("DB_PATH_PREFIX")
	if p == "" {
		p = "."
	}
	return filepath.Join(p, "data")
}

// ListImports returns all custody import rows for the user's DB, newest first.
// Delegates to the shared scan so each row reports its OWN stored canon tag
// (legacy rows keep h3-chain-v1; new rows carry h3-chain-sbv-genesisempty-v1).
func ListImports(userDB *sql.DB) ([]*ImportRecord, error) {
	return ListAllImports(userDB)
}

// listBackupFiles enumerates the non-hidden, non-log source files retained in the
// user's ingest/ and complete/ directories.
func listBackupFiles(userID string) []BackupFile {
	files := make([]BackupFile, 0)
	base := filepath.Join(dataDirPath(), userID)
	for _, sub := range []string{"ingest", "complete"} {
		dir := filepath.Join(base, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory may not exist yet; skip quietly
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".log") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			files = append(files, BackupFile{
				Name:     name,
				Path:     filepath.Join(dir, name),
				Size:     info.Size(),
				Modified: info.ModTime().Unix(),
				Dir:      sub,
			})
		}
	}
	return files
}
