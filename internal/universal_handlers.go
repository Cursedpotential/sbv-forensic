package internal

// universal_handlers.go — authenticated import-scoped API for the pluggable
// parser engine and its format-neutral viewer store.

import (
	"archive/zip"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

const (
	maxImportPageSize     = 1000
	defaultMaxImportBytes = int64(8) << 30 // 8 GiB total multipart body
)

// maxImportBodyBytes reads the total HTTP body limit. The value is bytes, not
// source-file bytes (multipart framing consumes a small part of it). Invalid or
// non-positive configuration is an explicit error rather than an unsafe fallback.
func maxImportBodyBytes() (int64, error) {
	raw := strings.TrimSpace(os.Getenv("SBV_MAX_IMPORT_BYTES"))
	if raw == "" {
		return defaultMaxImportBytes, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("SBV_MAX_IMPORT_BYTES must be a positive base-10 byte count")
	}
	return value, nil
}

// HandleUniversalImport streams a multipart source to the retained evidence
// area, computes H1 over those preserved bytes, then runs the detected (or
// explicitly requested) importer synchronously. The response's import_id is the
// authoritative handle for every later status/record/rejection request.
func HandleUniversalImport(c echo.Context) error {
	maxBytes, err := maxImportBodyBytes()
	if err != nil {
		slog.Error("Invalid universal import size configuration", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, maxBytes)
	if err := c.Request().ParseMultipartForm(32 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return c.JSON(http.StatusRequestEntityTooLarge, map[string]interface{}{
				"error": "import request exceeds configured body limit", "max_bytes": maxBytes,
			})
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid multipart form: " + err.Error()})
	}
	if c.Request().MultipartForm != nil {
		defer c.Request().MultipartForm.RemoveAll()
	}
	source, header, err := c.Request().FormFile("file")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "multipart field 'file' is required"})
	}
	defer source.Close()

	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}
	userDB, err := getUserDB(c)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get user database"})
	}

	retainedPath, err := retainEvidenceUpload(userID, header.Filename, source)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to retain source artifact: " + err.Error()})
	}
	// H1 and parsing use this exact open descriptor. Seeking it back to zero
	// avoids reopening a mutable path between custody hashing and extraction.
	f, err := os.Open(retainedPath) // #nosec G304 — path was created by retainEvidenceUpload.
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "source retained but could not be opened: " + err.Error(), "path": retainedPath,
		})
	}
	defer f.Close()
	h1, err := HashReaderH1(f)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "source retained but H1 computation failed: " + err.Error(), "path": retainedPath,
		})
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "source retained and hashed but could not be rewound: " + err.Error(), "path": retainedPath,
		})
	}

	summary, runErr := RunImportSequential(userDB, f, ImportOptions{
		Filename:     filepath.Base(header.Filename),
		Format:       strings.ToLower(strings.TrimSpace(c.FormValue("format"))),
		FileHash:     h1,
		OriginalPath: retainedPath,
		ArtifactRoot: filepath.Join(dataDirPath(), userID, "artifacts"),
	})
	if runErr != nil {
		return c.JSON(http.StatusUnprocessableEntity, map[string]interface{}{
			"error": runErr.Error(), "import": summary, "retained_path": retainedPath,
		})
	}
	return c.JSON(http.StatusCreated, summary)
}

// retainEvidenceUpload never rewrites or deletes the source. Failed partial
// writes are moved to a data-level to_be_deleted quarantine for owner review.
func retainEvidenceUpload(userID, filename string, source io.Reader) (path string, err error) {
	root := filepath.Join(dataDirPath(), userID, "imports")
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	ext := strings.ToLower(filepath.Ext(filepath.Base(filename)))
	if len(ext) > 12 {
		ext = ""
	}
	f, err := os.CreateTemp(root, "evidence-*"+ext)
	if err != nil {
		return "", err
	}
	path = f.Name()
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
		if err != nil {
			quarantinePartialUpload(path)
		}
	}()
	buf := make([]byte, 1024*1024)
	if _, err = io.CopyBuffer(f, source, buf); err != nil {
		return path, err
	}
	if err = f.Sync(); err != nil {
		return path, err
	}
	err = f.Close()
	closed = true
	return path, err
}

func quarantinePartialUpload(path string) {
	if path == "" {
		return
	}
	dir := filepath.Join(dataDirPath(), "to_be_deleted")
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	_ = os.Rename(path, filepath.Join(dir, filepath.Base(path)+".partial"))
}

func HandleImportFormats(c echo.Context) error {
	type formatInfo struct {
		Format   string `json:"format"`
		Priority int    `json:"priority"`
	}
	formats := make([]formatInfo, 0)
	for _, imp := range RegisteredImporters() {
		formats = append(formats, formatInfo{Format: imp.Format(), Priority: imp.Priority()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"formats": formats})
}

func HandleImports(c echo.Context) error {
	userDB, err := getUserDB(c)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	imports, err := ListAllImports(userDB)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"imports": imports})
}

func HandleImport(c echo.Context) error {
	userDB, id, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	rec, err := GetImport(userDB, id)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, rec)
}

func HandleImportRecords(c echo.Context) error {
	userDB, id, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	if _, err := GetImport(userDB, id); err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	limit, offset := importPagination(c)
	kind, status := c.QueryParam("kind"), c.QueryParam("status")
	rows, err := GetImportRecords(userDB, id, kind, status, limit, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	total, err := CountImportRecords(userDB, id, kind, status)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"import_id": id, "total": total, "limit": limit, "offset": offset, "records": rows,
	})
}

func HandleImportRejections(c echo.Context) error {
	userDB, id, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	if _, err := GetImport(userDB, id); err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	limit, offset := importPagination(c)
	rows, err := GetImportRejections(userDB, id, limit, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	total, err := CountImportRejections(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"import_id": id, "total": total, "limit": limit, "offset": offset, "rejections": rows,
	})
}

func HandleImportAttachments(c echo.Context) error {
	userDB, id, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	if _, err := GetImport(userDB, id); err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	items, err := GetImportAttachments(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	refs, err := GetImportAttachmentReferences(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	needsCompanions := false
	for _, ref := range refs {
		if ref.ResolutionStatus == AttachmentReferenceOnly {
			needsCompanions = true
			break
		}
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"import_id": id, "attachments": items, "references": refs,
		"needs_companion_bundle": needsCompanions,
	})
}

func HandleImportEvidenceReport(c echo.Context) error {
	userDB, id, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	item, err := GetImport(userDB, id)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	attachments, err := GetImportAttachments(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	references, err := GetImportAttachmentReferences(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	auditEvents, err := ListImportAuditEvents(userDB, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	verified, brokenAt, verifyError := VerifyImportAuditEvents(auditEvents)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"report_version": "sbv-evidence-report-v1", "generated_at": time.Now().UTC(),
		"import": item, "attachments": attachments, "attachment_references": references,
		"audit": map[string]interface{}{"canon": AuditCanonV1, "verified": verified,
			"broken_at_event_id": brokenAt, "verification_error": verifyError, "events": auditEvents},
		"assurance": "tamper-evident when the audit chain verifies; independently signed external checkpoint not configured",
	})
}

func HandleImportAttachmentDownload(c echo.Context) error {
	userDB, importID, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	attachmentID, err := strconv.ParseInt(c.Param("attachmentID"), 10, 64)
	if err != nil || attachmentID <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid attachment id"})
	}
	item, err := GetImportAttachment(userDB, importID, attachmentID)
	if err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "attachment not found"})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}
	relativePath := item.StoredPath
	downloadName := safeDownloadName(item.OriginalName, item.ID)
	contentType := item.MIME
	if c.QueryParam("variant") == "derived" {
		if item.ConversionStatus != "completed" || item.DerivedPath == "" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "derived attachment is unavailable"})
		}
		relativePath = item.DerivedPath
		downloadName = derivativeDownloadName(downloadName, item.DerivedMIME)
		contentType = item.DerivedMIME
	}
	path, err := ResolveImportArtifact(filepath.Join(dataDirPath(), userID, "artifacts"), importID, relativePath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	c.Response().Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": downloadName}))
	if contentType != "" {
		c.Response().Header().Set(echo.HeaderContentType, contentType)
	}
	return c.File(path)
}

func HandleImportAttachmentsExport(c echo.Context) error {
	userDB, importID, httpErr := importRequest(c)
	if httpErr != nil {
		return httpErr
	}
	if _, err := GetImport(userDB, importID); err == sql.ErrNoRows {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "import not found"})
	} else if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}
	artifactRoot := filepath.Join(dataDirPath(), userID, "artifacts")
	items, err := GetImportAttachments(userDB, importID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	response := c.Response()
	response.Header().Set(echo.HeaderContentType, "application/zip")
	response.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="import-%d-attachments.zip"`, importID))
	response.WriteHeader(http.StatusOK)
	zw := zip.NewWriter(response)
	for _, item := range items {
		name := safeDownloadName(item.OriginalName, item.ID)
		if err := addArtifactToZip(zw, artifactRoot, importID, item.StoredPath,
			fmt.Sprintf("originals/%06d-%s", item.ID, name)); err != nil {
			_ = zw.Close()
			return err
		}
		if item.ConversionStatus == "completed" && item.DerivedPath != "" {
			if err := addArtifactToZip(zw, artifactRoot, importID, item.DerivedPath,
				fmt.Sprintf("derived/%06d-%s", item.ID, derivativeDownloadName(name, item.DerivedMIME))); err != nil {
				_ = zw.Close()
				return err
			}
		}
	}
	return zw.Close()
}

func addArtifactToZip(zw *zip.Writer, artifactRoot string, importID int64, relative, name string) error {
	path, err := ResolveImportArtifact(artifactRoot, importID, relative)
	if err != nil {
		return err
	}
	f, err := os.Open(path) // #nosec G304 — resolved under authenticated import artifact root.
	if err != nil {
		return err
	}
	defer f.Close()
	entry, err := zw.Create(filepath.ToSlash(name))
	if err != nil {
		return err
	}
	_, err = io.Copy(entry, f)
	return err
}

func derivativeDownloadName(original, mimeType string) string {
	ext := ".bin"
	switch strings.ToLower(strings.TrimSpace(mimeType)) {
	case "image/jpeg":
		ext = ".jpg"
	case "video/mp4":
		ext = ".mp4"
	case "audio/mpeg":
		ext = ".mp3"
	}
	base := strings.TrimSuffix(original, filepath.Ext(original))
	if base == "" {
		base = "derived"
	}
	return base + ext
}

func safeDownloadName(name string, id int64) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	if name == "" || name == "." {
		return fmt.Sprintf("attachment-%d.bin", id)
	}
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, name)
	return name
}

func importRequest(c echo.Context) (*sql.DB, int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return nil, 0, echo.NewHTTPError(http.StatusBadRequest, "invalid import id")
	}
	userDB, err := getUserDB(c)
	if err != nil {
		return nil, 0, echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return userDB, id, nil
}

func importPagination(c echo.Context) (limit, offset int) {
	limit = 100
	if n, err := strconv.Atoi(c.QueryParam("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > maxImportPageSize {
		limit = maxImportPageSize
	}
	if n, err := strconv.Atoi(c.QueryParam("offset")); err == nil && n > 0 {
		offset = n
	}
	return limit, offset
}
