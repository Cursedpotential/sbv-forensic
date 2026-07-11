package internal

// automation_handlers.go — Phase 5a native automation HTTP endpoints for the SBV
// forensic fork. These make SBV agent-drivable and headless without the Python
// facade having to orchestrate an upload+poll loop:
//
//	POST /api/automation/extract       kick off a custody-preserving extraction
//	GET  /api/automation/status/:id    poll an extraction job
//	GET  /api/automation/export/:id    collect a synthesized export (json|csv)
//	GET  /api/automation/backups       list retained backup artifacts + custody rows
//
// All four are registered under the authenticated /api group in main.go and reuse
// the same session/auth + no-cache middleware as every other protected route.
// Error responses use the same shape as the rest of the handlers:
// c.JSON(status, map[string]string{"error": ...}).

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

// extractRequest is the POST /api/automation/extract body.
type extractRequest struct {
	// Path is a source file visible to THIS container (e.g. the shared /r2
	// mount, or a file already dropped in the user's ingest/ directory).
	Path string `json:"path"`
	// Filename is an optional display/override name; defaults to base(Path).
	Filename string `json:"filename,omitempty"`
	// Wait, when true, blocks until the extraction reaches a terminal state and
	// returns the final job; otherwise returns 202 with the queued job to poll.
	Wait bool `json:"wait,omitempty"`
}

// HandleAutomationExtract kicks off a headless, custody-preserving extraction of
// a server-visible source file. It returns a job id + status; poll
// GET /api/automation/status/:id (or pass {"wait": true} for a synchronous run).
func HandleAutomationExtract(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}
	username, ok := c.Get("username").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}

	var req extractRequest
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		}
	}
	if strings.TrimSpace(req.Path) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "'path' is required"})
	}

	job, err := StartExtractJob(userID, username, req.Path, req.Filename)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	slog.Info("Automation extract queued", "job", job.ID, "path", req.Path, "wait", req.Wait)

	if req.Wait {
		// Bound the wait by the same 30-minute window the server allows for large
		// uploads. A non-terminal return (timeout) still yields the current job so
		// the caller can keep polling.
		final, _ := waitForJob(job.ID, 30*time.Minute)
		if final != nil {
			status := http.StatusOK
			if final.Status == "error" {
				status = http.StatusInternalServerError
			}
			return c.JSON(status, final)
		}
	}

	return c.JSON(http.StatusAccepted, job)
}

// HandleAutomationStatus returns the current state of an extraction job.
func HandleAutomationStatus(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "job id required"})
	}
	job, ok := snapshotJob(id)
	if !ok {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "job not found"})
	}
	return c.JSON(http.StatusOK, job)
}

// HandleAutomationExport synthesizes an export of the user's corpus in the
// requested format (?format=json|csv, default json), stamped with the forensic
// custody summary for provenance. The :id path segment selects the custody
// anchor:
//   - "latest" or "all": the most recent import's custody row
//   - a job id: that extraction job's import (404 if the job is unknown)
func HandleAutomationExport(c echo.Context) error {
	userDB, err := getUserDB(c)
	if err != nil {
		slog.Error("Error getting user database", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get user database"})
	}

	id := c.Param("id")
	format := strings.ToLower(c.QueryParam("format"))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "format must be 'json' or 'csv'"})
	}

	// Resolve the custody anchor from :id.
	var custody *ImportRecord
	var jobID string
	switch {
	case id == "" || id == "latest" || id == "all":
		if rec, cerr := GetLatestImport(userDB); cerr == nil {
			custody = rec
		}
	default:
		job, ok := snapshotJob(id)
		if !ok {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "job not found"})
		}
		jobID = job.ID
		if job.ImportID > 0 {
			if rec, cerr := GetImport(userDB, job.ImportID); cerr == nil {
				custody = rec
			}
		}
	}

	messages, calls, err := CollectExport(userDB)
	if err != nil {
		slog.Error("Error collecting export", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to collect export"})
	}

	resp := ExportResponse{
		Format:       format,
		JobID:        jobID,
		Custody:      custody,
		MessageCount: len(messages),
		CallCount:    len(calls),
	}

	if format == "csv" {
		csvStr, cerr := messagesToCSV(messages)
		if cerr != nil {
			slog.Error("Error rendering CSV export", "error", cerr)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to render CSV export"})
		}
		resp.CSV = csvStr
	} else {
		resp.Messages = messages
		resp.Calls = calls
	}

	return c.JSON(http.StatusOK, resp)
}

// HandleAutomationBackups lists the durable backup artifacts for the user: the
// append-only custody import rows (H1/H3/count/time) and the retained source
// files on disk (ingest/ + complete/).
func HandleAutomationBackups(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not authenticated"})
	}
	userDB, err := getUserDB(c)
	if err != nil {
		slog.Error("Error getting user database", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get user database"})
	}

	imports, err := ListImports(userDB)
	if err != nil {
		slog.Error("Error listing imports", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list imports"})
	}

	return c.JSON(http.StatusOK, BackupsResponse{
		Imports: imports,
		Files:   listBackupFiles(userID),
	})
}
