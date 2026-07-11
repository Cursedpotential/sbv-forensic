package internal

// automation_test.go — Phase 5a automation endpoints. These follow the
// handlers_test.go pattern (setupTestDB + setupTestContext) and prove the
// custody-preserving extraction path: an extract job's H1 file hash MUST equal
// an independent HashFileH1 of the same source bytes, and the run MUST produce
// records + an imports custody row.

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

const automationSampleXML = `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<smses count="2">
  <sms protocol="0" address="+15551234567" date="1285799668000" type="2" body="Automation sent message" read="1" status="-1" />
  <sms protocol="0" address="+15551234567" date="1285799669000" type="1" body="Automation received message" read="1" status="-1" />
</smses>`

func TestHandleAutomationExtractMissingPath(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	c, rec := setupTestContext(http.MethodPost, "/api/automation/extract", `{}`)
	if err := HandleAutomationExtract(c); err != nil {
		t.Fatalf("HandleAutomationExtract failed: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing path, got %d", rec.Code)
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if !strings.Contains(response["error"], "path") {
		t.Errorf("Expected error about missing path, got: %s", response["error"])
	}
}

func TestHandleAutomationStatusNotFound(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	c, rec := setupTestContext(http.MethodGet, "/api/automation/status/nope", "")
	c.SetParamNames("id")
	c.SetParamValues("does-not-exist")

	if err := HandleAutomationStatus(c); err != nil {
		t.Fatalf("HandleAutomationStatus failed: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404 for unknown job, got %d", rec.Code)
	}
}

func TestHandleAutomationBackups(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	c, rec := setupTestContext(http.MethodGet, "/api/automation/backups", "")
	if err := HandleAutomationBackups(c); err != nil {
		t.Fatalf("HandleAutomationBackups failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	var resp BackupsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	// Imports and Files are non-nil (JSON arrays), possibly empty.
	if resp.Imports == nil {
		t.Error("Expected imports array in response")
	}
}

func TestHandleAutomationExportLatest(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	c, rec := setupTestContext(http.MethodGet, "/api/automation/export/latest", "")
	c.SetParamNames("id")
	c.SetParamValues("latest")

	if err := HandleAutomationExport(c); err != nil {
		t.Fatalf("HandleAutomationExport failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	var resp ExportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.Format != "json" {
		t.Errorf("Expected format json, got %s", resp.Format)
	}
}

// TestAutomationExtractCustodyPreserved is the load-bearing custody test: a
// headless extract of a real file must compute an H1 byte-identical to an
// independent HashFileH1 of the same file, and must write records + a custody
// import row (H3 chain).
func TestAutomationExtractCustodyPreserved(t *testing.T) {
	_, cleanup := setupTestDB(t)
	defer cleanup()

	// Write the sample backup to a real, server-visible file.
	tmp, err := os.CreateTemp("", "automation-extract-*.xml")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(automationSampleXML); err != nil {
		t.Fatalf("write: %v", err)
	}
	tmp.Close()

	// Independent H1 over the raw bytes for the cross-check.
	wantH1, err := HashFileH1(tmp.Name())
	if err != nil {
		t.Fatalf("HashFileH1: %v", err)
	}

	// Run the extraction synchronously via wait=true.
	body := `{"path": ` + jsonString(tmp.Name()) + `, "wait": true}`
	c, rec := setupTestContext(http.MethodPost, "/api/automation/extract", body)
	if err := HandleAutomationExtract(c); err != nil {
		t.Fatalf("HandleAutomationExtract failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200 for completed extract, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var job ExtractJob
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatalf("Failed to parse job: %v", err)
	}
	if job.Status != "completed" {
		t.Fatalf("Expected job status completed, got %q (err=%s)", job.Status, job.Error)
	}
	if job.FileHash != wantH1 {
		t.Errorf("H1 mismatch: extract=%s independent=%s", job.FileHash, wantH1)
	}
	if job.MessageCount != 2 {
		t.Errorf("Expected 2 messages extracted, got %d", job.MessageCount)
	}
	if job.RecordCount < 2 {
		t.Errorf("Expected custody record_count >= 2, got %d", job.RecordCount)
	}
	if job.ChainHash == "" {
		t.Error("Expected non-empty H3 chain hash in completed job")
	}

	// The job must now be pollable by id and report the same custody.
	c2, rec2 := setupTestContext(http.MethodGet, "/api/automation/status/"+job.ID, "")
	c2.SetParamNames("id")
	c2.SetParamValues(job.ID)
	if err := HandleAutomationStatus(c2); err != nil {
		t.Fatalf("HandleAutomationStatus failed: %v", err)
	}
	if rec2.Code != http.StatusOK {
		t.Errorf("Expected status 200 polling job, got %d", rec2.Code)
	}
	var polled ExtractJob
	if err := json.Unmarshal(rec2.Body.Bytes(), &polled); err != nil {
		t.Fatalf("Failed to parse polled job: %v", err)
	}
	if polled.FileHash != wantH1 {
		t.Errorf("Polled H1 mismatch: %s != %s", polled.FileHash, wantH1)
	}
}

// jsonString returns a JSON-quoted string literal (escapes backslashes on
// Windows paths so the request body is valid JSON).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
