package parseonly

// Byline: Claude Code · Opus 5 (1M) · 2026-09-06 — DEFECT 3 regression: the
// bracket-timestamp iMessage TXT grammar must route to messages_transcript.
// Fixtures are hand-written structure only; no real message content.

import "testing"

func TestDetectFormatRoutesBracketTimestampTXTToTranscript(t *testing.T) {
	// The shape an iMessage TXT export uses: "[YYYY-MM-DD HH:MM AM/PM] sender:"
	// on its own line, body on the lines after it. Guessing imessage_txt for
	// this file silently yields zero records.
	head := []byte("[2025-01-01 10:00 AM] Sender One:\nalpha text\n\n" +
		"[2025-01-01 10:05 AM] Sender Two:\nbravo text\n\n" +
		"[2025-01-01 10:10 AM] Sender One:\ncharlie text\n")
	format, ok := DetectFormat(head, "+15550000000.txt")
	if !ok {
		t.Fatal("DetectFormat claimed nothing for a bracket-timestamp TXT export")
	}
	if format != FormatTranscript {
		t.Fatalf("DetectFormat = %q, want %q", format, FormatTranscript)
	}
	if _, err := New(format); err != nil {
		t.Fatalf("detected format is not constructible: %v", err)
	}
}

func TestDetectFormatStillRoutesExporterTXTToIMessage(t *testing.T) {
	// The imessage-exporter grammar must not regress onto the transcript lane.
	head := []byte("Jan 01, 2025  10:00:00 AM\nSender One\nalpha text\n\n" +
		"Jan 01, 2025  10:05:00 AM\nSender Two\nbravo text\n")
	format, ok := DetectFormat(head, "export.txt")
	if !ok {
		t.Fatal("DetectFormat claimed nothing for an imessage-exporter TXT export")
	}
	if format != FormatIMessageTXT {
		t.Fatalf("DetectFormat = %q, want %q", format, FormatIMessageTXT)
	}
}

// DEFECT 3b. Detection matched only double-quoted class attributes, so a
// single-quoted iMessage bubble export was claimed by no importer at all.
func TestDetectFormatClaimsSingleQuotedIMessageBubbleHTML(t *testing.T) {
	head := []byte(`<!DOCTYPE html><html><head><style>.bubble{}</style></head><body>` +
		`<div class='message-container'><div style='text-align: left;'>` +
		`<div class='bubble from-them'>alpha text</div>` +
		`<div class='meta'>Sender One - 2025-01-01 10:00 AM</div></div></div></body></html>`)
	format, ok := DetectFormat(head, "index.html")
	if !ok {
		t.Fatal("DetectFormat claimed nothing for a single-quoted iMessage bubble export")
	}
	if format != FormatIMessageHTML {
		t.Fatalf("DetectFormat = %q, want %q", format, FormatIMessageHTML)
	}
}

func TestDetectFormatRoutesSMSBackupXMLAndReportsUnknown(t *testing.T) {
	head := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<smses count="3">`)
	format, ok := DetectFormat(head, "sms-20250101000000.xml")
	if !ok || format != FormatSMSBackupXML {
		t.Fatalf("DetectFormat = %q ok=%v, want %q true", format, ok, FormatSMSBackupXML)
	}
	if format, ok := DetectFormat([]byte("not a messaging export at all"), "notes.dat"); ok {
		t.Fatalf("DetectFormat claimed %q for an unrecognised source; it must report unknown", format)
	}
}
