package internal

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestGoogleVoiceHTMLGoldenMessage(t *testing.T) {
	source, err := os.ReadFile("testdata/google_voice_messages.html")
	if err != nil {
		t.Fatal(err)
	}
	importer := googleVoiceHTMLImporter{}
	if !importer.Detect(source, "calls.html") || (facebookHTMLImporter{}).Detect(source, "calls.html") {
		t.Fatal("Google Voice signature was not distinct")
	}
	sink := &captureSink{}
	if err := importer.Run(sink, bufio.NewReader(strings.NewReader(string(source)))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	rec := sink.records[0]
	if rec.Kind != KindMessage || rec.Content != "Can you call me?" || rec.OccurredAt == nil ||
		rec.Metadata["direction"] != "inbound" || rec.Metadata["telephone"] != "+15551234567" {
		t.Fatalf("record=%+v", rec)
	}
	if string(rec.Raw) != `<div class="message incoming"><abbr class="dt" title="2024-01-02T14:30:00-05:00">Jan 2, 2024</abbr><cite class="sender vcard"><span class="fn">Alex Example</span> <a class="tel" href="tel:+15551234567">mobile</a></cite><q>Can you call me?</q><span class="label">Received</span></div>` {
		t.Fatalf("raw H2 span changed: %q", rec.Raw)
	}
}

func TestGoogleVoiceHTMLGoldenVoicemail(t *testing.T) {
	source, err := os.ReadFile("testdata/google_voice_voicemail.html")
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	if err := (googleVoiceHTMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(string(source)))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].Kind != KindVoicemail {
		t.Fatalf("records=%+v rejects=%d", sink.records, sink.rejects)
	}
	rec := sink.records[0]
	if rec.Content != "Please call when you get this." || rec.Metadata["duration"] != "00:42" {
		t.Fatalf("record=%+v", rec)
	}
	refs, ok := rec.Metadata["audio_attachments"].([]map[string]interface{})
	if !ok || len(refs) != 1 || refs[0]["uri"] != "Voicemail - 2024-01-03.mp3" || refs[0]["unresolved"] != true {
		t.Fatalf("audio refs=%#v", rec.Metadata["audio_attachments"])
	}
}
