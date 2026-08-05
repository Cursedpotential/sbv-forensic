package internal

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEMLImporterGoldenMIMEAndExactH2(t *testing.T) {
	source, err := os.ReadFile("testdata/sample.eml")
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{artifactDir: t.TempDir()}
	importer := emlImporter{}
	if !importer.Detect(source, "sample.eml") {
		t.Fatal("EML signature not detected")
	}
	if err := importer.Run(sink, bufio.NewReader(bytes.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	rec := sink.records[0]
	if rec.Kind != KindEmail || rec.PrecomputedH2 != HashRecordH2(source) || rec.RawSize != int64(len(source)) || rec.Raw != nil {
		t.Fatalf("custody=%+v", rec)
	}
	if rec.Content != "The plain evidence body." || rec.OccurredAt == nil || rec.Metadata["message_id"] != "<message-1@example.com>" ||
		rec.Metadata["in_reply_to"] != "<earlier@example.com>" {
		t.Fatalf("projection=%+v", rec)
	}
	if len(rec.Attachments) != 1 || rec.Attachments[0].OriginalName != "filing.pdf" ||
		rec.Attachments[0].DecodedHash != HashBytesSHA256([]byte("evidence-attachment")) {
		t.Fatalf("attachments=%+v", rec.Attachments)
	}
	data, err := os.ReadFile(rec.Attachments[0].StoredPath)
	if err != nil || string(data) != "evidence-attachment" {
		t.Fatalf("attachment=%q err=%v", data, err)
	}
}

func TestMBOXImporterGoldenExactSpansAndNoSyntheticDate(t *testing.T) {
	source, err := os.ReadFile("testdata/sample.mbox")
	if err != nil {
		t.Fatal(err)
	}
	importer := mboxImporter{}
	if !importer.Detect(source, "sample.mbox") {
		t.Fatal("MBOX signature not detected")
	}
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := importer.Run(sink, bufio.NewReader(bytes.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 2 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	boundary := bytes.Index(source[1:], []byte("From owner@example.com Wed Jan 03")) + 1
	if boundary <= 0 {
		t.Fatal("fixture boundary missing")
	}
	for index, span := range [][]byte{source[:boundary], source[boundary:]} {
		if sink.records[index].PrecomputedH2 != HashRecordH2(span) || sink.records[index].RawSize != int64(len(span)) {
			t.Fatalf("record %d custody=%+v", index, sink.records[index])
		}
	}
	if sink.records[0].Content != "First exact message." || sink.records[1].Content != "Second HTML message." {
		t.Fatalf("content=%q / %q", sink.records[0].Content, sink.records[1].Content)
	}
	if sink.records[1].OccurredAt != nil {
		t.Fatalf("missing Date was synthesized: %v", sink.records[1].OccurredAt)
	}
	if !strings.HasPrefix(sink.records[0].Metadata["mbox_separator"].(string), "From alex@example.com") {
		t.Fatalf("separator metadata=%#v", sink.records[0].Metadata["mbox_separator"])
	}
}

func TestEMLImporterRejectsOversizeHeaderButStillHashesExactMessage(t *testing.T) {
	source := []byte("From: alex@example.com\nSubject: " + strings.Repeat("x", maxEmailHeaderLineBytes+1) + "\n\nbody")
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := (emlImporter{}).Run(sink, bufio.NewReader(bytes.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if sink.rejects != 1 || len(sink.records) != 0 || sink.lastRejectH2 != HashRecordH2(source) {
		t.Fatalf("records=%d rejects=%d h2=%s", len(sink.records), sink.rejects, sink.lastRejectH2)
	}
}
