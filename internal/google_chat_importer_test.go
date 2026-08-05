package internal

import (
	"bufio"
	"bytes"
	"os"
	"testing"
)

func TestGoogleChatSingleFileExactObjectsAndUnresolvedContext(t *testing.T) {
	source, err := os.ReadFile("testdata/google_chat_messages.json")
	if err != nil {
		t.Fatal(err)
	}
	importer := googleChatImporter{}
	if !importer.Detect(source, "messages.json") {
		t.Fatal("Google Chat signature not detected")
	}
	sink := &captureSink{}
	if err := importer.Run(sink, bufio.NewReader(bytes.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 2 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	firstStart := bytes.Index(source, []byte("{\n      \"creator\""))
	firstEnd := bytes.Index(source[firstStart:], []byte("\n    }")) + firstStart + len("\n    }")
	if firstStart < 0 || firstEnd <= firstStart || !bytes.Equal(sink.records[0].Raw, source[firstStart:firstEnd]) {
		t.Fatalf("first raw span changed: %q", sink.records[0].Raw)
	}
	if sink.records[0].Content != "The first chat message." || sink.records[0].OccurredAt == nil ||
		sink.records[0].Metadata["message_id"] != "message-1" ||
		sink.records[0].Metadata["bundle_context"] != "unresolved_missing_group_info" {
		t.Fatalf("first=%+v", sink.records[0])
	}
	refs, ok := sink.records[1].Metadata["attachment_references"].([]map[string]interface{})
	if !ok || len(refs) != 1 || refs[0]["uri"] != "Files/photo.jpg" || refs[0]["name"] != "Family Photo.jpg" ||
		refs[0]["content_type"] != "image/jpeg" || refs[0]["safe_relative"] != true || refs[0]["unresolved"] != true {
		t.Fatalf("refs=%#v", sink.records[1].Metadata["attachment_references"])
	}
	if safeJSONCompanionReference("../escape.jpg") || safeJSONCompanionReference("https://example.com/file") {
		t.Fatal("unsafe companion reference accepted")
	}
}
