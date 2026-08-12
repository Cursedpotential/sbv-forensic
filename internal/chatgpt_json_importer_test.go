package internal

import (
	"bufio"
	"strings"
	"testing"
)

// A minimal but structurally-real ChatGPT export: a top-level array of conversations,
// each a mapping node graph (root has no message; user -> assistant chain below it).
const sampleChatGPTExport = `[
  {
    "title": "Custody Test",
    "create_time": 1700000000.0,
    "conversation_id": "conv-1",
    "mapping": {
      "root": {"id": "root", "message": null, "parent": null, "children": ["n1"]},
      "n1": {"id": "n1", "parent": "root", "children": ["n2"], "message": {"id": "m1", "author": {"role": "user"}, "create_time": 1700000000.0, "content": {"content_type": "text", "parts": ["hello there"]}}},
      "n2": {"id": "n2", "parent": "n1", "children": [], "message": {"id": "m2", "author": {"role": "assistant"}, "create_time": 1700000005.0, "content": {"content_type": "text", "parts": ["hi, how can I help"]}}}
    }
  }
]`

func TestChatgptJSONDetect(t *testing.T) {
	imp := chatgptJSONImporter{}
	if !imp.Detect([]byte(`[{"title":"x","create_time":1.0,"mapping":{`), "export_2025.json") {
		t.Fatal("expected content-signature detection (mapping + create_time), filename-independent")
	}
	if !imp.Detect([]byte(`[{"foo":1}`), "conversations.json") {
		t.Fatal("expected filename fallback detection")
	}
	if imp.Detect([]byte(`{"chat_messages":[{"text":"hi"}]}`), "claude.json") {
		t.Fatal("must not detect a non-ChatGPT (Claude) export")
	}
}

func TestChatgptJSONImporterStreamsMessagesInOrder(t *testing.T) {
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := (chatgptJSONImporter{}).Run(sink, bufio.NewReader(strings.NewReader(sampleChatGPTExport))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 2 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d, want 2/0", len(sink.records), sink.rejects)
	}
	r0, r1 := sink.records[0], sink.records[1]

	if r0.Content != "hello there" || r1.Content != "hi, how can I help" {
		t.Fatalf("content/order mismatch: %q then %q", r0.Content, r1.Content)
	}
	if len(r0.Participants) != 1 || r0.Participants[0] != "user" || r1.Participants[0] != "assistant" {
		t.Fatalf("roles wrong: %v then %v", r0.Participants, r1.Participants)
	}
	if r0.OccurredAt == nil || r0.OccurredAt.Unix() != 1700000000 {
		t.Fatalf("r0 OccurredAt not derived from create_time: %v", r0.OccurredAt)
	}
	// Custody: Raw must be the EXACT message bytes (H2 input), never reformatted.
	if r0.RawCanon != "h2-rawrecord-v1" || len(r0.Raw) == 0 || !strings.Contains(string(r0.Raw), "hello there") {
		t.Fatalf("r0 raw custody wrong: canon=%q rawlen=%d", r0.RawCanon, len(r0.Raw))
	}
	if r0.Kind != "message" {
		t.Fatalf("r0.Kind=%q, want message", r0.Kind)
	}
	if r0.Metadata["conversation_title"] != "Custody Test" ||
		r0.Metadata["role"] != "user" ||
		r0.Metadata["source_format"] != chatgptJSONFormat {
		t.Fatalf("r0 metadata mismatch: %v", r0.Metadata)
	}
}

func TestChatgptJSONImporterRegisteredAndPriority(t *testing.T) {
	imp := chatgptJSONImporter{}
	if imp.Format() != "chatgpt-official-json" {
		t.Fatalf("format=%q", imp.Format())
	}
	// Registered in the shared importer registry (init()).
	found := false
	for _, r := range RegisteredImporters() {
		if r.Format() == chatgptJSONFormat {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("chatgpt decoder not registered in the importer registry")
	}
}
