package internal

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFacebookJSONGoldenVariantsExactCustodyAndSourceOrder(t *testing.T) {
	source, err := os.ReadFile("testdata/facebook_message_1.json")
	if err != nil {
		t.Fatal(err)
	}
	importer := facebookJSONImporter{}
	if !importer.Detect(source[:min(len(source), detectPeekBytes)], "message_1.json") {
		t.Fatal("Facebook signature not detected")
	}
	if (googleChatImporter{}).Detect(source, "message_1.json") {
		t.Fatal("Facebook export was stolen by Google Chat")
	}
	if got := DetectImporter(source[:min(len(source), detectPeekBytes)], "message_1.json"); got == nil || got.Format() != FormatFacebookJSON {
		t.Fatalf("registry selected %v", got)
	}
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := importer.Run(sink, bufio.NewReader(bytes.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 6 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)

	firstStart := bytes.Index(source, []byte(`{"sender_name":"Ex","timestamp_ms":1700000300000`))
	firstEnd := bytes.Index(source[firstStart:], []byte("},\n    {")) + firstStart + 1
	if firstStart < 0 || firstEnd <= firstStart || !bytes.Equal(sink.records[0].Raw, source[firstStart:firstEnd]) {
		t.Fatalf("first raw span changed: %q", sink.records[0].Raw)
	}
	if sink.records[0].RawSize != int64(firstEnd-firstStart) || HashRecordH2(sink.records[0].Raw) != HashRecordH2(source[firstStart:firstEnd]) {
		t.Fatalf("unexpected source record custody fields: %+v", sink.records[0])
	}
	first := sink.records[0]
	if first.Content != "meet at the café 😀" || first.Metadata["content_original"] != "meet at the cafÃ© 😀" ||
		first.Metadata["sender_name_display"] != "Ex" || first.Metadata["export_order"] != "reverse_chronological_as_exported" ||
		first.Metadata["source_sequence"] != 0 || first.Metadata["thread_title_display"] != "Gróup Chat 😀" {
		t.Fatalf("first=%+v", first)
	}
	participants := first.Metadata["participants_display"].([]string)
	threadContext := first.Metadata["raw_thread_context"].(map[string]interface{})
	if len(participants) != 3 || participants[0] != "Mé" || threadContext["is_still_participant"] != true ||
		threadContext["thread_type"] != "RegularGroup" || len(threadContext["magic_words"].([]interface{})) != 1 {
		t.Fatalf("participants=%#v context=%#v", participants, threadContext)
	}
	reactions := first.Metadata["reactions"].([]map[string]interface{})
	if len(reactions) != 1 || reactions[0]["reaction_display"] != "👍" || reactions[0]["actor_original"] != "MÃ©" {
		t.Fatalf("reactions=%#v", reactions)
	}

	media := sink.records[1].Metadata["media"].([]map[string]interface{})
	if len(media) != 5 || media[0]["uri"] != "inbox/ex/photos/1.jpg" || media[0]["safe_relative"] != true ||
		media[3]["uri"] != "" || media[3]["safe_relative"] != false || media[3]["uri_original"] != "../escape.pdf" {
		t.Fatalf("media=%#v", media)
	}
	refs := sink.records[1].AttachmentReferences
	if len(refs) != 6 || refs[0].ResolutionStatus != AttachmentReferenceOnly || !refs[0].SafeRelative ||
		refs[3].ResolutionStatus != AttachmentUnsafeReference || refs[3].SafeRelative {
		t.Fatalf("attachment references=%#v", refs)
	}
	if sink.records[1].Metadata["sticker"].(map[string]interface{})["uri"] != "stickers/1.png" {
		t.Fatalf("sticker=%#v", sink.records[1].Metadata["sticker"])
	}
	share := sink.records[1].Metadata["share"].(map[string]interface{})
	if share["share_text_display"] != "sháred text" || share["original_content_owner_display"] != "Créator" {
		t.Fatalf("share=%#v", share)
	}
	if sink.records[2].Kind != KindCall || !strings.Contains(sink.records[2].Content, "Missed Facebook call") ||
		sink.records[2].Metadata["ip"] != "192.0.2.4" {
		t.Fatalf("call=%+v", sink.records[2])
	}
	if sink.records[3].Kind != "event" || sink.records[3].Metadata["users"] == nil {
		t.Fatalf("system=%+v", sink.records[3])
	}
	if sink.records[4].Kind != "reaction" || !strings.Contains(sink.records[4].Content, "reaction-only") {
		t.Fatalf("reaction-only source object was lost: %+v", sink.records[4])
	}
	if sink.records[5].OccurredAt != nil || sink.records[5].Content != "No timestamp was exported." {
		t.Fatalf("missing timestamp was fabricated: %+v", sink.records[5])
	}
}

func TestFacebookJSONOversizeRecordUsesStreamedExactRejection(t *testing.T) {
	message := `{"sender_name":"Ex","timestamp_ms":1700000000000,"content":"` + strings.Repeat("x", 1024) + `"}`
	source := `{"participants":[{"name":"Ex"}],"messages":[` + message + `],"title":"Ex"}`
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := runFacebookJSONImport(sink, bufio.NewReader(strings.NewReader(source)), 128); err != nil {
		t.Fatal(err)
	}
	if sink.rejects != 1 || len(sink.records) != 0 || sink.lastRejectH2 != HashRecordH2([]byte(message)) ||
		sink.lastRejectRawSize != int64(len(message)) {
		t.Fatalf("records=%d rejects=%d h2=%s size=%d", len(sink.records), sink.rejects, sink.lastRejectH2, sink.lastRejectRawSize)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)
}

func TestFacebookJSONDetectionRejectsArbitraryJSONAndHandlesDeepParticipants(t *testing.T) {
	importer := facebookJSONImporter{}
	if importer.Detect([]byte(`{"participants":[],"some":"other json"}`), "ordinary.json") {
		t.Fatal("arbitrary JSON was claimed")
	}
	deepHead := []byte(`{"participants":[{"name":"` + strings.Repeat("x", detectPeekBytes))
	if !importer.Detect(deepHead, "message_99.json") {
		t.Fatal("message_N export with deep participant header was not admitted for bounded Run validation")
	}
	if importer.Priority() <= (googleChatImporter{}).Priority() || importer.Priority() <= (ndjsonImporter{}).Priority() {
		t.Fatal("Facebook priority must stay ahead of Google Chat and NDJSON")
	}
}

func TestFacebookJSONDeepValidationRejectsFalsePositiveAndQuarantinesSpool(t *testing.T) {
	source, err := os.ReadFile("testdata/facebook_false_positive_message_1.json")
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{artifactDir: t.TempDir()}
	err = runFacebookJSONImport(sink, bufio.NewReader(bytes.NewReader(source)), maxRawRecordBytes)
	if err == nil || !strings.Contains(err.Error(), "lack sender_name/timestamp_ms signature") {
		t.Fatalf("false-positive export was accepted: err=%v", err)
	}
	if len(sink.records) != 0 || sink.rejects != 0 {
		t.Fatalf("false positive reached custody: records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)
}

func TestFacebookJSONOversizeFalsePositiveIsNotDurablyRejected(t *testing.T) {
	// The key names occur inside a string value, not as JSON member keys. The
	// bounded overflow-prefix validator must not mistake them for a signature.
	message := `{"payload":"mentions \\"sender_name\\" and \\"timestamp_ms\\" only as text ` + strings.Repeat("x", 1024) + `"}`
	source := `{"participants":[{"name":"Example"}],"messages":[` + message + `],"title":"Not Messenger"}`
	sink := &captureSink{artifactDir: t.TempDir()}
	err := runFacebookJSONImport(sink, bufio.NewReader(strings.NewReader(source)), 256)
	if err == nil || !strings.Contains(err.Error(), "lack sender_name/timestamp_ms signature") {
		t.Fatalf("oversized false positive was accepted: err=%v", err)
	}
	if len(sink.records) != 0 || sink.rejects != 0 {
		t.Fatalf("oversized false positive reached custody: records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)
}

func TestFacebookJSONOversizeNestedSignatureKeysAreNotDurablyRejected(t *testing.T) {
	message := `{"metadata":{"sender_name":"Nested","timestamp_ms":1700000000000},"payload":"` + strings.Repeat("x", 1024) + `"}`
	source := `{"participants":[{"name":"Example"}],"messages":[` + message + `],"title":"Not Messenger"}`
	sink := &captureSink{artifactDir: t.TempDir()}
	err := runFacebookJSONImport(sink, bufio.NewReader(strings.NewReader(source)), 256)
	if err == nil || !strings.Contains(err.Error(), "lack sender_name/timestamp_ms signature") {
		t.Fatalf("oversized nested-key false positive was accepted: err=%v", err)
	}
	if len(sink.records) != 0 || sink.rejects != 0 {
		t.Fatalf("oversized nested-key false positive reached custody: records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)
}

func TestFacebookJSONShareRemainsMessage(t *testing.T) {
	source := `{"participants":[{"name":"Ex"}],"messages":[{"sender_name":"Ex","timestamp_ms":1700000000000,"type":"Share","share":{"link":"https://example.invalid"}}],"title":"Ex"}`
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := runFacebookJSONImport(sink, bufio.NewReader(strings.NewReader(source)), maxRawRecordBytes); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || sink.records[0].Kind != KindMessage || sink.records[0].Metadata["is_system_event"] != false {
		t.Fatalf("Share was not preserved as a message: %#v", sink.records)
	}
	assertFacebookSpoolQuarantined(t, sink.artifactDir)
}

func assertFacebookSpoolQuarantined(t *testing.T, root string) {
	t.Helper()
	active, err := os.ReadDir(filepath.Join(root, "facebook-spools"))
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("active Facebook spool directory is not empty: %#v", active)
	}
	spools := 0
	err = filepath.WalkDir(filepath.Join(root, "to_be_deleted"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), "messages-") && strings.HasSuffix(entry.Name(), ".bin") {
			spools++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if spools != 1 {
		t.Fatalf("expected one quarantined Facebook spool, found %d", spools)
	}
}
