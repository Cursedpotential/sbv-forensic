package parseonly

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChatGPTFacadePreservesOrderRawBytesAndTimestamp(t *testing.T) {
	input := `[{"title":"Conversation","create_time":1700000000,"mapping":{"root":{"id":"root","parent":null,"children":["n1"]},"n1":{"id":"n1","parent":"root","children":[],"message":{"id":"m1","author":{"role":"user"},"create_time":1700000001,"content":{"content_type":"text","parts":["hello"]}}}}}]`
	importer, err := New(FormatChatGPTJSON)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	if err := importer.Parse(context.Background(), strings.NewReader(input), func(_ context.Context, record Record) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != StatusParsed || string(records[0].Raw) == "" {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Content != "hello" || records[0].OccurredAt == nil || records[0].OccurredAt.Unix() != 1700000001 {
		t.Fatalf("record projection = %+v", records[0])
	}
	if !strings.Contains(string(records[0].Raw), `"id":"m1"`) {
		t.Fatalf("raw message bytes were not preserved: %s", records[0].Raw)
	}
}

func TestEmailFormatsAreExplicitlyExcludedWhenRawBytesAreUnavailable(t *testing.T) {
	for _, format := range []string{FormatEML, FormatMBOX} {
		if _, err := New(format); err == nil {
			t.Fatalf("%s was accepted despite missing exact raw-byte output", format)
		}
	}
}

func TestRetainedSMSXMLPersistsEveryMMSPartAndExactRawRecord(t *testing.T) {
	parts := [][]byte{[]byte("image-one"), []byte("document-two"), []byte("audio-three")}
	input := `<smses count="1"><mms date="1700000000000" msg_box="1" read="1"><parts>` +
		`<part seq="0" ct="image/png" name="photo.png" data="aW1hZ2Utb25l" />` +
		`<part seq="1" ct="application/pdf" name="filing.pdf" data="ZG9jdW1lbnQtdHdv" />` +
		`<part seq="2" ct="audio/mpeg" name="memo.mp3" data="YXVkaW8tdGhyZWU=" />` +
		`</parts><addrs><addr address="+15551234567" type="137" /></addrs></mms></smses>`
	importer, err := New(FormatSMSBackupXML)
	if err != nil {
		t.Fatal(err)
	}
	sink := newImmutableTestSink(t)
	var records []Record
	err = importer.ParseWithArtifacts(context.Background(), strings.NewReader(input), "source-version-42", sink,
		func(_ context.Context, record Record) error {
			records = append(records, record)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	record := records[0]
	if record.RawLocator == nil || len(record.Raw) != 0 {
		t.Fatalf("raw projection=%+v bytes=%d", record.RawLocator, len(record.Raw))
	}
	rawMMS := input[strings.Index(input, "<mms ") : strings.Index(input, "</mms>")+len("</mms>")]
	assertLocatorBytes(t, sink.root, *record.RawLocator, []byte(rawMMS))
	if len(record.Attachments) != len(parts) {
		t.Fatalf("attachments=%d, want %d: %+v", len(record.Attachments), len(parts), record.Attachments)
	}
	wantNames := []string{"photo.png", "filing.pdf", "memo.mp3"}
	wantMIME := []string{"image/png", "application/pdf", "audio/mpeg"}
	seen := make(map[string]struct{}, len(parts))
	for index, attachment := range record.Attachments {
		if attachment.AttachmentOrdinal != uint64(index) || attachment.SourceAssociation != "source-version-42" || attachment.ParentSourcePos != "element:1" {
			t.Fatalf("attachment association=%+v", attachment)
		}
		if attachment.OriginalName != wantNames[index] || attachment.MIME != wantMIME[index] || attachment.ByteCount != int64(len(parts[index])) {
			t.Fatalf("attachment metadata=%+v", attachment)
		}
		wantHash := sha256Hex(parts[index])
		if attachment.DigestSHA256 != wantHash || attachment.Locator.ContentHash != wantHash {
			t.Fatalf("attachment digest=%+v want=%s", attachment, wantHash)
		}
		if _, duplicate := seen[attachment.Locator.URI]; duplicate {
			t.Fatalf("duplicate attachment locator %q", attachment.Locator.URI)
		}
		seen[attachment.Locator.URI] = struct{}{}
		assertLocatorBytes(t, sink.root, attachment.Locator, parts[index])
	}
	if len(sink.stored) != 4 || sink.stored[0].Kind != ArtifactRawRecord {
		t.Fatalf("stored artifacts=%+v", sink.stored)
	}
	if !sink.completed || sink.quarantined {
		t.Fatalf("attempt lifecycle completed=%v quarantined=%v", sink.completed, sink.quarantined)
	}
	for _, artifact := range sink.stored {
		if artifact.SourceAssociation != "source-version-42" || artifact.ParentSourcePos != "element:1" {
			t.Fatalf("unstable source association: %+v", artifact)
		}
	}
}

func TestMMSArtifactSinkFailuresAreFatal(t *testing.T) {
	input := `<smses count="1"><mms date="1700000000000" msg_box="1"><parts><part seq="0" ct="image/png" data="aW1hZ2U=" /></parts><addrs><addr address="+1555" type="137" /></addrs></mms></smses>`
	importer, err := New(FormatSMSBackupXML)
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Parse(context.Background(), strings.NewReader(input), func(context.Context, Record) error { return nil }); err == nil {
		t.Fatal("MMS parse succeeded without an immutable artifact sink")
	}
	failing := &failingArtifactSink{root: t.TempDir(), err: errors.New("object store unavailable")}
	err = importer.ParseWithArtifacts(context.Background(), strings.NewReader(input), "source-version-42", failing,
		func(context.Context, Record) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "object store unavailable") {
		t.Fatalf("unwritable sink error=%v", err)
	}
}

func TestMalformedMMSAttachmentIsRejectedAndQuarantined(t *testing.T) {
	input := `<smses count="1"><mms date="1700000000000" msg_box="1"><parts><part seq="0" ct="image/png" name="broken.png" data="%%%not-base64%%%" /></parts><addrs><addr address="+1555" type="137" /></addrs></mms></smses>`
	importer, err := New(FormatSMSBackupXML)
	if err != nil {
		t.Fatal(err)
	}
	sink := newImmutableTestSink(t)
	var records []Record
	if err := importer.ParseWithArtifacts(context.Background(), strings.NewReader(input), "source-version-42", sink, func(_ context.Context, record Record) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != StatusRejected || records[0].CapturedAttachments != 1 {
		t.Fatalf("records=%+v", records)
	}
	if len(records[0].Attachments) != 0 || len(records[0].AttachmentFailures) != 1 {
		t.Fatalf("attachment outcome=%+v", records[0])
	}
	failure := records[0].AttachmentFailures[0]
	if failure.ConversionStatus != "decode_failed" || strings.TrimSpace(failure.ConversionError) == "" {
		t.Fatalf("failure=%+v", failure)
	}
	if !sink.quarantined || sink.completed {
		t.Fatalf("attempt lifecycle completed=%v quarantined=%v", sink.completed, sink.quarantined)
	}
	for _, artifact := range sink.stored {
		if artifact.Kind == ArtifactAttachment {
			t.Fatal("malformed partial attachment was published")
		}
	}
}

func TestMMSDataAttributeAllowsXMLWhitespaceAroundEquals(t *testing.T) {
	input := "<smses count=\"1\"><mms date=\"1700000000000\" msg_box=\"1\"><parts>" +
		"<part seq=\"0\" ct=\"image/png\" name=\"spaced.png\" data \t=\r\n \"aW1hZ2U=\" />" +
		"</parts><addrs><addr address=\"+1555\" type=\"137\" /></addrs></mms></smses>"
	importer, err := New(FormatSMSBackupXML)
	if err != nil {
		t.Fatal(err)
	}
	sink := newImmutableTestSink(t)
	var records []Record
	if err := importer.ParseWithArtifacts(context.Background(), strings.NewReader(input), "source-version-42", sink, func(_ context.Context, record Record) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].CapturedAttachments != 1 || len(records[0].Attachments) != 1 {
		t.Fatalf("XML-whitespace attachment capture=%+v", records)
	}
	assertLocatorBytes(t, sink.root, records[0].Attachments[0].Locator, []byte("image"))
}

type immutableTestSink struct {
	t           *testing.T
	stage       string
	root        string
	stored      []Artifact
	completed   bool
	quarantined bool
}

func newImmutableTestSink(t *testing.T) *immutableTestSink {
	base := t.TempDir()
	stage := filepath.Join(base, "stage")
	root := filepath.Join(base, "objects")
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	return &immutableTestSink{t: t, stage: stage, root: root}
}

func (s *immutableTestSink) ArtifactDir(_ context.Context, sourceAssociation, attemptID string) (string, error) {
	if sourceAssociation == "" || attemptID == "" {
		return "", errors.New("missing source association")
	}
	return s.stage, nil
}

func (s *immutableTestSink) Store(_ context.Context, artifact Artifact) (ArtifactLocator, error) {
	data, err := os.ReadFile(artifact.StagedPath)
	if err != nil {
		return ArtifactLocator{}, err
	}
	digest := sha256Hex(data)
	association := sha256Hex([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d", artifact.SourceAssociation, artifact.Kind, artifact.ParentSourcePos, artifact.AttachmentOrdinal)))
	path := filepath.Join(s.root, association)
	if existing, readErr := os.ReadFile(path); readErr == nil {
		if !bytes.Equal(existing, data) {
			return ArtifactLocator{}, errors.New("logical identity conflict")
		}
		return ArtifactLocator{StorageClass: "filesystem", URI: path, ContentHash: digest}, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ArtifactLocator{}, err
	}
	if _, err := io.Copy(file, bytes.NewReader(data)); err != nil {
		_ = file.Close()
		return ArtifactLocator{}, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ArtifactLocator{}, err
	}
	if err := file.Close(); err != nil {
		return ArtifactLocator{}, err
	}
	s.stored = append(s.stored, artifact)
	return ArtifactLocator{StorageClass: "filesystem", URI: path, ContentHash: digest}, nil
}

func (s *immutableTestSink) CompleteAttempt(context.Context, string, string) error {
	s.completed = true
	return nil
}

func (s *immutableTestSink) QuarantineAttempt(context.Context, string, string, string) error {
	s.quarantined = true
	return nil
}

type failingArtifactSink struct {
	root string
	err  error
}

func (s *failingArtifactSink) ArtifactDir(context.Context, string, string) (string, error) {
	return s.root, nil
}
func (s *failingArtifactSink) Store(context.Context, Artifact) (ArtifactLocator, error) {
	return ArtifactLocator{}, s.err
}
func (s *failingArtifactSink) CompleteAttempt(context.Context, string, string) error { return nil }
func (s *failingArtifactSink) QuarantineAttempt(context.Context, string, string, string) error {
	return nil
}

func assertLocatorBytes(t *testing.T, root string, locator ArtifactLocator, want []byte) {
	t.Helper()
	relative, err := filepath.Rel(root, locator.URI)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		t.Fatalf("locator escaped immutable root: %q (%v)", locator.URI, err)
	}
	data, err := os.ReadFile(locator.URI)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("locator %q bytes=%q want=%q", locator.URI, data, want)
	}
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
