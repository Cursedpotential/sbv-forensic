package internal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

type captureSink struct {
	records           []*SourceRecord
	rejects           int
	artifactDir       string
	lastRejectH2      string
	lastRejectRawSize int64
}

func (*captureSink) ImportID() int64                { return 1 }
func (s *captureSink) ArtifactDir() (string, error) { return s.artifactDir, nil }
func (*captureSink) Claim(int)                      {}
func (s *captureSink) Record(rec *SourceRecord) error {
	s.records = append(s.records, rec)
	return nil
}
func (s *captureSink) Reject(string, string, []byte, bool) error {
	s.rejects++
	return nil
}
func (s *captureSink) RejectHashed(_, _, h2, _ string, rawSize int64) error {
	s.rejects++
	s.lastRejectH2 = h2
	s.lastRejectRawSize = rawSize
	return nil
}

func TestNDJSONImporterPreservesRawLineBeforeProjection(t *testing.T) {
	raw := "{\"body\":\" hello \",\"timestamp\":1700000000000,\"sender\":\"+1555\"}\r\n"
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := (ndjsonImporter{}).Run(sink, bufio.NewReader(strings.NewReader(raw))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 1 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d, want 1/0", len(sink.records), sink.rejects)
	}
	rec := sink.records[0]
	if got, want := string(rec.Raw), strings.TrimSuffix(raw, "\r\n"); got != want {
		t.Fatalf("raw H2 span changed: got %q want %q", got, want)
	}
	if rec.RawCanon != RecordHashCanonRawV1 {
		t.Fatalf("record canon=%q", rec.RawCanon)
	}
	if rec.Content != " hello " || rec.OccurredAt == nil || rec.OccurredAt.UnixMilli() != 1700000000000 {
		t.Fatalf("projection mismatch: %#v", rec)
	}
}

func TestImporterDetectionUsesExplicitPriority(t *testing.T) {
	got := detectFrom([]Importer{ndjsonImporter{}, smsXMLImporter{}},
		[]byte("<smses count=\"0\"></smses>"), "backup.xml")
	if got == nil || got.Format() != FormatSMSBackupXML {
		t.Fatalf("detected %v, want SMS XML", got)
	}
	got = DetectImporter([]byte("{\"a\":1}\n{\"a\":2}\n"), "evidence.bin")
	if got == nil || got.Format() != FormatNDJSON {
		t.Fatalf("content detection=%v, want NDJSON", got)
	}
}

func TestSMSXMLImporterKeepsAttachmentOnlyMMS(t *testing.T) {
	xmlSource := `<smses count="1"><mms date="1700000000000" msg_box="1" read="1" ct_t="application/vnd.wap.multipart.related"><parts><part seq="0" ct="image/png" data="aW1hZ2U=" /></parts><addrs><addr address="+15551234567" type="137" /></addrs></mms></smses>`
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(xmlSource))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 1 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	rec := sink.records[0]
	if rec.LegacyMessage == nil || rec.LegacyMessage.Body != "" || rec.LegacyMessage.MediaType != "image/png" {
		t.Fatalf("attachment-only MMS lost: %+v", rec.LegacyMessage)
	}
	rawMMS := xmlSource[strings.Index(xmlSource, "<mms ") : strings.Index(xmlSource, "</mms>")+len("</mms>")]
	if rec.Raw != nil || rec.RawSize != int64(len(rawMMS)) || rec.PrecomputedH2 != HashRecordH2([]byte(rawMMS)) {
		t.Fatalf("streamed raw custody mismatch: size=%d h2=%s", rec.RawSize, rec.PrecomputedH2)
	}
	if len(rec.Attachments) != 1 || rec.Attachments[0].MIME != "image/png" || rec.Attachments[0].DecodedHash != HashBytesSHA256([]byte("image")) {
		t.Fatalf("attachment manifest: %+v", rec.Attachments)
	}
	decoded, err := os.ReadFile(rec.Attachments[0].StoredPath)
	if err != nil || string(decoded) != "image" {
		t.Fatalf("spooled attachment=%q err=%v", decoded, err)
	}
}

func TestSMSXMLImporterStreamsAttachmentLargerThanWorkBuffer(t *testing.T) {
	// Generate an 8 MiB decoded part through an io.Pipe. Neither the test nor the
	// importer ever assembles the encoded attribute or raw MMS element in memory.
	// The contract is not merely success: SourceRecord.Raw stays nil while the
	// exact H2/raw_size and the independently streamed child hash still agree.
	const decodedSize = int64(8 << 20)
	mmsPrefix := `<mms date="1700000000000" msg_box="1"><parts><part seq="0" ct="application/octet-stream" data="`
	mmsSuffix := `" /></parts><addrs><addr address="+1555" type="137" /></addrs></mms>`
	source := io.MultiReader(
		strings.NewReader(`<smses count="1">`+mmsPrefix),
		streamBase64Repeat('a', decodedSize),
		strings.NewReader(mmsSuffix+`</smses>`),
	)
	sink := &captureSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReaderSize(source, 64<<10)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 1 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	rec := sink.records[0]
	expectedH2 := sha256.New()
	_, _ = io.WriteString(expectedH2, mmsPrefix)
	if _, err := io.Copy(expectedH2, streamBase64Repeat('a', decodedSize)); err != nil {
		t.Fatalf("expected H2 stream: %v", err)
	}
	_, _ = io.WriteString(expectedH2, mmsSuffix)
	expectedRawSize := int64(len(mmsPrefix)+len(mmsSuffix)) + int64(base64.StdEncoding.EncodedLen(int(decodedSize)))
	if rec.Raw != nil || rec.RawSize != expectedRawSize || rec.PrecomputedH2 != hex.EncodeToString(expectedH2.Sum(nil)) {
		t.Fatalf("streamed custody: raw=%d size=%d h2=%s", len(rec.Raw), rec.RawSize, rec.PrecomputedH2)
	}
	expectedDecoded := sha256.New()
	if _, err := io.Copy(expectedDecoded, &repeatByteReader{remaining: decodedSize, value: 'a'}); err != nil {
		t.Fatalf("expected decoded hash: %v", err)
	}
	if len(rec.Attachments) != 1 || rec.Attachments[0].ByteCount != decodedSize ||
		rec.Attachments[0].DecodedHash != hex.EncodeToString(expectedDecoded.Sum(nil)) {
		t.Fatalf("attachment manifest: %+v", rec.Attachments)
	}
	info, err := os.Stat(rec.Attachments[0].StoredPath)
	if err != nil || info.Size() != decodedSize {
		t.Fatalf("spooled file size=%v err=%v", info, err)
	}
	if mmsStreamBufferBytes != 128<<10 || decodedSize <= int64(mmsStreamBufferBytes*4) {
		t.Fatalf("test must substantially exceed asserted %d-byte work buffer", mmsStreamBufferBytes)
	}
}

type repeatByteReader struct {
	remaining int64
	value     byte
}

func (r *repeatByteReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	for i := range p {
		p[i] = r.value
	}
	r.remaining -= int64(len(p))
	return len(p), nil
}

func streamBase64Repeat(value byte, size int64) io.Reader {
	reader, writer := io.Pipe()
	go func() {
		encoder := base64.NewEncoder(base64.StdEncoding, writer)
		_, copyErr := io.Copy(encoder, &repeatByteReader{remaining: size, value: value})
		closeErr := encoder.Close()
		if copyErr != nil {
			_ = writer.CloseWithError(copyErr)
			return
		}
		_ = writer.CloseWithError(closeErr)
	}()
	return reader
}

func TestResolveImportArtifactIsUserScopedAndRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	path, err := ResolveImportArtifact(root, 7, "attachments/item.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := filepath.Join(root, "import-7", "attachments", "item.bin")
	if path != want {
		t.Fatalf("path=%q want=%q", path, want)
	}
	for _, unsafe := range []string{"../other-user/item.bin", "/absolute/item.bin", `C:\\outside.bin`} {
		if _, err := ResolveImportArtifact(root, 7, unsafe); err == nil {
			t.Fatalf("unsafe path %q accepted", unsafe)
		}
	}
}

func TestMessagingCSVEmbeddedNewlineRawSpanAndSMSBRDirection(t *testing.T) {
	source := "address,readable_date,type,body,read,contact_name\r\n" +
		`+15550001,"Jan 3, 2024 4:12:09 PM",1,"hello` + "\n" + `there",1,Ex Partner` + "\r\n" +
		`+15550001,"Jan 3, 2024 4:13:09 PM",4,"sent",1,Ex Partner` + "\r\n"
	sink := &captureSink{}
	if err := (messagingCSVImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 2 || sink.rejects != 0 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), sink.rejects)
	}
	first := sink.records[0]
	if first.Content != "hello\nthere" || first.Metadata["direction"] != "inbound" {
		t.Fatalf("first projection: %+v", first)
	}
	if bytes.HasSuffix(first.Raw, []byte("\r\n")) || !bytes.Contains(first.Raw, []byte("hello\nthere")) {
		t.Fatalf("CSV H2 span must retain embedded newline but exclude record terminator: %q", first.Raw)
	}
	if sink.records[1].Metadata["direction"] != "outbound" {
		t.Fatalf("SMSBR type=4 direction: %+v", sink.records[1].Metadata)
	}
}

func TestTranscriptAndIMessageTXTConservativeDetectionAndBlocks(t *testing.T) {
	transcript := "[2024-01-02 9:15 AM] Ex:\r\nhello\r\n[2024-01-02 9:16 AM] Me:\r\nMissed call\r\n"
	if !(transcriptImporter{}).Detect([]byte(transcript), "thread.txt") {
		t.Fatal("transcript signature not detected")
	}
	sink := &captureSink{}
	if err := (transcriptImporter{}).Run(sink, bufio.NewReader(strings.NewReader(transcript))); err != nil {
		t.Fatalf("transcript Run: %v", err)
	}
	if len(sink.records) != 2 || sink.records[0].Content != "hello" || sink.records[1].Kind != KindCall {
		t.Fatalf("transcript records: %+v", sink.records)
	}
	if !bytes.Contains(sink.records[0].Raw, []byte("\r\n")) {
		t.Fatalf("transcript raw span lost CRLF: %q", sink.records[0].Raw)
	}
	if (transcriptImporter{}).Detect([]byte("ordinary note\nwithout markers\n"), "note.txt") {
		t.Fatal("generic text false-positive")
	}

	imessage := "May 17, 2022  5:29:42 PM (Read by you)\nMe\nSee attached\n/Attachments/IMG_1.jpeg\n"
	if !(imessageTXTImporter{}).Detect([]byte(imessage), "thread.txt") {
		t.Fatal("iMessage signature not detected")
	}
	sink = &captureSink{}
	if err := (imessageTXTImporter{}).Run(sink, bufio.NewReader(strings.NewReader(imessage))); err != nil {
		t.Fatalf("iMessage Run: %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].Metadata["direction"] != "outbound" || sink.records[0].Content != "See attached" {
		t.Fatalf("iMessage record: %+v", sink.records)
	}
	refs := sink.records[0].AttachmentReferences
	if len(refs) != 1 || refs[0].URI != "Attachments/IMG_1.jpeg" ||
		refs[0].ResolutionStatus != AttachmentReferenceOnly || !refs[0].SafeRelative {
		t.Fatalf("iMessage references: %#v", refs)
	}
}

func TestHTMLImportersDistinguishFacebookAndIMessage(t *testing.T) {
	facebook := `<html><body><div class="message"><div class="meta">Ex Partner - May 17, 2022, 5:29 PM</div><p>Why are you late</p></div></body></html>`
	if !(facebookHTMLImporter{}).Detect([]byte(facebook), "thread.html") || (imessageHTMLImporter{}).Detect([]byte(facebook), "thread.html") {
		t.Fatal("Facebook/iMessage discriminator failed")
	}
	sink := &captureSink{}
	if err := (facebookHTMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(facebook))); err != nil {
		t.Fatalf("Facebook Run: %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].Content != "Why are you late" || sink.records[0].OccurredAt == nil {
		t.Fatalf("Facebook record: %+v", sink.records)
	}

	imessage := `<html><body><div class="message"><div class="received"><p><span class="timestamp">May 17, 2022  5:29:42 PM</span><span class="sender">Ex</span></p><div class="message_part"><span class="bubble">hello</span></div></div></div></body></html>`
	if !(imessageHTMLImporter{}).Detect([]byte(imessage), "thread.html") || (facebookHTMLImporter{}).Detect([]byte(imessage), "thread.html") {
		t.Fatal("iMessage/Facebook discriminator failed")
	}
	sink = &captureSink{}
	if err := (imessageHTMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(imessage))); err != nil {
		t.Fatalf("iMessage HTML Run: %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].Content != "hello" || sink.records[0].Metadata["direction"] != "inbound" {
		t.Fatalf("iMessage HTML record: %+v", sink.records)
	}
}

func TestOwnerCustomIMessageHTMLKeepsFollowingMetaAndAttachment(t *testing.T) {
	source := `<html><body><div class="bubble from-them">Where is she</div><div class="meta">+18105551234 - 2023-03-04 02:15 PM</div><div class="bubble from-me">See attached</div><div class="meta">Me - 2023-03-04 02:16 PM</div><a class="attachment-link" href="IMG_1.jpeg">IMG_1.jpeg</a></body></html>`
	sink := &captureSink{}
	if err := (imessageHTMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(sink.records) != 2 || sink.records[0].Participants[1] != "+18105551234" || sink.records[1].Metadata["direction"] != "outbound" {
		t.Fatalf("owner records: %+v", sink.records)
	}
	attachments, ok := sink.records[1].Metadata["attachments"].([]map[string]interface{})
	if !ok || len(attachments) != 1 || attachments[0]["uri"] != "IMG_1.jpeg" ||
		attachments[0]["resolution_status"] != AttachmentReferenceOnly {
		t.Fatalf("attachments: %#v", sink.records[1].Metadata["attachments"])
	}
	if refs := sink.records[1].AttachmentReferences; len(refs) != 1 || refs[0].URI != "IMG_1.jpeg" {
		t.Fatalf("structured attachment refs: %#v", refs)
	}
}

func TestAttachmentReferenceSafetyStates(t *testing.T) {
	cases := []struct {
		value, status, uri string
		safe               bool
	}{
		{"../escape.jpg", AttachmentUnsafeReference, "", false},
		{"https://example.invalid/photo.jpg", AttachmentExternalReference, "", false},
		{"Attachment Missing", AttachmentSourceReportedMissing, "", false},
		{"/Attachments/photo.jpg", AttachmentReferenceOnly, "Attachments/photo.jpg", true},
	}
	for _, tc := range cases {
		ref := newIMessageAttachmentReference("file", tc.value, tc.value)
		if ref.ResolutionStatus != tc.status || ref.URI != tc.uri || ref.SafeRelative != tc.safe {
			t.Fatalf("%q => %#v", tc.value, ref)
		}
	}
}

func TestUniversalEngineDurableAccountingCustodyAndImportIsolation(t *testing.T) {
	db := newUniversalTestDB(t)
	defer db.Close()

	line := `{ "body": "one", "occurred_at": "2026-08-02T12:00:00Z" }`
	source := line + "\nnot-json\n" + line + "\n"
	first, err := RunImport(db, strings.NewReader(source), ImportOptions{
		Filename: "first.ndjson", FileHash: HashBytesSHA256([]byte(source)),
		OriginalPath: "retained/first.ndjson",
	})
	if err != nil {
		t.Fatalf("first RunImport: %v", err)
	}
	if first.ImportID == 0 || first.Accepted != 1 || first.Rejected != 1 ||
		first.Deduplicated != 1 || first.Encountered != 3 {
		t.Fatalf("first summary: %+v", first)
	}
	h2 := HashRecordH2([]byte(line))
	rejectedH2 := HashRecordH2([]byte("not-json"))
	if want := ChainH3([]string{h2, rejectedH2, h2}, ""); first.ChainHash != want {
		t.Fatalf("H3=%s want %s", first.ChainHash, want)
	}

	rec, err := GetImport(db, first.ImportID)
	if err != nil {
		t.Fatalf("GetImport: %v", err)
	}
	if rec.ChainCanon != ChainCanonVersionSBV || rec.RecordHashCanon != RecordHashCanonRawV1 ||
		rec.Status != ImportStatusCompleted || rec.Reconciliation != ReconciliationUnverified || rec.RecordCount != 3 {
		t.Fatalf("custody row: %+v", rec)
	}
	rows, err := GetImportRecords(db, first.ImportID, "", "", 100, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("records len=%d err=%v", len(rows), err)
	}
	if rows[0].RecordHash != h2 || rows[0].Status != "accepted" || rows[1].Status != "deduplicated" {
		t.Fatalf("record dispositions: %+v", rows)
	}
	rejects, err := GetImportRejections(db, first.ImportID, 100, 0)
	if err != nil || len(rejects) != 1 || !strings.Contains(rejects[0].Reason, "invalid JSON") ||
		rejects[0].RecordHash != rejectedH2 || rejects[0].RecordHashCanon != RecordHashCanonRawV1 {
		t.Fatalf("rejections=%+v err=%v", rejects, err)
	}

	secondSource := "{\"body\":\"two\"}\n"
	second, err := RunImport(db, strings.NewReader(secondSource), ImportOptions{
		Filename: "second.jsonl", FileHash: HashBytesSHA256([]byte(secondSource)),
	})
	if err != nil {
		t.Fatalf("second RunImport: %v", err)
	}
	if second.ImportID == first.ImportID || second.Accepted != 1 || second.Encountered != 1 {
		t.Fatalf("second summary: %+v", second)
	}
	firstCount, _ := CountImportRecords(db, first.ImportID, "", "")
	secondCount, _ := CountImportRecords(db, second.ImportID, "", "")
	if firstCount != 2 || secondCount != 1 {
		t.Fatalf("import data leaked: first=%d second=%d", firstCount, secondCount)
	}
}

func TestUnsupportedFormatStillCreatesTerminalImportLedgerRow(t *testing.T) {
	db := newUniversalTestDB(t)
	defer db.Close()
	summary, err := RunImport(db, strings.NewReader("opaque"), ImportOptions{
		Filename: "evidence.bin", FileHash: HashBytesSHA256([]byte("opaque")),
	})
	if err == nil || summary == nil || summary.ImportID == 0 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	rec, getErr := GetImport(db, summary.ImportID)
	if getErr != nil || rec.Status != ImportStatusError || rec.Error == "" || rec.FinishedAt == 0 {
		t.Fatalf("failed ledger row=%+v err=%v", rec, getErr)
	}
}

func TestMaxImportBodyBytesValidation(t *testing.T) {
	t.Setenv("SBV_MAX_IMPORT_BYTES", "")
	if got, err := maxImportBodyBytes(); err != nil || got != defaultMaxImportBytes {
		t.Fatalf("default got=%d err=%v", got, err)
	}
	t.Setenv("SBV_MAX_IMPORT_BYTES", "8589934592")
	if got, err := maxImportBodyBytes(); err != nil || got != 8<<30 {
		t.Fatalf("configured got=%d err=%v", got, err)
	}
	for _, invalid := range []string{"0", "-1", "4GiB", "999999999999999999999"} {
		t.Setenv("SBV_MAX_IMPORT_BYTES", invalid)
		if _, err := maxImportBodyBytes(); err == nil {
			t.Fatalf("value %q should fail", invalid)
		}
	}
}

func TestUniversalImportRejectsOversizeMultipartBeforeAuthOrStorage(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", "large.ndjson")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(bytes.Repeat([]byte("x"), 1024)); err != nil {
		t.Fatalf("write multipart: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	t.Setenv("SBV_MAX_IMPORT_BYTES", "128")

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/imports", &body)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := HandleUniversalImport(c); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func newUniversalTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	// ensureCustodyColumns only needs a messages table to support its additive
	// legacy content_hash migration; neutral NDJSON rows never write to it.
	if _, err := db.Exec(`CREATE TABLE messages (id INTEGER PRIMARY KEY, content_hash TEXT)`); err != nil {
		t.Fatalf("create messages: %v", err)
	}
	if err := ensureCustodyColumns(db); err != nil {
		t.Fatalf("ensure custody schema: %v", err)
	}
	return db
}
