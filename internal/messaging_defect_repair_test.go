package internal

// Byline: Claude Code · Opus 5 (1M) · 2026-09-06 — synthetic regression tests for
// the three messaging-decoder defects found by the 2026-09-06 atomic parse test.
// Every fixture here is hand-written structure only: no real message content,
// no real phone numbers, no copied export bytes.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rejectRecord captures what a reject actually carried, which captureSink drops.
type rejectRecord struct {
	pos      string
	reason   string
	raw      []byte
	complete bool
}

type detailSink struct {
	records     []*SourceRecord
	rejects     []rejectRecord
	claimed     int
	artifactDir string
}

func (*detailSink) ImportID() int64                { return 1 }
func (s *detailSink) ArtifactDir() (string, error) { return s.artifactDir, nil }
func (s *detailSink) Claim(n int)                  { s.claimed = n }
func (s *detailSink) Record(rec *SourceRecord) error {
	s.records = append(s.records, rec)
	return nil
}

func (s *detailSink) Reject(pos, reason string, raw []byte, complete bool) error {
	s.rejects = append(s.rejects, rejectRecord{pos: pos, reason: reason, raw: append([]byte(nil), raw...), complete: complete})
	return nil
}

func (s *detailSink) RejectHashed(pos, reason, _, _ string, _ int64) error {
	s.rejects = append(s.rejects, rejectRecord{pos: pos, reason: reason})
	return nil
}

// DEFECT 1a. An unescaped quote inside an attribute value desynchronises
// start-tag scanning. The bad element must produce exactly one reject carrying
// its complete raw span, and the following element must still parse.
func TestSMSXMLMalformedStartElementIsRejectedWholeAndParsingContinues(t *testing.T) {
	const source = `<?xml version="1.0" encoding="UTF-8"?>
<smses count="3">
  <sms protocol="0" address="5550001" date="1700000000000" type="1" body="first" read="1" />
  <sms protocol="0" address="5550002" date="1700000001000" type="2" body="he said "hi" read="1" />
  <sms protocol="0" address="5550003" date="1700000002000" type="1" body="third" read="1" />
</smses>
`
	sink := &detailSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
		t.Fatalf("Run returned an error; one bad record must never abort the file: %v", err)
	}
	if sink.claimed != 3 {
		t.Fatalf("claimed=%d, want the declared count 3", sink.claimed)
	}
	if len(sink.records) != 2 {
		t.Fatalf("parsed=%d, want 2 (first and third)", len(sink.records))
	}
	if len(sink.rejects) != 1 {
		t.Fatalf("rejects=%d, want exactly 1 for the one bad element", len(sink.rejects))
	}
	if parsed, rejected := len(sink.records), len(sink.rejects); parsed+rejected != sink.claimed {
		t.Fatalf("parsed+rejected=%d does not reconcile with declared count %d", parsed+rejected, sink.claimed)
	}
	bad := sink.rejects[0]
	if !bad.complete {
		t.Fatal("reject was not marked as carrying complete raw bytes")
	}
	if !strings.Contains(bad.reason, "malformed_start_element") {
		t.Fatalf("reject reason %q does not name malformed_start_element", bad.reason)
	}
	if !strings.Contains(bad.reason, "bytes ") {
		t.Fatalf("reject reason %q does not carry a byte range", bad.reason)
	}
	rawSpan := string(bad.raw)
	if !strings.HasPrefix(rawSpan, "<sms ") {
		t.Fatalf("reject span does not start at the element: %q", rawSpan)
	}
	if !strings.Contains(rawSpan, "5550002") {
		t.Fatalf("reject span does not contain the bad element's own bytes: %q", rawSpan)
	}
	if strings.Contains(rawSpan, "5550003") {
		t.Fatalf("reject span swallowed the following good element: %q", rawSpan)
	}
	// The third element must be the second parsed record, unharmed.
	third := sink.records[1]
	if !strings.Contains(string(third.Raw), "5550003") {
		t.Fatalf("third element was not parsed; got raw %q", string(third.Raw))
	}
	if !strings.Contains(third.Content, "third") {
		t.Fatalf("third element content = %q, want the body preserved", third.Content)
	}
}

// DEFECT 1b. An <mms> element that cannot be projected must be rejected with
// its complete raw span rather than a nil one. A nil span makes the
// parse-only sink refuse the reject, which aborted the whole 1.3 GB file after
// the last <sms> and before the first <mms>.
func TestSMSXMLMalformedMMSRejectsCompleteSpanAndContinues(t *testing.T) {
	const source = `<?xml version="1.0" encoding="UTF-8"?>
<smses count="2">
  <mms date="not-a-number" msg_box="1" address="5550002">
    <parts><part seq="0" ct="text/plain" text="body" /></parts>
  </mms>
  <sms protocol="0" address="5550003" date="1700000002000" type="1" body="after" read="1" />
</smses>
`
	sink := &detailSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
		t.Fatalf("Run returned an error; a bad MMS must not abort the file: %v", err)
	}
	if len(sink.rejects) != 1 {
		t.Fatalf("rejects=%d, want exactly 1", len(sink.rejects))
	}
	bad := sink.rejects[0]
	if !bad.complete || len(bad.raw) == 0 {
		t.Fatalf("MMS reject must carry complete raw bytes; complete=%v len=%d", bad.complete, len(bad.raw))
	}
	if !strings.HasPrefix(string(bad.raw), "<mms ") || !strings.HasSuffix(string(bad.raw), "</mms>") {
		t.Fatalf("MMS reject span is not the whole element: %q", string(bad.raw))
	}
	if len(sink.records) != 1 {
		t.Fatalf("parsed=%d, want the following <sms> to still parse", len(sink.records))
	}
	if !strings.Contains(string(sink.records[0].Raw), "5550003") {
		t.Fatalf("record after the bad MMS is wrong: %q", string(sink.records[0].Raw))
	}
}

// DEFECT 2. Each bubble is wrapped in an unclassed <div>. Flush must fire on
// every new bubble, not only on bubbles that happen to sit at depth 0.
func TestIMessageHTMLWrappedBubblesProduceOneRecordEach(t *testing.T) {
	// Structure only: every bubble+meta pair sits inside an outer <div> that
	// carries a style attribute and no class, so no bubble is ever at depth 0.
	const source = `<html><body><div class='message-container'>` +
		`<div style='text-align: left;'><div class='bubble from-them'>alpha text</div>` +
		`<div class='meta'>Sender One - 2025-01-01 10:00 AM</div></div>` +
		`<div style='text-align: left;'><div class='bubble from-them'>bravo text</div>` +
		`<div class='meta'>Sender Two - 2025-01-01 10:05 AM</div></div>` +
		`<div style='text-align: left;'><div class='bubble from-them'>charlie text</div>` +
		`<div class='meta'>Sender One - 2025-01-01 10:10 AM</div></div>` +
		`</div></body></html>`
	sink := &detailSink{artifactDir: t.TempDir()}
	if err := runHTMLRecords(sink, strings.NewReader(source), "imessage"); err != nil {
		t.Fatalf("runHTMLRecords: %v", err)
	}
	if len(sink.rejects) != 0 {
		t.Fatalf("rejects=%d, want 0: %+v", len(sink.rejects), sink.rejects)
	}
	if len(sink.records) != 3 {
		t.Fatalf("records=%d, want 3 (one per wrapped bubble)", len(sink.records))
	}
	wantText := []string{"alpha text", "bravo text", "charlie text"}
	for i, want := range wantText {
		if !strings.Contains(sink.records[i].Content, want) {
			t.Fatalf("record %d content = %q, want it to contain %q", i, sink.records[i].Content, want)
		}
		for _, other := range wantText {
			if other == want {
				continue
			}
			if strings.Contains(sink.records[i].Content, other) {
				t.Fatalf("record %d absorbed a later bubble: %q", i, sink.records[i].Content)
			}
		}
	}
	if sink.records[0].OccurredAt == nil {
		t.Fatal("first record has no timestamp; the lingering meta sibling was not captured")
	}
	if sink.records[0].Sender == sink.records[1].Sender {
		t.Fatalf("senders were blended: %q / %q", sink.records[0].Sender, sink.records[1].Sender)
	}
}

func TestSMSXMLRejectOffsetsAfterSuccessfulMMS(t *testing.T) {
	const good = `<mms date="1700000000" msg_box="1" address="5550001"><parts><part seq="0" ct="text/plain" text="ok" /></parts></mms>`
	const bad = `<sms body="unterminated`
	source := `<smses>` + good + bad + `</smses>`
	sink := &detailSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	if len(sink.records) != 1 || len(sink.rejects) != 1 {
		t.Fatalf("records=%d rejects=%d", len(sink.records), len(sink.rejects))
	}
	rejected := sink.rejects[0]
	want := fmt.Sprintf("bytes %d-%d", len(`<smses>`)+len(good), len(`<smses>`)+len(good)+len(bad))
	if !strings.Contains(rejected.reason, want) || string(rejected.raw) != bad || !rejected.complete {
		t.Fatalf("wrong reject: %+v; want %s", rejected, want)
	}
}

func TestSMSXMLTruncatedMMSRetainsBufferedRawBytes(t *testing.T) {
	const bad = `<mms date="1700000000"><parts><part text="unfinished`
	sink := &detailSink{artifactDir: t.TempDir()}
	if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(`<smses>`+bad))); err != nil {
		t.Fatal(err)
	}
	if len(sink.rejects) != 1 {
		t.Fatalf("rejects=%d", len(sink.rejects))
	}
	if got := sink.rejects[0]; string(got.raw) != bad || !got.complete {
		t.Fatalf("source span lost: %+v", got)
	}
}

func TestMMSRejectedSpanReadIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "span.xml")
	if err := os.WriteFile(path, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	span := &mmsSpan{path: path}
	raw, complete := span.readBytes(4)
	if string(raw) != "0123" || complete {
		t.Fatalf("raw=%q complete=%v", raw, complete)
	}
}

func TestMalformedXMLResyncRetainsBoundedSpan(t *testing.T) {
	seed := make([]byte, maxRawRecordBytes)
	offset := int64(len(seed))
	reader := bufio.NewReader(strings.NewReader("tail<sms body='ok'/>"))
	raw, name, prefix, err := resyncMalformedSpan(reader, seed, &offset)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if len(raw) != maxRawRecordBytes || name != "sms" || string(prefix) != "<sms " || offset != int64(maxRawRecordBytes+9) {
		t.Fatalf("len=%d name=%s prefix=%q offset=%d", len(raw), name, prefix, offset)
	}
}

func TestSMSXMLMalformedMMSDoesNotConsumeNextRecord(t *testing.T) {
	for _, bad := range []string{`<mms date="unterminated`, `<mms date="1700000000"><parts></parts>`} {
		source := `<smses>` + bad + `<sms address="5550003" date="1700000002000" type="1" body="after" /></smses>`
		sink := &detailSink{artifactDir: t.TempDir()}
		if err := (smsXMLImporter{}).Run(sink, bufio.NewReader(strings.NewReader(source))); err != nil {
			t.Fatal(err)
		}
		if len(sink.records) != 1 || len(sink.rejects) != 1 {
			t.Fatalf("records=%d rejects=%d", len(sink.records), len(sink.rejects))
		}
		if got := sink.rejects[0]; string(got.raw) != bad || !got.complete {
			t.Fatalf("bad reject: %+v", got)
		}
	}
}
