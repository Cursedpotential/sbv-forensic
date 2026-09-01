package internal

// custody_test.go — forensic hashing guarantees for the SBV forensic fork.
//
// These prove the court-evidence properties the Python custody gate relies on:
//   * H1 == plain sha256 of raw file bytes (byte-identical to custody.py).
//   * H2 == sha256 of the RAW source XML element bytes, computed on the raw
//     bytes and NOT on anything the normalizer would canonicalize.
//   * H3 == a deterministic, order-sensitive chain over the ordered H2s.
//   * The streaming parser stores each record's H2 in content_hash and writes
//     one imports row (H1 file_hash + H3 chain_hash + record_count).

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
)

// --- H1 -----------------------------------------------------------------------

func TestHashFileH1_KnownFixture(t *testing.T) {
	// Known-answer test: sha256("abc") is a fixed, widely published vector.
	const knownABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	tmp, err := os.CreateTemp("", "h1-abc-*.bin")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("abc"); err != nil {
		t.Fatalf("write: %v", err)
	}
	tmp.Close()

	got, err := HashFileH1(tmp.Name())
	if err != nil {
		t.Fatalf("HashFileH1: %v", err)
	}
	if got != knownABC {
		t.Fatalf("H1 mismatch:\n got  %s\n want %s", got, knownABC)
	}
}

func TestHashFileH1_MatchesRawByteSha256(t *testing.T) {
	// H1 must equal a plain sha256 over the exact raw bytes — the same thing
	// custody.py::_sha256_file computes — for arbitrary content.
	content := []byte("hello evidence\x00\x01\x02 binary + text \xff")
	tmp, err := os.CreateTemp("", "h1-raw-*.bin")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		t.Fatalf("write: %v", err)
	}
	tmp.Close()

	got, err := HashFileH1(tmp.Name())
	if err != nil {
		t.Fatalf("HashFileH1: %v", err)
	}
	sum := sha256.Sum256(content)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("H1 not a raw-byte sha256:\n got  %s\n want %s", got, want)
	}
}

func TestHashReaderH1HashesCurrentDescriptorAndCanBeRewound(t *testing.T) {
	r := strings.NewReader("abc")
	got, err := HashReaderH1(r)
	if err != nil {
		t.Fatalf("HashReaderH1: %v", err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("H1=%s want %s", got, want)
	}
	if _, err := r.Seek(0, 0); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "abc" {
		t.Fatalf("post-rewind read=%q err=%v", b, err)
	}
}

// --- H2 -----------------------------------------------------------------------

func TestHashRecordH2_IsSha256OfRawElement(t *testing.T) {
	raw := []byte(`<sms address="5551234567" date="1500000000000" type="2" body="hi there" read="1" />`)
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	if got := HashRecordH2(raw); got != want {
		t.Fatalf("H2 is not sha256 of the raw element:\n got  %s\n want %s", got, want)
	}
}

func TestHashRecordH2_Deterministic(t *testing.T) {
	raw := []byte(`<call number="5551234567" duration="0" date="1500000000000" type="5" />`)
	a := HashRecordH2(raw)
	b := HashRecordH2(append([]byte{}, raw...))
	if a != b {
		t.Fatalf("H2 not deterministic: %s != %s", a, b)
	}
}

// TestHashRecordH2_RawNotNormalized is the load-bearing forensic test: two <sms>
// elements that our parser would NORMALIZE to the identical record (same phone
// number after normalizePhoneNumber, same body) still produce DIFFERENT H2s,
// because H2 hashes the RAW source bytes — not the normalized form.
func TestHashRecordH2_RawNotNormalized(t *testing.T) {
	rawA := []byte(`<sms address="5551234567" date="1500000000000" type="2" body="hi" read="1" />`)
	rawB := []byte(`<sms address="555-123-4567" date="1500000000000" type="2" body="hi" read="1" />`)

	// Sanity: our normalizer collapses both raw addresses to the same value...
	if normalizePhoneNumber("5551234567") != normalizePhoneNumber("555-123-4567") {
		t.Fatalf("test premise broken: the two addresses do not normalize equal")
	}
	// ...yet the RAW-element H2s MUST differ (proving H2 is over raw, not normalized).
	if HashRecordH2(rawA) == HashRecordH2(rawB) {
		t.Fatalf("H2 collapsed two raw variants — it is hashing normalized data, not raw")
	}

	// Whitespace the normalizer would strip must also change the raw H2.
	rawC := []byte(`<sms address="5551234567"  date="1500000000000" type="2" body="hi" read="1" />`)
	if HashRecordH2(rawA) == HashRecordH2(rawC) {
		t.Fatalf("H2 ignored raw whitespace — it is not hashing the raw bytes")
	}
}

// --- H3 -----------------------------------------------------------------------

func TestChainH3_DeterministicAndReproducible(t *testing.T) {
	h2s := []string{
		HashRecordH2([]byte(`<sms body="a" />`)),
		HashRecordH2([]byte(`<sms body="b" />`)),
		HashRecordH2([]byte(`<sms body="c" />`)),
	}
	first := ChainH3(h2s, "")
	second := ChainH3(h2s, "")
	if first != second {
		t.Fatalf("H3 not deterministic: %s != %s", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("H3 is not a sha256 hex digest (len %d): %s", len(first), first)
	}

	// Independent re-derivation of the documented left fold.
	want := ""
	for _, h2 := range h2s {
		s := sha256.Sum256([]byte(want + "\n" + h2))
		want = hex.EncodeToString(s[:])
	}
	if first != want {
		t.Fatalf("H3 does not match its documented construction:\n got  %s\n want %s", first, want)
	}
}

func TestChainH3_OrderSensitiveAndEmpty(t *testing.T) {
	a := HashRecordH2([]byte(`<sms body="a" />`))
	b := HashRecordH2([]byte(`<sms body="b" />`))
	if ChainH3([]string{a, b}, "") == ChainH3([]string{b, a}, "") {
		t.Fatalf("H3 must be order-sensitive")
	}
	// A batch with no records folds to the prevChain (empty for a fresh batch).
	if got := ChainH3(nil, ""); got != "" {
		t.Fatalf("empty batch H3 should be the empty prevChain, got %q", got)
	}
}

// --- rawCaptureReader ----------------------------------------------------------

func TestRawCaptureReader_SliceAndDiscard(t *testing.T) {
	src := "0123456789ABCDEF"
	cr := newRawCaptureReader(strings.NewReader(src))
	buf := make([]byte, 4)
	// Drain the reader fully (mimics the decoder pulling bytes).
	for {
		if _, err := cr.Read(buf); err != nil {
			break
		}
	}
	if got := string(cr.slice(2, 6)); got != "2345" {
		t.Fatalf("slice(2,6) = %q, want %q", got, "2345")
	}
	cr.discardBefore(6)
	if got := string(cr.slice(6, 10)); got != "6789" {
		t.Fatalf("slice(6,10) after discard = %q, want %q", got, "6789")
	}
	// Bytes before the discard point are no longer retrievable.
	if cr.slice(2, 6) != nil {
		t.Fatalf("slice below discard base should be nil")
	}
}

// --- end-to-end streaming (DB-backed) -----------------------------------------

// TestParseSMSBackupStreaming_CustodyHashes runs the full streaming path and
// asserts: (1) each stored content_hash equals the sha256 of that record's RAW
// element bytes, and (2) the imports row carries the passed H1 plus the H3 chain
// folded over the ordered H2s. Requires the CGO sqlite build (-tags "fts5 heic").
func TestParseSMSBackupStreaming_CustodyHashes(t *testing.T) {
	tmpDB := t.TempDir() + "/custody_test.db"
	if err := InitDB(tmpDB); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer db.Close()

	// Two records with exactly-known raw element bytes (built by concatenation so
	// the test knows the precise bytes the parser will hash).
	smsElem := `<sms address="5551234567" date="1500000000000" type="2" body="hi there" read="1" />`
	callElem := `<call number="5559998888" duration="0" date="1500000100000" type="5" />`
	doc := "<?xml version='1.0' encoding='UTF-8'?>\n<smses count=\"2\">\n" +
		smsElem + "\n" + callElem + "\n</smses>"

	const h1 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef01"
	msgCount, callCount, err := ParseSMSBackupStreaming(db, strings.NewReader(doc), 1, h1)
	if err != nil {
		t.Fatalf("ParseSMSBackupStreaming: %v", err)
	}
	if msgCount != 1 || callCount != 1 {
		t.Fatalf("expected 1 message + 1 call, got %d + %d", msgCount, callCount)
	}

	wantSMSH2 := HashRecordH2([]byte(smsElem))
	wantCallH2 := HashRecordH2([]byte(callElem))

	// content_hash on the stored SMS row (address normalized to +1…).
	msgs, err := GetMessages(db, normalizePhoneNumber("5551234567"), nil, nil)
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 stored message, got %d", len(msgs))
	}
	if msgs[0].ContentHash != wantSMSH2 {
		t.Fatalf("SMS content_hash mismatch:\n got  %s\n want %s (sha256 of raw element)",
			msgs[0].ContentHash, wantSMSH2)
	}

	// content_hash on the stored call row.
	calls, err := GetAllCalls(db, nil, nil, 100, 0)
	if err != nil {
		t.Fatalf("GetAllCalls: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 stored call, got %d", len(calls))
	}
	if calls[0].ContentHash != wantCallH2 {
		t.Fatalf("call content_hash mismatch:\n got  %s\n want %s", calls[0].ContentHash, wantCallH2)
	}

	// imports row: H1 carried through, H3 == chain over the ordered H2s, count == 2.
	imp, err := GetLatestImport(db)
	if err != nil {
		t.Fatalf("GetLatestImport: %v", err)
	}
	if imp.FileHash != h1 {
		t.Fatalf("imports.file_hash (H1) = %s, want %s", imp.FileHash, h1)
	}
	if imp.RecordCount != 2 {
		t.Fatalf("imports.record_count = %d, want 2", imp.RecordCount)
	}
	wantChain := ChainH3([]string{wantSMSH2, wantCallH2}, "")
	if imp.ChainHash != wantChain {
		t.Fatalf("imports.chain_hash (H3) mismatch:\n got  %s\n want %s", imp.ChainHash, wantChain)
	}
}
