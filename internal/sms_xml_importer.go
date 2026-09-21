package internal

// Byline amendment: Codex · GPT-5 · 2026-08-18 (combined-change hygiene).

// sms_xml_importer.go adapts the existing, battle-tested SMS Backup & Restore
// conversions to the universal engine. Legacy message/call projections keep the
// original viewer working, while every raw element also lands in the
// import-scoped canonical store with durable disposition accounting.

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type smsXMLImporter struct{}

// mmsStreamBufferBytes is the largest explicit work buffer used while
// transferring an inline base64 MMS part. The source reader has its own 64 KiB
// buffer; neither buffer grows with the attachment or source-file size.
const mmsStreamBufferBytes = 128 << 10

func (smsXMLImporter) Format() string { return FormatSMSBackupXML }
func (smsXMLImporter) Priority() int  { return 900 }

func (smsXMLImporter) Detect(head []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	text := strings.ToLower(string(head))
	return ext == ".xml" && (strings.Contains(text, "<smses") || strings.Contains(text, "<calls"))
}

func (smsXMLImporter) Run(sink ImportSink, r *bufio.Reader) error {
	if head, _ := r.Peek(detectPeekBytes); len(head) > 0 {
		if match := xmlCountRE.FindSubmatch(head); len(match) == 2 {
			if n, err := strconv.Atoi(string(match[1])); err == nil {
				sink.Claim(n)
			}
		}
	}
	recordNo := 0
	var offset int64
	// pendingName/pendingPrefix carry a record boundary that a resync already
	// consumed, so no element is lost while recovering from a malformed span.
	pendingName := ""
	var pendingPrefix []byte
	for {
		var (
			name   string
			prefix []byte
			err    error
		)
		if pendingName != "" {
			name, prefix = pendingName, pendingPrefix
			pendingName, pendingPrefix = "", nil
		} else {
			name, prefix, err = nextXMLRecordStart(r, &offset)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
		elementStart := offset - int64(len(prefix))
		recordNo++
		pos := fmt.Sprintf("element:%d", recordNo)
		if name == "mms" {
			rec, span, err := streamMMSRecord(sink, r, prefix, pos)
			if err != nil {
				if span == nil {
					// No source bytes were consumed: the artifact staging area
					// is unavailable, which is an environment failure and must
					// not masquerade as a malformed record.
					return fmt.Errorf("MMS record at %s cannot be staged (artifact sink unavailable): %w", pos, err)
				}
				offset += span.consumed() - int64(len(prefix))
				raw, complete := span.readBytes(maxRawRecordBytes)
				reason := fmt.Sprintf("malformed_mms_record: %s (bytes %d-%d)",
					err.Error(), elementStart, elementStart+span.consumed())
				if !span.complete {
					tail, nextName, nextPrefix, resyncErr := resyncMalformedSpan(r, nil, &offset)
					available := maxRawRecordBytes - len(raw)
					if len(tail) > available {
						tail = tail[:available]
					}
					raw = append(raw, tail...)
					end := offset - int64(len(nextPrefix))
					complete = complete && int64(len(raw)) == end-elementStart
					reason = fmt.Sprintf("malformed_mms_record: %s (bytes %d-%d, resynced)",
						err.Error(), elementStart, end)
					if rejectErr := sink.Reject(pos, reason, raw, complete); rejectErr != nil {
						return rejectErr
					}
					if resyncErr == io.EOF {
						return nil
					}
					if resyncErr != nil {
						return resyncErr
					}
					pendingName, pendingPrefix = nextName, nextPrefix
					continue
				}
				if rejectErr := sink.Reject(pos, reason, raw, complete); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			offset += span.consumed() - int64(len(prefix))
			if err := sink.Record(rec); err != nil {
				return err
			}
			continue
		}
		raw, tooLong, err := readXMLStartElement(r, prefix, maxStartElementBytes, &offset)
		if err != nil && err != io.EOF {
			return err
		}
		if tooLong || err == io.EOF {
			// The start tag never terminated inside its bound (an unescaped
			// quote desynchronises attribute scanning). Recover the whole bad
			// span, emit exactly one reject for it, and continue the file.
			span, nextName, nextPrefix, resyncErr := resyncMalformedSpan(r, raw, &offset)
			reason := fmt.Sprintf("malformed_start_element: <%s> start tag did not terminate (unescaped quote desynchronises attribute scanning); bytes %d-%d",
				name, elementStart, offset-int64(len(nextPrefix)))
			complete := int64(len(span)) == offset-int64(len(nextPrefix))-elementStart
			if rejectErr := sink.Reject(pos, reason, span, complete); rejectErr != nil {
				return rejectErr
			}
			if resyncErr == io.EOF {
				return nil
			}
			if resyncErr != nil {
				return resyncErr
			}
			if nextName == "" {
				continue
			}
			pendingName, pendingPrefix = nextName, nextPrefix
			continue
		}
		switch name {
		case "sms":
			var entry SMSEntry
			if err := xml.Unmarshal(raw, &entry); err != nil {
				if rejectErr := sink.Reject(pos, "decode SMS: "+err.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			msg, err := convertSMSEntry(entry)
			if err != nil {
				if rejectErr := sink.Reject(pos, "convert SMS: "+err.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			if err := sink.Record(messageSourceRecord(raw, pos, &msg, entry)); err != nil {
				return err
			}
		case "call":
			var entry CallEntry
			if err := xml.Unmarshal(raw, &entry); err != nil {
				if rejectErr := sink.Reject(pos, "decode call: "+err.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			call, err := convertCallEntry(entry)
			if err != nil {
				if rejectErr := sink.Reject(pos, "convert call: "+err.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			if err := sink.Record(callSourceRecord(raw, pos, &call, entry)); err != nil {
				return err
			}
		}
	}
}

var xmlCountRE = regexp.MustCompile(`(?i)<(?:smses|calls)[^>]*\bcount=["']([0-9]+)["']`)

func nextXMLRecordStart(r *bufio.Reader, offset *int64) (string, []byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", nil, err
		}
		*offset++
		if b != '<' {
			continue
		}
		prefix := []byte{'<'}
		for len(prefix) < 16 {
			b, err = r.ReadByte()
			if err != nil {
				return "", nil, err
			}
			*offset++
			prefix = append(prefix, b)
			if b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '>' || b == '/' {
				break
			}
		}
		name := strings.ToLower(strings.Trim(string(prefix[1:]), " \t\r\n>/"))
		if name == "sms" || name == "mms" || name == "call" {
			return name, prefix, nil
		}
	}
}

// readXMLStartElement reads one start tag, reporting malformed=true instead of
// running away when the tag cannot be scanned. Two bounds apply:
//
//   - a '<' can never appear inside a well-formed start tag (XML requires
//     &lt;), so meeting one means attribute-quote tracking has desynchronised
//     on an unescaped quote. The '<' is left unread so the caller resyncs on it.
//   - limit bytes, as a backstop for a desync with no following '<'.
//
// Everything consumed so far is returned either way, so the caller can emit one
// reject covering a contiguous, complete malformed span.
func readXMLStartElement(r *bufio.Reader, prefix []byte, limit int, offset *int64) ([]byte, bool, error) {
	raw := append([]byte(nil), prefix...)
	if len(raw) > 0 && raw[len(raw)-1] == '>' {
		return raw, false, nil
	}
	var quote byte
	for {
		if len(raw) >= limit {
			return raw, true, nil
		}
		peek, err := r.Peek(1)
		if err != nil {
			return raw, false, err
		}
		if peek[0] == '<' {
			return raw, true, nil
		}
		b, err := r.ReadByte()
		if err != nil {
			return raw, false, err
		}
		*offset++
		raw = append(raw, b)
		if quote != 0 {
			if b == quote {
				quote = 0
			}
			continue
		}
		if b == '\'' || b == '"' {
			quote = b
		} else if b == '>' {
			return raw, false, nil
		}
	}
}

// xmlRecordBoundary reports the record element name a '<' begins, if any.
func xmlRecordBoundary(peek []byte) (string, int) {
	lower := strings.ToLower(string(peek))
	end := strings.IndexAny(lower, " \t\r\n>/")
	if end <= 0 {
		return "", 0
	}
	switch lower[:end] {
	case "sms", "mms", "call":
		return lower[:end], end
	}
	return "", 0
}

// resyncMalformedSpan consumes bytes from a malformed region until the next
// record boundary (<sms/<mms/<call) or container close (</smses>, </calls>).
// It retains at most maxRawRecordBytes plus the next boundary. Callers compare
// the retained length with the consumed offsets before claiming a complete span.
func resyncMalformedSpan(r *bufio.Reader, seed []byte, offset *int64) ([]byte, string, []byte, error) {
	span := append([]byte(nil), seed...)
	for {
		first, err := r.Peek(1)
		if err != nil {
			return span, "", nil, err
		}
		if first[0] == '<' {
			peek, _ := r.Peek(17)
			if name, end := xmlRecordBoundary(peek[1:]); name != "" {
				prefix := append([]byte(nil), peek[:end+2]...)
				if _, err := r.Discard(len(prefix)); err != nil {
					return span, "", nil, err
				}
				*offset += int64(len(prefix))
				return span, name, prefix, nil
			}
			lower := strings.ToLower(string(peek[1:]))
			if strings.HasPrefix(lower, "/smses") || strings.HasPrefix(lower, "/calls") {
				return span, "", nil, nil
			}
		}
		b, err := r.ReadByte()
		if err != nil {
			return span, "", nil, err
		}
		*offset++
		if len(span) < maxRawRecordBytes {
			span = append(span, b)
		}
	}
}

type streamedAttachment struct {
	path      string
	hash      string
	bytes     int64
	status    string
	decodeErr string
	marker    string
}

// streamMMSRecord hashes the exact raw <mms> span while producing a small
// sanitized XML spool. Inline base64 data attributes are decoded directly to
// files and replaced by marker strings in the spool, so neither the encoded nor
// decoded attachment is ever materialized as one []byte/string.
func streamMMSRecord(sink ImportSink, r *bufio.Reader, prefix []byte, pos string) (*SourceRecord, *mmsSpan, error) {
	span := &mmsSpan{}
	rec, err := streamMMSRecordInto(sink, r, prefix, pos, span)
	if err != nil {
		span.seal()
		if span.path == "" {
			// Nothing was consumed from the reader: this is a staging/sink
			// failure, not a defect in the source record.
			return nil, nil, err
		}
		return nil, span, err
	}
	return rec, span, nil
}

// mmsSpan retains the exact bytes an <mms> element consumed so a failed record
// can still be rejected with its complete raw span instead of a nil one.
type mmsSpan struct {
	spool    *os.File
	buffered *bufio.Writer
	path     string
	size     *int64
	complete bool
	sealed   bool
}

func (s *mmsSpan) seal() {
	if s == nil || s.sealed {
		return
	}
	s.sealed = true
	if s.buffered != nil {
		_ = s.buffered.Flush()
	}
	if s.spool != nil {
		_ = s.spool.Sync()
		_ = s.spool.Close()
	}
}

// readBytes returns the consumed span, reporting whether it is the whole span.
func (s *mmsSpan) readBytes(limit int) ([]byte, bool) {
	if s == nil || s.path == "" {
		return nil, false
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, false
	}
	if len(data) > limit {
		return data[:limit], false
	}
	return data, true
}

func (s *mmsSpan) consumed() int64 {
	if s == nil || s.size == nil {
		return 0
	}
	return *s.size
}

func streamMMSRecordInto(sink ImportSink, r *bufio.Reader, prefix []byte, pos string, span *mmsSpan) (*SourceRecord, error) {
	root, err := sink.ArtifactDir()
	if err != nil {
		return nil, err
	}
	attachmentDir := filepath.Join(root, "attachments")
	if err := os.MkdirAll(attachmentDir, 0700); err != nil {
		return nil, err
	}
	sanitized, err := os.CreateTemp(root, "mms-sanitized-*.xml")
	if err != nil {
		return nil, err
	}
	defer sanitized.Close()
	rawSpool, err := os.CreateTemp(root, "mms-raw-*.xml")
	if err != nil {
		return nil, err
	}
	defer rawSpool.Close()
	rawBuffered := bufio.NewWriterSize(rawSpool, mmsStreamBufferBytes)
	h := sha256.New()
	var rawSize int64
	span.spool = rawSpool
	span.buffered = rawBuffered
	span.path = rawSpool.Name()
	span.size = &rawSize
	// Flush retained source bytes before the deferred raw-spool close, including
	// when malformed input interrupts streaming.
	defer span.seal()
	writeRaw := func(data []byte) error {
		if _, err := h.Write(data); err != nil {
			return err
		}
		n, err := rawBuffered.Write(data)
		rawSize += int64(n)
		if err != nil {
			return err
		}
		if n != len(data) {
			return io.ErrShortWrite
		}
		return nil
	}
	writeBoth := func(data []byte) error {
		if err := writeRaw(data); err != nil {
			return err
		}
		_, err := sanitized.Write(data)
		return err
	}
	if err := writeBoth(prefix); err != nil {
		return nil, err
	}

	inTag := true
	var quote byte
	drafts := make([]streamedAttachment, 0)
	for {
		// Leave a following record boundary unread when the current MMS is
		// malformed, so recovery cannot absorb a subsequent good record.
		if peek, _ := r.Peek(1); len(peek) > 0 && peek[0] == '<' {
			if inTag {
				return nil, fmt.Errorf("malformed MMS start tag")
			}
			boundary, _ := r.Peek(17)
			if name, _ := xmlRecordBoundary(boundary[1:]); name != "" {
				return nil, fmt.Errorf("unterminated MMS before next record")
			}
		}
		b, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("unterminated MMS record: %w", err)
		}
		if !inTag && b == '<' {
			if closing, _ := r.Peek(5); string(closing) == "/mms>" {
				_, _ = r.Discard(5)
				if err := writeBoth([]byte("</mms>")); err != nil {
					return nil, err
				}
				span.complete = true
				break
			}
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			inTag = true
			continue
		}
		if !inTag {
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			continue
		}
		if quote != 0 {
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			if b == quote {
				quote = 0
			}
			continue
		}
		if b == '>' {
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			inTag = false
			continue
		}
		if b == '\'' || b == '"' {
			quote = b
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			continue
		}
		if isXMLSpace(b) {
			if err := writeBoth([]byte{b}); err != nil {
				return nil, err
			}
			candidate, _ := r.Peek(len("data"))
			if string(candidate) != "data" {
				continue
			}
			draft, captured, err := captureMMSDataAttribute(r, writeBoth, writeRaw, sanitized, h, rawBuffered, &rawSize, attachmentDir, len(drafts))
			if err != nil {
				return nil, err
			}
			if captured {
				drafts = append(drafts, draft)
			}
			continue
		}
		if err := writeBoth([]byte{b}); err != nil {
			return nil, err
		}
	}
	if err := sanitized.Sync(); err != nil {
		return nil, err
	}
	if err := rawBuffered.Flush(); err != nil {
		return nil, err
	}
	if err := rawSpool.Sync(); err != nil {
		return nil, err
	}
	if err := rawSpool.Close(); err != nil {
		return nil, err
	}
	if _, err := sanitized.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var entry MMSEntry
	if err := xml.NewDecoder(sanitized).Decode(&entry); err != nil {
		return nil, fmt.Errorf("decode sanitized MMS: %w", err)
	}
	attachments := make([]AttachmentArtifact, 0, len(drafts))
	// A part that names a payload but carries no bytes (data="" in real exports,
	// or no data attribute) is a gap in THIS backup, not a zero-byte attachment.
	// It becomes a source-reported-missing reference so the missing-payload check
	// can record it against the message (owner requirement 2026-09-20).
	var withoutPayload []AttachmentReference
	associated := 0
	matchedDrafts := make([]bool, len(drafts))
	for partIndex := range entry.Parts {
		part := &entry.Parts[partIndex]
		matchedPart := false
		for draftIndex := range drafts {
			draft := &drafts[draftIndex]
			if part.Data != draft.marker {
				continue
			}
			if matchedDrafts[draftIndex] {
				return nil, fmt.Errorf("MMS attachment marker %d appeared more than once", draftIndex)
			}
			if draft.bytes == 0 && draft.decodeErr == "" && mmsPartExpectsPayload(*part) {
				if err := os.Remove(draft.path); err != nil && !os.IsNotExist(err) {
					return nil, err
				}
				withoutPayload = append(withoutPayload, mmsPartWithoutPayloadReference(*part))
				matchedDrafts[draftIndex] = true
				matchedPart = true
				associated++
				part.Data = ""
				break
			}
			name := sanitizedAttachmentName(part.Name, part.CL, draftIndex)
			// part sequence repeats for every MMS, so include the source position;
			// otherwise two records named image.jpg could overwrite each other.
			finalPath := filepath.Join(attachmentDir, fmt.Sprintf("%s-%03d-%s",
				sanitizedAttachmentName(pos), draftIndex, name))
			if err := os.Rename(draft.path, finalPath); err != nil {
				return nil, err
			}
			draft.path = finalPath
			attachments = append(attachments, AttachmentArtifact{
				OriginalName: name, MIME: part.ContentType, DecodedHash: draft.hash,
				ByteCount: draft.bytes, StoredPath: finalPath,
				ConversionStatus: draft.status, ConversionError: draft.decodeErr,
			})
			matchedDrafts[draftIndex] = true
			matchedPart = true
			associated++
			part.Data = ""
			break
		}
		if !matchedPart && strings.TrimSpace(part.Data) != "" {
			return nil, fmt.Errorf("MMS inline data escaped lossless capture at part %d", partIndex)
		}
		if !matchedPart && mmsPartExpectsPayload(*part) {
			withoutPayload = append(withoutPayload, mmsPartWithoutPayloadReference(*part))
		}
	}
	if associated != len(drafts) {
		return nil, fmt.Errorf("MMS captured %d inline payloads but associated %d parts", len(drafts), associated)
	}
	msg, err := convertMMSEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("convert MMS: %w", err)
	}
	if len(attachments) > 0 && msg.MediaType == "" {
		msg.MediaType = attachments[0].MIME
	}
	rec := messageSourceRecord(nil, pos, &msg, entry)
	rec.RawPath = rawSpool.Name()
	rec.PrecomputedH2 = hex.EncodeToString(h.Sum(nil))
	rec.RawSize = rawSize
	rec.Attachments = attachments
	rec.AttachmentReferences = append(rec.AttachmentReferences, withoutPayload...)
	return rec, nil
}

const mmsPartWithoutPayloadKind = "mms_part_without_payload"

// mmsPartExpectsPayload is true for a media part: not the SMIL layout, not text.
func mmsPartExpectsPayload(part MMSPart) bool {
	ct := strings.ToLower(strings.TrimSpace(part.ContentType))
	return ct != "" && ct != "null" && ct != "application/smil" && !strings.HasPrefix(ct, "text/")
}

func mmsPartWithoutPayloadReference(part MMSPart) AttachmentReference {
	name := part.CL
	if name == "" || name == "null" {
		name = part.Name
	}
	if name == "null" {
		name = ""
	}
	return AttachmentReference{
		Kind: mmsPartWithoutPayloadKind, URIOriginal: name,
		DisplayText:      fmt.Sprintf("ct=%s seq=%s", part.ContentType, part.Seq),
		ResolutionStatus: AttachmentSourceReportedMissing, SourceReportedMissing: true,
	}
}

// captureMMSDataAttribute recognizes the XML attribute grammar
// `data S* = S* ("..."|'...')` only at an attribute boundary. Bytes are not
// committed to the sanitized spool until the name and delimiter are known, so
// data-prefixed attributes are preserved normally and legal whitespace cannot
// bypass attachment capture.
func captureMMSDataAttribute(
	r *bufio.Reader,
	writeBoth func([]byte) error,
	writeRaw func([]byte) error,
	sanitized io.Writer,
	rawHash hash.Hash,
	rawSpool io.Writer,
	rawSize *int64,
	dir string,
	ordinal int,
) (streamedAttachment, bool, error) {
	consumed := make([]byte, 0, 16)
	flushOrdinary := func() (streamedAttachment, bool, error) {
		if err := writeBoth(consumed); err != nil {
			return streamedAttachment{}, false, err
		}
		return streamedAttachment{}, false, nil
	}
	name, err := r.Peek(len("data"))
	if err != nil || string(name) != "data" {
		return streamedAttachment{}, false, err
	}
	_, _ = r.Discard(len("data"))
	consumed = append(consumed, name...)
	b, err := r.ReadByte()
	if err != nil {
		return streamedAttachment{}, false, err
	}
	consumed = append(consumed, b)
	if isXMLNameByte(b) {
		return flushOrdinary()
	}
	if !isXMLSpace(b) && b != '=' {
		return streamedAttachment{}, false, errors.New("malformed MMS data attribute delimiter")
	}
	for isXMLSpace(b) {
		b, err = r.ReadByte()
		if err != nil {
			return streamedAttachment{}, false, err
		}
		consumed = append(consumed, b)
	}
	if b != '=' {
		return flushOrdinary()
	}
	b, err = r.ReadByte()
	if err != nil {
		return streamedAttachment{}, false, err
	}
	consumed = append(consumed, b)
	for isXMLSpace(b) {
		b, err = r.ReadByte()
		if err != nil {
			return streamedAttachment{}, false, err
		}
		consumed = append(consumed, b)
	}
	if b != '\'' && b != '"' {
		return streamedAttachment{}, false, errors.New("malformed MMS data attribute: quoted value required")
	}
	if err := writeRaw(consumed); err != nil {
		return streamedAttachment{}, false, err
	}
	marker := fmt.Sprintf("__SBV_ATTACHMENT_%d__", ordinal)
	if _, err := sanitized.Write(consumed); err != nil {
		return streamedAttachment{}, false, err
	}
	if _, err := io.WriteString(sanitized, marker+string(b)); err != nil {
		return streamedAttachment{}, false, err
	}
	draft, err := decodeMMSAttribute(r, rawHash, rawSpool, rawSize, b, dir, marker)
	if err != nil {
		return streamedAttachment{}, false, err
	}
	return draft, true, nil
}

func isXMLNameByte(b byte) bool {
	return b == ':' || b == '_' || b == '-' || b == '.' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= 0x80
}

type quotedHashReader struct {
	r     *bufio.Reader
	h     hash.Hash
	raw   io.Writer
	size  *int64
	quote byte
	done  bool
}

func (q *quotedHashReader) Read(p []byte) (int, error) {
	if q.done {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		b, err := q.r.ReadByte()
		if err != nil {
			return n, err
		}
		_, _ = q.h.Write([]byte{b})
		if _, err := q.raw.Write([]byte{b}); err != nil {
			return n, err
		}
		*q.size++
		if b == q.quote {
			q.done = true
			if n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}
		p[n] = b
		n++
	}
	return n, nil
}

func decodeMMSAttribute(r *bufio.Reader, rawHash hash.Hash, rawSpool io.Writer, rawSize *int64, quote byte,
	dir, marker string) (streamedAttachment, error) {
	f, err := os.CreateTemp(dir, "decoded-*.bin")
	if err != nil {
		return streamedAttachment{}, err
	}
	defer f.Close()
	decodedHash := sha256.New()
	qr := &quotedHashReader{r: r, h: rawHash, raw: rawSpool, size: rawSize, quote: quote}
	decoder := base64.NewDecoder(base64.StdEncoding, qr)
	written, decodeErr := io.CopyBuffer(io.MultiWriter(f, decodedHash), decoder, make([]byte, mmsStreamBufferBytes))
	if !qr.done {
		_, _ = io.CopyBuffer(io.Discard, qr, make([]byte, mmsStreamBufferBytes))
	}
	if err := f.Sync(); err != nil {
		return streamedAttachment{}, err
	}
	status, errText := "not_attempted", ""
	if decodeErr != nil {
		status, errText = "decode_failed", decodeErr.Error()
	}
	return streamedAttachment{path: f.Name(), hash: hex.EncodeToString(decodedHash.Sum(nil)),
		bytes: written, status: status, decodeErr: errText, marker: marker}, nil
}

func sanitizedAttachmentName(values ...interface{}) string {
	name := ""
	index := 0
	for _, value := range values {
		switch v := value.(type) {
		case string:
			if cleaned := normalizeNullString(v); cleaned != "" && name == "" {
				name = filepath.Base(strings.ReplaceAll(cleaned, "\\", "/"))
			}
		case int:
			index = v
		}
	}
	if name == "" || name == "." {
		name = fmt.Sprintf("attachment-%d.bin", index)
	}
	name = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, name)
	return name
}

func isXMLSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

func messageSourceRecord(raw []byte, pos string, msg *Message, source interface{}) *SourceRecord {
	participants := append([]string(nil), msg.Addresses...)
	if msg.Address != "" {
		participants = append(participants, msg.Address)
	}
	sender := msg.Sender
	recipients := make([]SourceParty, 0)
	if msg.Type == 1 {
		if sender == "" {
			sender = msg.Address
		}
		recipients = append(recipients, SourceParty{Identity: "self", Role: "to"})
		participants = append(participants, "self")
	} else if msg.Type == 2 || msg.Type == 4 || msg.Type == 5 || msg.Type == 6 {
		sender = "self"
		participants = append(participants, "self")
		for _, address := range uniqueStrings(append(msg.Addresses, msg.Address)...) {
			if address != "" {
				recipients = append(recipients, SourceParty{Identity: address, Role: "to"})
			}
		}
	}
	return &SourceRecord{
		Kind: KindMessage, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonVersion,
		OccurredAt: &msg.Date, Participants: participants, Sender: sender, Recipients: recipients, Content: msg.Body,
		Metadata: structMetadata(source), LegacyMessage: msg,
	}
}

func callSourceRecord(raw []byte, pos string, call *CallLog, source interface{}) *SourceRecord {
	participants := make([]string, 0, 1)
	if call.Number != "" {
		participants = append(participants, call.Number)
	}
	return &SourceRecord{
		Kind: KindCall, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonVersion,
		OccurredAt: &call.Date, Participants: participants,
		Metadata: structMetadata(source), LegacyCall: call,
	}
}

func structMetadata(value interface{}) map[string]interface{} {
	b, err := json.Marshal(value)
	if err != nil {
		return map[string]interface{}{"projection_error": err.Error()}
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		return map[string]interface{}{"projection_error": err.Error()}
	}
	return out
}

func init() {
	RegisterImporter(smsXMLImporter{})
}
