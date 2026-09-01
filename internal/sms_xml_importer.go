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
	for {
		name, prefix, err := nextXMLRecordStart(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		recordNo++
		pos := fmt.Sprintf("element:%d", recordNo)
		if name == "mms" {
			rec, err := streamMMSRecord(sink, r, prefix, pos)
			if err != nil {
				if rejectErr := sink.Reject(pos, err.Error(), nil, false); rejectErr != nil {
					return rejectErr
				}
				continue
			}
			if err := sink.Record(rec); err != nil {
				return err
			}
			continue
		}
		raw, tooLong, err := readXMLStartElement(r, prefix, maxRawRecordBytes)
		if err != nil {
			return err
		}
		if tooLong {
			if rejectErr := sink.Reject(pos, "XML record exceeds size bound", raw, false); rejectErr != nil {
				return rejectErr
			}
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

func nextXMLRecordStart(r *bufio.Reader) (string, []byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", nil, err
		}
		if b != '<' {
			continue
		}
		prefix := []byte{'<'}
		for len(prefix) < 16 {
			b, err = r.ReadByte()
			if err != nil {
				return "", nil, err
			}
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

func readXMLStartElement(r *bufio.Reader, prefix []byte, limit int) ([]byte, bool, error) {
	raw := append([]byte(nil), prefix...)
	if len(raw) > 0 && raw[len(raw)-1] == '>' {
		return raw, false, nil
	}
	tooLong := false
	var quote byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return raw, tooLong, err
		}
		if !tooLong {
			raw = append(raw, b)
			if len(raw) > limit {
				tooLong = true
				raw = raw[:limit]
			}
		}
		if quote != 0 {
			if b == quote {
				quote = 0
			}
			continue
		}
		if b == '\'' || b == '"' {
			quote = b
		} else if b == '>' {
			return raw, tooLong, nil
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
func streamMMSRecord(sink ImportSink, r *bufio.Reader, prefix []byte, pos string) (*SourceRecord, error) {
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
			part.Data = ""
			break
		}
		if !matchedPart && strings.TrimSpace(part.Data) != "" {
			return nil, fmt.Errorf("MMS inline data escaped lossless capture at part %d", partIndex)
		}
	}
	if len(attachments) != len(drafts) {
		return nil, fmt.Errorf("MMS captured %d inline payloads but associated %d parts", len(drafts), len(attachments))
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
	return rec, nil
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
