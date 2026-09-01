package internal

// Byline amendment: Codex · GPT-5 · 2026-08-18 (combined-change hygiene).

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

const (
	maxEmailHeaderBytes     = 1 << 20
	maxEmailHeaderLineBytes = 64 << 10
	maxEmailTextBytes       = 8 << 20
	maxMIMEDepth            = 32
	maxEmailMessageBytes    = int64(8) << 30
)

type emlImporter struct{}
type mboxImporter struct{}

func (emlImporter) Format() string { return FormatEML }
func (emlImporter) Priority() int  { return 820 }
func (emlImporter) Detect(head []byte, filename string) bool {
	if strings.EqualFold(filepath.Ext(filename), ".eml") {
		return true
	}
	s := strings.ToLower(string(head))
	return (strings.HasPrefix(s, "from:") || strings.Contains(s, "\nfrom:")) &&
		strings.Contains(s, "\nsubject:") && (strings.Contains(s, "\nmime-version:") || strings.Contains(s, "\ndate:"))
}

func (mboxImporter) Format() string { return FormatMBOX }
func (mboxImporter) Priority() int  { return 830 }
func (mboxImporter) Detect(head []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".mbox" && ext != ".mbx" {
		return false
	}
	line := string(head)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return mboxSeparatorRE.MatchString(strings.TrimSuffix(line, "\r"))
}

type hashingCountReader struct {
	r        io.Reader
	h        hash.Hash
	count    int64
	exceeded bool
}

func (r *hashingCountReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		_, _ = r.h.Write(p[:n])
		r.count += int64(n)
		if r.count > maxEmailMessageBytes {
			r.exceeded = true
		}
	}
	return n, err
}

func (emlImporter) Run(sink ImportSink, r *bufio.Reader) error {
	tracker := &hashingCountReader{r: r, h: sha256.New()}
	rec, parseErr := parseEmailProjection(sink, bufio.NewReaderSize(tracker, 64<<10), "message:1")
	_, drainErr := io.CopyBuffer(io.Discard, tracker, make([]byte, 128<<10))
	if drainErr != nil && parseErr == nil {
		parseErr = drainErr
	}
	h2 := hex.EncodeToString(tracker.h.Sum(nil))
	if tracker.exceeded && parseErr == nil {
		parseErr = fmt.Errorf("EML message exceeds %d-byte bound", maxEmailMessageBytes)
	}
	if parseErr != nil {
		return sink.RejectHashed("message:1", parseErr.Error(), h2, RecordHashCanonRawV1, tracker.count)
	}
	rec.PrecomputedH2 = h2
	rec.RawSize = tracker.count
	return sink.Record(rec)
}

var mboxSeparatorRE = regexp.MustCompile(`^From\s+\S+\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+`)

func (mboxImporter) Run(sink ImportSink, r *bufio.Reader) error {
	root, err := sink.ArtifactDir()
	if err != nil {
		return err
	}
	spoolDir := filepath.Join(root, "email-spools")
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return err
	}
	var separator []byte
	recordNo := 0
	for {
		if separator == nil {
			line, tooLong, readErr := readRawTextLine(r, maxLineRecordBytes)
			if tooLong {
				return sink.Reject("mbox-preamble", "MBOX separator line exceeds size bound", line, false)
			}
			if readErr == io.EOF && len(line) == 0 {
				return nil
			}
			if !mboxSeparatorRE.MatchString(strings.TrimSuffix(string(line), "\r\n")) {
				return sink.Reject("mbox-preamble", "MBOX must begin with a conservative From_ separator", line, true)
			}
			separator = line
		}
		recordNo++
		pos := fmt.Sprintf("mbox-message:%d", recordNo)
		separatorForRecord := append([]byte(nil), separator...)
		spool, err := os.CreateTemp(spoolDir, "message-*.eml")
		if err != nil {
			return err
		}
		h := sha256.New()
		_, _ = h.Write(separator)
		rawSize := int64(len(separator))
		overflow := rawSize > maxEmailMessageBytes
		hashComplete := true
		separator = nil
		for {
			line, tooLong, readErr := readRawTextLine(r, maxLineRecordBytes)
			if tooLong {
				overflow = true
				hashComplete = false
			}
			isSeparator := !tooLong && mboxSeparatorRE.MatchString(strings.TrimSuffix(string(line), "\r\n"))
			if isSeparator {
				separator = line
				break
			}
			if len(line) > 0 {
				_, _ = h.Write(line)
				rawSize += int64(len(line))
				if rawSize > maxEmailMessageBytes {
					overflow = true
				}
				if !overflow {
					if _, err := spool.Write(line); err != nil {
						_ = spool.Close()
						return err
					}
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = spool.Close()
				return readErr
			}
		}
		if err := spool.Sync(); err != nil {
			_ = spool.Close()
			return err
		}
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			_ = spool.Close()
			return err
		}
		h2 := hex.EncodeToString(h.Sum(nil))
		if overflow {
			_ = spool.Close()
			var rejectErr error
			if hashComplete {
				rejectErr = sink.RejectHashed(pos, "MBOX message exceeds message size bound", h2, RecordHashCanonRawV1, rawSize)
			} else {
				rejectErr = sink.Reject(pos, "MBOX message contains a physical line exceeding the streaming bound", nil, false)
			}
			if rejectErr != nil {
				return rejectErr
			}
		} else {
			rec, parseErr := parseEmailProjection(sink, bufio.NewReaderSize(spool, 64<<10), pos)
			_ = spool.Close()
			if parseErr != nil {
				if err := sink.RejectHashed(pos, parseErr.Error(), h2, RecordHashCanonRawV1, rawSize); err != nil {
					return err
				}
			} else {
				rec.PrecomputedH2 = h2
				rec.RawSize = rawSize
				rec.Metadata["mbox_separator"] = strings.TrimRight(string(separatorForRecord), "\r\n")
				if err := sink.Record(rec); err != nil {
					return err
				}
			}
		}
		if separator == nil {
			return nil
		}
	}
}

type emailProjection struct {
	plain       string
	html        string
	attachments []AttachmentArtifact
	manifest    []map[string]interface{}
	truncated   bool
	partNo      int
	root        string
}

func parseEmailProjection(sink ImportSink, r *bufio.Reader, pos string) (*SourceRecord, error) {
	rawHeader, err := readBoundedEmailHeader(r)
	if err != nil {
		return nil, err
	}
	message, err := mail.ReadMessage(bytes.NewReader(rawHeader))
	if err != nil {
		return nil, fmt.Errorf("parse RFC5322 headers: %w", err)
	}
	root, err := sink.ArtifactDir()
	if err != nil {
		return nil, err
	}
	state := &emailProjection{root: root}
	if err := parseMIMEEntity(textproto.MIMEHeader(message.Header), r, 0, state); err != nil {
		return nil, err
	}
	body := state.plain
	if body == "" {
		body = state.html
	}
	metadata := emailHeaderMetadata(message.Header, string(rawHeader))
	metadata["attachments"] = state.manifest
	metadata["text_truncated"] = state.truncated
	metadata["platform"] = "email"
	metadata["format"] = "rfc5322-mime"
	participants := emailParticipants(message.Header)
	sender, recipients := emailParties(message.Header)
	var occurred *time.Time
	if rawDate := strings.TrimSpace(message.Header.Get("Date")); rawDate != "" {
		if parsed, err := mail.ParseDate(rawDate); err == nil {
			occurred = &parsed
		}
	}
	return &SourceRecord{Kind: KindEmail, SourcePos: pos, RawCanon: RecordHashCanonRawV1,
		OccurredAt: occurred, Participants: participants, Sender: sender, Recipients: recipients,
		Content: body, Metadata: metadata,
		Attachments: state.attachments}, nil
}

func readBoundedEmailHeader(r *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 4096)
	for {
		line, tooLong, err := readRawTextLine(r, maxEmailHeaderLineBytes)
		if tooLong {
			return nil, fmt.Errorf("RFC5322 header line exceeds %d-byte bound", maxEmailHeaderLineBytes)
		}
		if len(header)+len(line) > maxEmailHeaderBytes {
			return nil, fmt.Errorf("RFC5322 header block exceeds %d-byte bound", maxEmailHeaderBytes)
		}
		header = append(header, line...)
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			return header, nil
		}
		if err == io.EOF {
			return nil, fmt.Errorf("RFC5322 message has no header/body separator")
		}
		if err != nil {
			return nil, err
		}
	}
}

func parseMIMEEntity(header textproto.MIMEHeader, body io.Reader, depth int, state *emailProjection) error {
	if depth > maxMIMEDepth {
		return fmt.Errorf("MIME nesting exceeds depth %d", maxMIMEDepth)
	}
	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
		params = map[string]string{}
	}
	mediaType = strings.ToLower(mediaType)
	decoded := decodeTransferEncoding(body, header.Get("Content-Transfer-Encoding"))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return fmt.Errorf("multipart MIME entity missing boundary")
		}
		reader := multipart.NewReader(decoded, boundary)
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read MIME part: %w", err)
			}
			if err := parseMIMEEntity(part.Header, part, depth+1, state); err != nil {
				_ = part.Close()
				return err
			}
			_ = part.Close()
		}
	}

	disposition, dispositionParams, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := dispositionParams["filename"]
	if filename == "" {
		filename = params["name"]
	}
	cid := strings.Trim(strings.TrimSpace(header.Get("Content-ID")), "<>")
	isAttachment := strings.EqualFold(disposition, "attachment") || strings.EqualFold(disposition, "inline") || filename != "" || cid != ""
	if isAttachment {
		return spoolMIMEPart(decoded, mediaType, filename, cid, state)
	}
	if mediaType == "text/plain" || mediaType == "text/html" {
		text, truncated, err := readProjectedText(decoded, params["charset"], mediaType == "text/html")
		if err != nil {
			return err
		}
		state.truncated = state.truncated || truncated
		if mediaType == "text/plain" && state.plain == "" {
			state.plain = text
		} else if mediaType == "text/html" && state.html == "" {
			state.html = text
		}
		return nil
	}
	_, err = io.CopyBuffer(io.Discard, decoded, make([]byte, 128<<10))
	return err
}

func decodeTransferEncoding(body io.Reader, encoding string) io.Reader {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		return quotedprintable.NewReader(body)
	default:
		return body
	}
}

func spoolMIMEPart(body io.Reader, mediaType, filename, cid string, state *emailProjection) error {
	state.partNo++
	if filename == "" {
		if cid != "" {
			filename = "cid-" + cid
		} else {
			filename = fmt.Sprintf("mime-part-%d.bin", state.partNo)
		}
	}
	filename = sanitizedAttachmentName(filename, state.partNo)
	dir := filepath.Join(state.root, "attachments")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, fmt.Sprintf("email-%04d-*-%s", state.partNo, filename))
	if err != nil {
		return err
	}
	h := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(file, h), body, make([]byte, 128<<10))
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		quarantineConversionArtifact(state.root, file.Name())
		if copyErr != nil {
			return fmt.Errorf("decode MIME attachment: %w", copyErr)
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	state.attachments = append(state.attachments, AttachmentArtifact{
		OriginalName: filename, MIME: mediaType, DecodedHash: hex.EncodeToString(h.Sum(nil)),
		ByteCount: written, StoredPath: file.Name(), ConversionStatus: "not_attempted",
	})
	state.manifest = append(state.manifest, map[string]interface{}{
		"part": state.partNo, "filename": filename, "mime_type": mediaType,
		"content_id": cid, "decoded_hash": hex.EncodeToString(h.Sum(nil)), "byte_count": written,
	})
	return nil
}

func readProjectedText(reader io.Reader, label string, isHTML bool) (string, bool, error) {
	if label != "" && !strings.EqualFold(label, "utf-8") && !strings.EqualFold(label, "us-ascii") {
		converted, err := charset.NewReaderLabel(label, reader)
		if err == nil {
			reader = converted
		}
	}
	limited := &io.LimitedReader{R: reader, N: maxEmailTextBytes + 1}
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", false, err
	}
	truncated := len(data) > maxEmailTextBytes
	if truncated {
		data = data[:maxEmailTextBytes]
	}
	if _, err := io.CopyBuffer(io.Discard, reader, make([]byte, 64<<10)); err != nil {
		return "", truncated, err
	}
	if isHTML {
		return htmlText(data), truncated, nil
	}
	return strings.TrimSpace(string(data)), truncated, nil
}

func htmlText(data []byte) string {
	z := html.NewTokenizer(bytes.NewReader(data))
	parts := make([]string, 0)
	for {
		token := z.Next()
		if token == html.ErrorToken {
			break
		}
		if token == html.TextToken {
			if value := strings.TrimSpace(string(z.Text())); value != "" {
				parts = append(parts, value)
			}
		}
	}
	return strings.Join(parts, " ")
}

func emailHeaderMetadata(header mail.Header, raw string) map[string]interface{} {
	values := make(map[string][]string, len(header))
	for key, entries := range header {
		values[key] = append([]string(nil), entries...)
	}
	return map[string]interface{}{
		"raw_headers": raw, "headers": values, "message_id": header.Get("Message-ID"),
		"in_reply_to": header.Get("In-Reply-To"), "references": header.Get("References"),
		"from": header.Get("From"), "to": header.Get("To"), "cc": header.Get("Cc"),
		"bcc": header.Get("Bcc"), "subject": header.Get("Subject"), "raw_date": header.Get("Date"),
	}
}

func emailParticipants(header mail.Header) []string {
	participants := make([]string, 0)
	for _, key := range []string{"From", "To", "Cc", "Bcc"} {
		raw := header.Get(key)
		addresses, err := mail.ParseAddressList(raw)
		if err != nil {
			if raw != "" {
				participants = append(participants, raw)
			}
			continue
		}
		for _, address := range addresses {
			participants = append(participants, address.Address)
		}
	}
	return uniqueStrings(participants...)
}

func emailParties(header mail.Header) (string, []SourceParty) {
	sender := strings.TrimSpace(header.Get("From"))
	if addresses, err := mail.ParseAddressList(sender); err == nil && len(addresses) > 0 {
		sender = addresses[0].Address
	}
	recipients := make([]SourceParty, 0)
	for _, spec := range []struct{ key, role string }{{"To", "to"}, {"Cc", "cc"}, {"Bcc", "bcc"}} {
		raw := header.Get(spec.key)
		addresses, err := mail.ParseAddressList(raw)
		if err != nil {
			if strings.TrimSpace(raw) != "" {
				recipients = append(recipients, SourceParty{Identity: strings.TrimSpace(raw), Role: spec.role})
			}
			continue
		}
		for _, address := range addresses {
			recipients = append(recipients, SourceParty{Identity: address.Address, Role: spec.role})
		}
	}
	return sender, recipients
}

func init() {
	RegisterImporter(mboxImporter{})
	RegisterImporter(emlImporter{})
}
