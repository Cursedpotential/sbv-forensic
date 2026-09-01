package internal

// Byline amendment: Codex · GPT-5 · 2026-08-18 (combined-change hygiene).

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	transcriptMarkerRE = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)\]\s*(.*?):\s*$`)
	imessageHeaderRE   = regexp.MustCompile(`(?i)^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2}, \d{4}\s+\d{1,2}:\d{2}(?::\d{2})?\s*[AP]M)(?:\s*\(Read by (.*?)\))?\s*$`)
	attachmentPathRE   = regexp.MustCompile(`(?i)(?:^|[/\\])[^/\\]+\.(?:jpe?g|png|gif|heic|mov|mp4|m4a|mp3|wav|pdf|vcf|webp)$`)
)

type transcriptImporter struct{}
type imessageTXTImporter struct{}

func (transcriptImporter) Format() string { return FormatTranscript }
func (transcriptImporter) Priority() int  { return 680 }
func (transcriptImporter) Detect(head []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".txt" && ext != ".csv" {
		return false
	}
	for _, line := range bytes.Split(head, []byte{'\n'}) {
		if transcriptMarkerRE.MatchString(strings.TrimSpace(string(line))) {
			return true
		}
	}
	return false
}

func (transcriptImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runTextBlocks(sink, r, transcriptMarker, "transcript")
}

func (imessageTXTImporter) Format() string { return FormatIMessageTXT }
func (imessageTXTImporter) Priority() int  { return 720 }
func (imessageTXTImporter) Detect(head []byte, filename string) bool {
	if strings.ToLower(filepath.Ext(filename)) != ".txt" {
		return false
	}
	lines := bytes.Split(head, []byte{'\n'})
	for i, line := range lines {
		if imessageHeaderRE.MatchString(strings.TrimSpace(string(line))) {
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if strings.TrimSpace(string(lines[j])) != "" {
					return true
				}
			}
		}
	}
	return false
}

func (imessageTXTImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runTextBlocks(sink, r, imessageMarker, "imessage")
}

type textMarker func(string) (timestamp, sender, receipt string, ok bool)

func transcriptMarker(line string) (string, string, string, bool) {
	m := transcriptMarkerRE.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", "", "", false
	}
	return m[1], strings.TrimSpace(m[2]), "", true
}

func imessageMarker(line string) (string, string, string, bool) {
	m := imessageHeaderRE.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", "", "", false
	}
	return m[1], "", strings.TrimSpace(m[2]), true
}

type textBlock struct {
	raw       []byte
	pos       string
	timestamp string
	sender    string
	receipt   string
	body      []string
}

func runTextBlocks(sink ImportSink, r *bufio.Reader, marker textMarker, platform string) error {
	lineNo := 0
	var current *textBlock
	flush := func() error {
		if current == nil {
			return nil
		}
		if current.sender == "" && platform == "imessage" {
			for len(current.body) > 0 && strings.TrimSpace(current.body[0]) == "" {
				current.body = current.body[1:]
			}
			if len(current.body) > 0 {
				current.sender = strings.TrimSpace(current.body[0])
				current.body = current.body[1:]
			}
		}
		bodyLines := make([]string, 0, len(current.body))
		attachmentLines := make([]string, 0)
		for _, line := range current.body {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if attachmentPathRE.MatchString(trimmed) || strings.Contains(strings.ToLower(trimmed), "attachment missing") {
				attachmentLines = append(attachmentLines, trimmed)
				continue
			}
			bodyLines = append(bodyLines, trimmed)
		}
		content := strings.Join(bodyLines, "\n")
		if content == "" && len(attachmentLines) > 0 {
			content = fmt.Sprintf("[%d attachment(s)]", len(attachmentLines))
		}
		sender := strings.TrimSpace(current.sender)
		if sender == "" {
			sender = "Unknown"
		}
		role, direction := sender, "inbound"
		if strings.EqualFold(sender, "me") || strings.EqualFold(sender, "you") {
			role, direction = ownerRole, "outbound"
		}
		actualSender := sender
		recipients := []SourceParty(nil)
		if direction == "outbound" {
			actualSender = "self"
		} else {
			recipients = []SourceParty{{Identity: "self", Role: "to"}}
		}
		kind := KindMessage
		lower := strings.ToLower(content)
		if strings.Contains(lower, "call") && (strings.Contains(lower, "facetime") || strings.Contains(lower, "missed") || strings.Contains(lower, "incoming") || strings.Contains(lower, "outgoing")) {
			kind = KindCall
		}
		metadata := map[string]interface{}{
			"platform": platform, "format": "txt", "direction": direction,
			"sender_label": sender, "raw_timestamp": current.timestamp,
		}
		if current.receipt != "" {
			metadata["read_receipt"] = map[string]interface{}{"reader": current.receipt}
		}
		attachmentRefs := make([]AttachmentReference, 0, len(attachmentLines))
		attachmentMetadata := make([]map[string]interface{}, 0, len(attachmentLines))
		for _, line := range attachmentLines {
			ref := newIMessageAttachmentReference("file", line, line)
			attachmentRefs = append(attachmentRefs, ref)
			attachmentMetadata = append(attachmentMetadata, attachmentReferenceMetadata(ref))
		}
		if len(attachmentMetadata) > 0 {
			metadata["attachments"] = attachmentMetadata
		}
		return sink.Record(&SourceRecord{
			Kind: kind, SourcePos: current.pos, Raw: current.raw, RawCanon: RecordHashCanonRawV1,
			OccurredAt: parseMessagingTime(current.timestamp), Participants: uniqueStrings("self", role),
			Sender: actualSender, Recipients: recipients, Content: content,
			Metadata: metadataJSONSizeSafe(metadata), AttachmentReferences: attachmentRefs,
		})
	}

	for {
		raw, tooLong, err := readRawTextLine(r, maxLineRecordBytes)
		if len(raw) == 0 && err == io.EOF {
			break
		}
		lineNo++
		if tooLong {
			if current != nil {
				current.raw = append(current.raw, raw...)
				if rejectErr := sink.Reject(current.pos, "transcript block contains an over-limit line", current.raw, false); rejectErr != nil {
					return rejectErr
				}
				current = nil
			} else if rejectErr := sink.Reject(fmt.Sprintf("line:%d", lineNo), "text line exceeds size bound", raw, false); rejectErr != nil {
				return rejectErr
			}
		} else {
			line := string(bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\r'}))
			if ts, sender, receipt, ok := marker(line); ok {
				if flushErr := flush(); flushErr != nil {
					return flushErr
				}
				current = &textBlock{raw: append([]byte(nil), raw...), pos: fmt.Sprintf("line:%d", lineNo), timestamp: ts, sender: sender, receipt: receipt}
			} else if current != nil {
				if len(current.raw)+len(raw) > maxRawRecordBytes {
					if rejectErr := sink.Reject(current.pos, "transcript block exceeds size bound", current.raw, false); rejectErr != nil {
						return rejectErr
					}
					current = nil
				} else {
					current.raw = append(current.raw, raw...)
					current.body = append(current.body, line)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return flush()
}

func readRawTextLine(r *bufio.Reader, limit int) ([]byte, bool, error) {
	var raw []byte
	tooLong := false
	for {
		fragment, err := r.ReadSlice('\n')
		if !tooLong {
			remaining := limit + 1 - len(raw)
			if remaining > len(fragment) {
				remaining = len(fragment)
			}
			if remaining > 0 {
				raw = append(raw, fragment[:remaining]...)
			}
			if len(raw) > limit {
				tooLong = true
				raw = raw[:limit]
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return raw, tooLong, err
	}
}

func init() {
	RegisterImporter(imessageTXTImporter{})
	RegisterImporter(transcriptImporter{})
}
