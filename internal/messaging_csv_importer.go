package internal

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type messagingCSVImporter struct{}

var (
	csvTimeKeys       = []string{"message date", "readable_date", "readable date", "date", "timestamp", "time", "datetime", "date sent", "sent date", "date/time", "date time", "sent at"}
	csvTextKeys       = []string{"text", "message", "body", "content", "message text", "msg"}
	csvSenderKeys     = []string{"sender name", "sender", "from", "from name", "contact", "contact_name", "contact name", "sender_name", "name", "author"}
	csvSenderIDKeys   = []string{"sender id", "from number", "address", "phone", "phone number", "number", "sender_id", "handle", "handle id"}
	csvRecipientKeys  = []string{"recipient", "to", "to number", "recipient id", "recipients"}
	csvDirectionKeys  = []string{"is from me", "fromme", "type", "direction", "sent/received", "kind", "message type"}
	csvServiceKeys    = []string{"service", "platform", "protocol", "account"}
	csvChatKeys       = []string{"chat session", "conversation", "thread", "chat", "group", "chat name", "conversation id", "chat id", "group name"}
	csvReadKeys       = []string{"read date", "read", "date read", "read receipt"}
	csvAttachmentKeys = []string{"attachment", "attachments", "attachment path", "file", "media", "attachment id", "attachment name"}
)

func (messagingCSVImporter) Format() string { return FormatCSV }
func (messagingCSVImporter) Priority() int  { return 650 }
func (messagingCSVImporter) Detect(head []byte, filename string) bool {
	if strings.ToLower(filepath.Ext(filename)) != ".csv" {
		return false
	}
	raw := firstPhysicalLine(head)
	comma := detectCSVComma(raw)
	fields, err := decodeCSVRecord(raw, comma)
	return err == nil && messagingCSVHeader(fields)
}

func (messagingCSVImporter) Run(sink ImportSink, r *bufio.Reader) error {
	headerRaw, over, err := readBoundedCSVRecord(r, maxLineRecordBytes)
	if over {
		return fmt.Errorf("CSV header exceeds %d-byte bound", maxLineRecordBytes)
	}
	if err != nil && err != io.EOF {
		return err
	}
	comma := detectCSVComma(headerRaw)
	header, err := decodeCSVRecord(headerRaw, comma)
	if err != nil || !messagingCSVHeader(header) {
		return fmt.Errorf("not a messaging CSV: invalid or unsupported header")
	}
	norm := make([]string, len(header))
	for i := range header {
		norm[i] = normalizeHeader(header[i])
	}

	rowNo := 1
	for {
		raw, tooLong, readErr := readBoundedCSVRecord(r, maxLineRecordBytes)
		if len(raw) == 0 && readErr == io.EOF {
			return nil
		}
		rowNo++
		pos := fmt.Sprintf("row:%d", rowNo)
		if tooLong {
			if err := sink.Reject(pos, fmt.Sprintf("CSV record exceeds %d-byte bound", maxLineRecordBytes), raw, false); err != nil {
				return err
			}
		} else if len(bytes.TrimSpace(raw)) > 0 {
			fields, err := decodeCSVRecord(raw, comma)
			if err != nil {
				if rejectErr := sink.Reject(pos, "invalid CSV record: "+err.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
			} else if len(fields) > maxCSVFields {
				if rejectErr := sink.Reject(pos, "CSV record has too many fields", raw, true); rejectErr != nil {
					return rejectErr
				}
			} else if recordErr := sink.Record(csvSourceRecord(header, norm, fields, raw, pos)); recordErr != nil {
				return recordErr
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func readBoundedCSVRecord(r *bufio.Reader, limit int) ([]byte, bool, error) {
	raw := make([]byte, 0, 4096)
	inQuotes, tooLong := false, false
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
		if b == '"' {
			if inQuotes {
				if next, _ := r.Peek(1); len(next) == 1 && next[0] == '"' {
					escaped, readErr := r.ReadByte()
					if !tooLong {
						raw = append(raw, escaped)
						if len(raw) > limit {
							tooLong = true
							raw = raw[:limit]
						}
					}
					if readErr != nil {
						return raw, tooLong, readErr
					}
				} else {
					inQuotes = false
				}
			} else {
				inQuotes = true
			}
		}
		if b == '\n' && !inQuotes {
			if !tooLong {
				raw = bytes.TrimSuffix(raw, []byte{'\n'})
				raw = bytes.TrimSuffix(raw, []byte{'\r'})
			}
			return raw, tooLong, nil
		}
	}
}

func detectCSVComma(raw []byte) rune {
	best, bestCount := ',', -1
	for _, candidate := range []rune{',', ';', '\t', '|'} {
		if count := strings.Count(string(raw), string(candidate)); count > bestCount {
			best, bestCount = candidate, count
		}
	}
	return best
}

func decodeCSVRecord(raw []byte, comma rune) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(raw))
	r.Comma = comma
	r.FieldsPerRecord = -1
	return r.Read()
}

func messagingCSVHeader(header []string) bool {
	keys := make(map[string]bool)
	for _, h := range header {
		keys[normalizeHeader(h)] = true
	}
	has := func(groups ...[]string) bool {
		for _, group := range groups {
			for _, key := range group {
				if keys[key] {
					return true
				}
			}
		}
		return false
	}
	return has(csvTimeKeys) && has(csvTextKeys) && has(csvSenderKeys, csvDirectionKeys, csvServiceKeys, csvSenderIDKeys)
}

func csvSourceRecord(header, norm, fields []string, raw []byte, pos string) *SourceRecord {
	row, original := make(map[string]string), make(map[string]string)
	for i, value := range fields {
		if i < len(header) {
			row[norm[i]], original[header[i]] = value, value
		}
	}
	text := pickField(row, csvTextKeys...)
	sender := pickField(row, csvSenderKeys...)
	senderID := pickField(row, csvSenderIDKeys...)
	recipient := pickField(row, csvRecipientKeys...)
	attachment := pickField(row, csvAttachmentKeys...)
	direction := csvDirection(row)
	role := sender
	if direction == "outbound" || strings.EqualFold(sender, "me") || strings.EqualFold(sender, "you") {
		role = ownerRole
	} else if role == "" {
		role = senderID
	}
	if role == "" {
		role = "Unknown"
	}
	if text == "" && attachment != "" {
		text = "[attachment: " + attachment + "]"
	}
	service := pickField(row, csvServiceKeys...)
	platform := "messages"
	lowerService := strings.ToLower(service)
	for _, candidate := range []string{"imessage", "sms", "mms", "whatsapp"} {
		if strings.Contains(lowerService, candidate) {
			platform = candidate
			break
		}
	}
	kind := KindMessage
	blob := strings.ToLower(text + " " + pickField(row, csvDirectionKeys...))
	for _, token := range []string{"missed call", "facetime", "incoming call", "outgoing call", "phone call", "call ended", "cancelled call"} {
		if strings.Contains(blob, token) {
			kind = KindCall
			break
		}
	}
	metadata := map[string]interface{}{
		"platform": platform, "format": "csv", "raw_row": original,
		"role": role, "conversation_id": pickField(row, csvChatKeys...),
	}
	for key, value := range map[string]string{"direction": direction, "sender_label": sender,
		"sender_id": senderID, "service": service, "attachment": attachment,
		"read_receipt": pickField(row, csvReadKeys...)} {
		if value != "" {
			metadata[key] = value
		}
	}
	return &SourceRecord{
		Kind: kind, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		OccurredAt:   parseMessagingTime(pickField(row, csvTimeKeys...)),
		Participants: uniqueStrings(ownerRole, role, senderID, recipient), Content: text,
		Metadata: metadataJSONSizeSafe(metadata),
	}
}

func csvDirection(row map[string]string) string {
	for _, key := range csvDirectionKeys {
		value := strings.ToLower(strings.TrimSpace(row[key]))
		if value == "" {
			continue
		}
		if key == "is from me" || key == "fromme" {
			if value == "1" || value == "true" || value == "yes" {
				return "outbound"
			}
			return "inbound"
		}
		if key == "type" {
			if value == "1" {
				return "inbound"
			}
			if value == "2" || value == "4" || value == "5" || value == "6" {
				return "outbound"
			}
		}
		if containsDirection(value, []string{"sent", "outgoing", "outbound", "me", "from me", "true", "yes"}) {
			return "outbound"
		}
		if containsDirection(value, []string{"received", "incoming", "inbound", "false", "no"}) {
			return "inbound"
		}
	}
	return ""
}

func containsDirection(value string, candidates []string) bool {
	for _, candidate := range candidates {
		if value == candidate || strings.Contains(" "+value+" ", " "+candidate+" ") {
			return true
		}
	}
	return false
}

func firstPhysicalLine(head []byte) []byte {
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		return bytes.TrimSuffix(head[:i], []byte{'\r'})
	}
	return head
}

func init() { RegisterImporter(messagingCSVImporter{}) }
