package internal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type googleChatImporter struct{}

func (googleChatImporter) Format() string { return FormatGoogleChat }
func (googleChatImporter) Priority() int  { return 810 }
func (googleChatImporter) Detect(head []byte, filename string) bool {
	if !strings.EqualFold(filepath.Ext(filename), ".json") {
		return false
	}
	s := strings.ToLower(string(head))
	return strings.Contains(s, `"messages"`) && strings.Contains(s, `"creator"`) &&
		(strings.Contains(s, `"created_date"`) || strings.Contains(s, `"message_id"`))
}

func (googleChatImporter) Run(sink ImportSink, r *bufio.Reader) error {
	if err := seekJSONArray(r, "messages"); err != nil {
		return err
	}
	for index := 1; ; index++ {
		first, done, err := nextJSONArrayValueStart(r)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		pos := fmt.Sprintf("messages[%d]", index-1)
		if first != '{' {
			return fmt.Errorf("Google Chat %s is not an object", pos)
		}
		raw, h2, rawSize, overflow, err := readExactJSONObject(r, first, maxRawRecordBytes)
		if err != nil {
			return err
		}
		if overflow {
			if err := sink.RejectHashed(pos, "Google Chat message exceeds record size bound", h2, RecordHashCanonRawV1, rawSize); err != nil {
				return err
			}
			continue
		}
		rec, err := projectGoogleChatMessage(raw, pos)
		if err != nil {
			if err := sink.Reject(pos, err.Error(), raw, true); err != nil {
				return err
			}
			continue
		}
		if err := sink.Record(rec); err != nil {
			return err
		}
	}
}

func seekJSONArray(r *bufio.Reader, wanted string) error {
	inString, escaped := false, false
	var token bytes.Buffer
	for {
		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("find Google Chat messages array: %w", err)
		}
		if inString {
			if escaped {
				escaped = false
				token.WriteByte(b)
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
				if token.String() == wanted {
					if err := consumeJSONColonAndArray(r); err != nil {
						return err
					}
					return nil
				}
				continue
			}
			if token.Len() <= 256 {
				token.WriteByte(b)
			}
			continue
		}
		if b == '"' {
			inString = true
			token.Reset()
		}
	}
}

func consumeJSONColonAndArray(r *bufio.Reader) error {
	colon := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if isJSONSpace(b) {
			continue
		}
		if !colon {
			if b != ':' {
				return fmt.Errorf("messages key is not followed by ':'")
			}
			colon = true
			continue
		}
		if b != '[' {
			return fmt.Errorf("messages value is not an array")
		}
		return nil
	}
}

func nextJSONArrayValueStart(r *bufio.Reader) (byte, bool, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, false, err
		}
		if isJSONSpace(b) || b == ',' {
			continue
		}
		if b == ']' {
			return 0, true, nil
		}
		return b, false, nil
	}
}

func readExactJSONObject(r *bufio.Reader, first byte, limit int) ([]byte, string, int64, bool, error) {
	h := sha256.New()
	_, _ = h.Write([]byte{first})
	raw := []byte{first}
	rawSize := int64(1)
	depth := 1
	inString, escaped := false, false
	overflow := false
	for depth > 0 {
		b, err := r.ReadByte()
		if err != nil {
			return raw, "", rawSize, overflow, fmt.Errorf("unterminated JSON object: %w", err)
		}
		_, _ = h.Write([]byte{b})
		rawSize++
		if !overflow {
			raw = append(raw, b)
			if len(raw) > limit {
				overflow = true
				raw = raw[:limit]
			}
		}
		if inString {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return raw, hex.EncodeToString(h.Sum(nil)), rawSize, overflow, nil
}

func projectGoogleChatMessage(raw []byte, pos string) (*SourceRecord, error) {
	var obj map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid Google Chat message: %w", err)
	}
	creatorName, creatorEmail := "", ""
	if creator, ok := obj["creator"].(map[string]interface{}); ok {
		creatorName = firstString(creator, "name", "display_name")
		creatorEmail = firstString(creator, "email", "user_id")
	}
	text := firstString(obj, "text", "message_text")
	attachments, attachmentRefs := googleChatAttachmentRefs(obj)
	if text == "" && len(attachments) > 0 {
		text = fmt.Sprintf("[%d unresolved attachment(s)]", len(attachments))
	}
	metadata := make(map[string]interface{}, len(obj)+4)
	for key, value := range obj {
		metadata[key] = value
	}
	metadata["platform"] = "google_chat"
	metadata["format"] = "takeout-messages-json"
	metadata["bundle_context"] = "unresolved_missing_group_info"
	metadata["attachment_references"] = attachments
	return &SourceRecord{
		Kind: KindMessage, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		OccurredAt:   firstTime(obj, "created_date", "create_time", "timestamp"),
		Participants: uniqueStrings(creatorEmail, creatorName), Content: text, Metadata: metadata,
		AttachmentReferences: attachmentRefs,
	}, nil
}

func googleChatAttachmentRefs(obj map[string]interface{}) ([]map[string]interface{}, []AttachmentReference) {
	out := make([]map[string]interface{}, 0)
	refs := make([]AttachmentReference, 0)
	for _, key := range []string{"attached_files", "attachments", "attachment", "media"} {
		values, ok := obj[key].([]interface{})
		if !ok {
			continue
		}
		for _, value := range values {
			entry, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			name := firstString(entry, "original_name", "name", "filename", "title", "export_name")
			uri := firstString(entry, "export_name", "source", "url", "path", "download_url")
			ref := newAttachmentReference("file", uri, name)
			metadata := attachmentReferenceMetadata(ref)
			metadata["name"] = name
			metadata["content_type"] = firstString(entry, "content_type", "mime_type")
			out = append(out, metadata)
			refs = append(refs, ref)
		}
	}
	return out, refs
}

// safeJSONCompanionReference remains as the narrow boolean compatibility
// helper used by focused tests and older internal callers.
func safeJSONCompanionReference(value string) bool {
	return newAttachmentReference("file", value, "").SafeRelative
}

func isJSONSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\r' || b == '\n' }

func init() { RegisterImporter(googleChatImporter{}) }
