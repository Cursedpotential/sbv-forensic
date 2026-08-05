package internal

// ndjson_importer.go — bounded-memory NDJSON/JSONL plugin for the universal
// import engine. Each non-empty physical line is one logical source record.
// H2 is computed by the engine over that exact line without its LF/CRLF record
// terminator; JSON decoding and field projection happen only afterwards.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ndjsonImporter struct{}

func (ndjsonImporter) Format() string { return FormatNDJSON }
func (ndjsonImporter) Priority() int  { return 700 }

func (ndjsonImporter) Detect(head []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".ndjson" || ext == ".jsonl" {
		return true
	}
	// Content-only detection is deliberately conservative: ordinary JSON must
	// not be mistaken for NDJSON merely because it starts with an object.
	validObjects := 0
	for _, line := range bytes.Split(head, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var obj map[string]interface{}
		if json.Unmarshal(line, &obj) != nil || obj == nil {
			return false
		}
		validObjects++
		if validObjects >= 2 {
			return true
		}
	}
	return false
}

func (ndjsonImporter) Run(sink ImportSink, r *bufio.Reader) error {
	lineNo := 0
	for {
		raw, tooLong, err := readBoundedLine(r, maxLineRecordBytes)
		if len(raw) == 0 && err == io.EOF {
			return nil
		}
		lineNo++
		pos := fmt.Sprintf("line:%d", lineNo)
		if tooLong {
			if rejectErr := sink.Reject(pos,
				fmt.Sprintf("NDJSON record exceeds %d-byte bound", maxLineRecordBytes), raw, false); rejectErr != nil {
				return rejectErr
			}
		} else if len(bytes.TrimSpace(raw)) != 0 {
			rec, decodeErr := decodeNDJSONRecord(raw, pos)
			if decodeErr != nil {
				if rejectErr := sink.Reject(pos, decodeErr.Error(), raw, true); rejectErr != nil {
					return rejectErr
				}
			} else if recordErr := sink.Record(rec); recordErr != nil {
				return recordErr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read NDJSON %s: %w", pos, err)
		}
	}
}

// readBoundedLine reads one physical line without its LF/CRLF terminator. For
// an over-limit line it retains only a bounded excerpt and drains the rest of
// that line, allowing the following record to be parsed normally.
func readBoundedLine(r *bufio.Reader, limit int) ([]byte, bool, error) {
	var raw []byte
	tooLong := false
	for {
		frag, err := r.ReadSlice('\n')
		if !tooLong {
			remaining := limit + 1 - len(raw)
			if remaining > 0 {
				if len(frag) < remaining {
					remaining = len(frag)
				}
				raw = append(raw, frag[:remaining]...)
			}
			if len(raw) > limit {
				tooLong = true
				raw = raw[:limit]
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return raw, tooLong, err
		}
		if !tooLong {
			raw = bytes.TrimSuffix(raw, []byte{'\n'})
			raw = bytes.TrimSuffix(raw, []byte{'\r'})
		}
		return raw, tooLong, err
	}
}

func decodeNDJSONRecord(raw []byte, pos string) (*SourceRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]interface{}
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	if obj == nil {
		return nil, fmt.Errorf("NDJSON record must be a JSON object")
	}
	// Reject trailing non-whitespace JSON values on one physical line.
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values on one NDJSON line")
		}
		return nil, fmt.Errorf("invalid trailing JSON data: %w", err)
	}

	kind := firstString(obj, "kind", "record_type", "type")
	if kind == "" || len(kind) > 80 {
		kind = KindObject
	}
	content := firstString(obj, "content", "text", "body", "message", "description")
	participants := firstParticipants(obj, "participants", "addresses", "address", "sender", "author", "from", "to")
	occurred := firstTime(obj, "occurred_at", "timestamp", "datetime", "created_at", "date")

	return &SourceRecord{
		Kind:         kind,
		SourcePos:    pos,
		Raw:          raw,
		RawCanon:     RecordHashCanonRawV1,
		OccurredAt:   occurred,
		Participants: participants,
		Content:      content,
		Metadata:     obj,
	}, nil
}

func firstString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if value, ok := obj[key]; ok {
			if s, ok := value.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

func firstParticipants(obj map[string]interface{}, keys ...string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, key := range keys {
		switch value := obj[key].(type) {
		case string:
			add(value)
		case []interface{}:
			for _, item := range value {
				if s, ok := item.(string); ok {
					add(s)
				}
			}
		}
	}
	return out
}

func firstTime(obj map[string]interface{}, keys ...string) *time.Time {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok {
			continue
		}
		if t, ok := parseImportTime(value); ok {
			return &t
		}
	}
	return nil
}

func parseImportTime(value interface{}) (time.Time, bool) {
	if s, ok := value.(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t, true
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return unixImportTime(n), true
		}
	}
	if n, ok := value.(json.Number); ok {
		if v, err := n.Int64(); err == nil {
			return unixImportTime(v), true
		}
	}
	return time.Time{}, false
}

func unixImportTime(value int64) time.Time {
	// Millisecond epochs are common in export formats; preserve seconds too.
	if value > 100000000000 || value < -100000000000 {
		return time.UnixMilli(value).UTC()
	}
	return time.Unix(value, 0).UTC()
}

func init() {
	RegisterImporter(ndjsonImporter{})
}
