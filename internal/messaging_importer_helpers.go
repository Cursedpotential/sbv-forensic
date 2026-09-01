package internal

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const ownerRole = "owner"

func normalizeHeader(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "\ufeff")))), " ")
}

func pickField(row map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(row[key]); value != "" {
			return value
		}
	}
	return ""
}

func parseMessagingTime(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
		t := unixImportTime(value)
		return &t
	}
	formats := []string{
		time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02 15:04",
		"01/02/2006 03:04:05 PM", "01/02/2006 15:04:05", "01/02/2006 03:04 PM",
		"01/02/2006 15:04", "01/02/06 03:04:05 PM", "01/02/06 15:04",
		"Jan 2, 2006 03:04:05 PM", "January 2, 2006 03:04:05 PM",
		"Jan 2, 2006, 3:04 PM", "January 2, 2006, 3:04 PM",
		"Jan 2, 2006 at 3:04 PM", "January 2, 2006 at 3:04 PM",
		"2006/01/02 15:04:05", "01/02/2006", "2006-01-02",
		"2006-01-02 03:04 PM", "2006-01-02 03:04:05 PM",
	}
	for _, layout := range formats {
		if parsed, err := time.Parse(layout, strings.Join(strings.Fields(raw), " ")); err == nil {
			t := parsed.UTC()
			return &t
		}
	}
	return nil
}

func metadataJSONSizeSafe(metadata map[string]interface{}) map[string]interface{} {
	// Keep canonical rows bounded even when a source field is unexpectedly huge.
	// H1/H2 and the retained original preserve all bytes; this projection marks
	// truncated values rather than silently exhausting memory/storage.
	const maxValue = 64 << 10
	for key, value := range metadata {
		if s, ok := value.(string); ok && len(s) > maxValue {
			metadata[key] = s[:maxValue]
			metadata[key+"_truncated"] = true
		}
	}
	if b, err := json.Marshal(metadata); err == nil && len(b) <= 1<<20 {
		return metadata
	}
	return map[string]interface{}{"projection_truncated": true}
}

func uniqueStrings(values ...string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
