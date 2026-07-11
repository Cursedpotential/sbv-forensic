package internal

// export.go — Phase 5a native export synthesis for the SBV forensic fork.
//
// Upstream SBV has no server-side export route (the GUI exports client-side);
// today the Python tools-facade synthesizes an export from /sbv/messages +
// /sbv/calls (docker/tools/tools/facade.py: sbv_export). This makes that same
// export NATIVE and headless, and — because SBV is where custody is computed —
// stamps the export with the H1/H3 custody summary so an exported bundle carries
// its own chain-of-custody anchor. The NormalizedRecord mapping that Python does
// (server/evidence/tools/sbv_sms.py) is intentionally NOT duplicated here (see
// plan §5c): this is a faithful dump of SBV's own records + custody, not a
// re-normalization.

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"sort"
	"strings"
)

// ExportResponse is a superset of the facade's synthesized-export shape:
// the facade returns {format, messages, calls} (json) or {format, csv,
// message_count, call_count} (csv); this always includes both counts and,
// additively, the forensic custody summary for provenance.
type ExportResponse struct {
	Format       string        `json:"format"`
	JobID        string        `json:"job_id,omitempty"`
	Custody      *ImportRecord `json:"custody,omitempty"`
	MessageCount int           `json:"message_count"`
	CallCount    int           `json:"call_count"`
	Messages     []*Message    `json:"messages,omitempty"`
	Calls        []*CallLog    `json:"calls,omitempty"`
	CSV          string        `json:"csv,omitempty"`
}

// CollectExport walks the user's entire corpus via the existing GetActivity
// query (paginated) and splits it into messages and calls. It reuses the same
// unified activity read path the /api/activity handler uses — no new SQL, no
// duplicated parsing.
func CollectExport(userDB *sql.DB) ([]*Message, []*CallLog, error) {
	const page = 1000
	messages := make([]*Message, 0)
	calls := make([]*CallLog, 0)
	offset := 0
	for {
		items, err := GetActivity(userDB, nil, nil, page, offset)
		if err != nil {
			return nil, nil, err
		}
		for i := range items {
			switch items[i].Type {
			case "call":
				if items[i].Call != nil {
					calls = append(calls, items[i].Call)
				}
			default:
				if items[i].Message != nil {
					messages = append(messages, items[i].Message)
				}
			}
		}
		if len(items) < page {
			break
		}
		offset += page
	}
	return messages, calls, nil
}

// messagesToCSV renders messages as CSV with a sorted union of all populated
// JSON keys as the header — the same generic-columns behavior the Python facade
// uses (csv.DictWriter over the union of message keys).
func messagesToCSV(messages []*Message) (string, error) {
	rows := make([]map[string]interface{}, 0, len(messages))
	colSet := make(map[string]struct{})
	for _, m := range messages {
		b, err := json.Marshal(m)
		if err != nil {
			return "", err
		}
		var row map[string]interface{}
		if err := json.Unmarshal(b, &row); err != nil {
			return "", err
		}
		rows = append(rows, row)
		for k := range row {
			colSet[k] = struct{}{}
		}
	}

	cols := make([]string, 0, len(colSet))
	for k := range colSet {
		cols = append(cols, k)
	}
	sort.Strings(cols)

	var buf strings.Builder
	w := csv.NewWriter(&buf)
	if len(rows) > 0 {
		if err := w.Write(cols); err != nil {
			return "", err
		}
		for _, row := range rows {
			rec := make([]string, len(cols))
			for i, c := range cols {
				rec[i] = csvCell(row[c])
			}
			if err := w.Write(rec); err != nil {
				return "", err
			}
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// csvCell renders a decoded-JSON value as a CSV cell. Strings pass through;
// everything else is re-marshaled compactly so nested/typed values survive.
func csvCell(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
