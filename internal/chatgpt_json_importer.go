package internal

// chatgpt_json_importer.go — streaming decoder for the ChatGPT official data export
// (conversations.json). The FIRST AI-chat decoder in the SBV universal engine
// (ADR-0049 Gap 2). Memory-safe by construction: the export is a large JSON array of
// conversation objects, so we stream it ONE conversation at a time with a json.Decoder
// (never io.ReadAll / whole-file load) — the "Go is critical for files that could blow
// out a memory store" criterion (ADR-0049 / DECISION_LOG D-046). A 61 MB export holds at
// most one conversation object in memory at a time, not the whole file.
//
// Custody: each message node is captured as its exact raw JSON bytes (json.RawMessage) and
// handed to the sink as SourceRecord.Raw — the H2 input, never reformatted (h2-rawrecord-v1).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const chatgptJSONFormat = "chatgpt-official-json"

type chatgptJSONImporter struct{}

func (chatgptJSONImporter) Format() string { return chatgptJSONFormat }

// Priority: above the generic ndjson importer (700) so a .json export is offered to this
// specific decoder first. Detection is precise (mapping+create_time), so ordering only
// breaks ties, never mis-routes.
func (chatgptJSONImporter) Priority() int { return 820 }

// Detect: the export's structural signature — each conversation object opens with
// "title","create_time","update_time","mapping", so "mapping" + "create_time" both land in
// the first peek bytes. Those two keys do NOT co-occur in the Claude/Gemini/Perplexity
// exports (mirrors the Python chatgpt_official signature fix, 2026-08-12).
func (chatgptJSONImporter) Detect(head []byte, filename string) bool {
	s := string(head)
	if strings.Contains(s, `"mapping"`) && strings.Contains(s, `"create_time"`) {
		return true
	}
	lf := strings.ToLower(filename)
	return strings.HasSuffix(lf, ".json") && strings.Contains(lf, "conversations")
}

// --- the slice of the export we decode (everything else is carried in Metadata via Raw) ---

type chatgptNode struct {
	ID       string          `json:"id"`
	Message  json.RawMessage `json:"message"` // exact raw bytes of the message object (H2 input); null for the root
	Parent   *string         `json:"parent"`
	Children []string        `json:"children"`
}

type chatgptConversation struct {
	Title          string                 `json:"title"`
	CreateTime     *float64               `json:"create_time"`
	ConversationID string                 `json:"conversation_id"`
	Mapping        map[string]chatgptNode `json:"mapping"`
}

type chatgptMessage struct {
	ID         string          `json:"id"`
	Author     chatgptAuthor   `json:"author"`
	CreateTime *float64        `json:"create_time"`
	Content    json.RawMessage `json:"content"`
}

type chatgptAuthor struct {
	Role string `json:"role"`
}

func (chatgptJSONImporter) Run(sink ImportSink, r *bufio.Reader) error {
	dec := json.NewDecoder(r)

	// Consume the opening '[' — the export is a top-level array of conversations.
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("chatgpt export: reading opening token: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return fmt.Errorf("chatgpt export: expected a top-level JSON array, got %v", tok)
	}

	convIdx := 0
	for dec.More() {
		// Decode ONE conversation at a time as raw bytes, then unmarshal — bounded memory.
		var convRaw json.RawMessage
		if err := dec.Decode(&convRaw); err != nil {
			return fmt.Errorf("chatgpt export: decoding conversation %d: %w", convIdx, err)
		}
		var conv chatgptConversation
		if err := json.Unmarshal(convRaw, &conv); err != nil {
			// Malformed conversation object — reject the whole conversation span, keep going.
			if rerr := sink.Reject(fmt.Sprintf("conversation %d", convIdx), "invalid conversation object: "+err.Error(), convRaw, true); rerr != nil {
				return rerr
			}
			convIdx++
			continue
		}
		if err := emitConversation(sink, conv, convIdx); err != nil {
			return err
		}
		convIdx++
	}
	return nil
}

// emitConversation walks the mapping tree in root->children order and emits one
// SourceRecord per message node that carries actual content.
func emitConversation(sink ImportSink, conv chatgptConversation, convIdx int) error {
	// Roots: nodes whose parent is nil. Walk each in a stable, deterministic order.
	roots := make([]string, 0, 2)
	for id, node := range conv.Mapping {
		if node.Parent == nil {
			roots = append(roots, id)
		}
	}
	// Stable order so H3 (chain over ordered H2s) is reproducible run-to-run.
	sortStrings(roots)

	msgIdx := 0
	visited := make(map[string]bool, len(conv.Mapping))
	for _, root := range roots {
		if err := walkChatgptNode(sink, conv, root, convIdx, &msgIdx, visited); err != nil {
			return err
		}
	}
	return nil
}

func walkChatgptNode(sink ImportSink, conv chatgptConversation, nodeID string, convIdx int, msgIdx *int, visited map[string]bool) error {
	if visited[nodeID] {
		return nil // cycle guard (mappings are trees, but never trust the source)
	}
	visited[nodeID] = true

	node, ok := conv.Mapping[nodeID]
	if !ok {
		return nil
	}

	if len(node.Message) > 0 && string(node.Message) != "null" {
		if err := emitMessage(sink, conv, node, convIdx, *msgIdx); err != nil {
			return err
		}
		*msgIdx++
	}

	for _, child := range node.Children {
		if err := walkChatgptNode(sink, conv, child, convIdx, msgIdx, visited); err != nil {
			return err
		}
	}
	return nil
}

func emitMessage(sink ImportSink, conv chatgptConversation, node chatgptNode, convIdx, msgIdx int) error {
	var msg chatgptMessage
	if err := json.Unmarshal(node.Message, &msg); err != nil {
		return sink.Reject(
			fmt.Sprintf("conversation %d node %s", convIdx, node.ID),
			"invalid message object: "+err.Error(),
			node.Message, true,
		)
	}

	content := chatgptContentText(msg.Content)
	if strings.TrimSpace(content) == "" {
		// System/empty nodes carry no human content — skip without rejecting (not a defect).
		return nil
	}

	rec := &SourceRecord{
		Kind:      "message",
		SourcePos: fmt.Sprintf("conversation %d, message %d (node %s)", convIdx, msgIdx, node.ID),
		Raw:       node.Message, // exact raw message bytes = H2 input, never reformatted
		RawCanon:  "h2-rawrecord-v1",
		RawSize:   int64(len(node.Message)),
		Content:   content,
		Metadata: map[string]interface{}{
			"source_format":      chatgptJSONFormat,
			"conversation_title": conv.Title,
			"conversation_id":    conv.ConversationID,
			"conversation_index": convIdx,
			"message_index":      msgIdx,
			"node_id":            node.ID,
			"message_id":         msg.ID,
			"role":               msg.Author.Role,
		},
	}
	if msg.Author.Role != "" {
		rec.Participants = []string{msg.Author.Role}
	}
	if t := unixFloatTime(msg.CreateTime); t != nil {
		rec.OccurredAt = t
	} else if t := unixFloatTime(conv.CreateTime); t != nil {
		rec.OccurredAt = t
	}
	return sink.Record(rec)
}

// chatgptContentText flattens a ChatGPT message "content" object to text. The common case
// is {"content_type":"text","parts":["...","..."]}; parts may be strings or objects (image
// refs etc.), so non-string parts are skipped rather than stringified lossily into content.
func chatgptContentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var c struct {
		Parts []json.RawMessage `json:"parts"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range c.Parts {
		var s string
		if err := json.Unmarshal(p, &s); err == nil && s != "" {
			if b.Len() > 0 {
				b.WriteString("\n")
			}
			b.WriteString(s)
		}
	}
	return b.String()
}

func unixFloatTime(v *float64) *time.Time {
	if v == nil || *v <= 0 {
		return nil
	}
	sec := int64(*v)
	nsec := int64((*v - float64(sec)) * 1e9)
	t := time.Unix(sec, nsec).UTC()
	return &t
}

// sortStrings is a tiny in-place sort (avoids importing "sort" for one call site).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func init() { RegisterImporter(chatgptJSONImporter{}) }
