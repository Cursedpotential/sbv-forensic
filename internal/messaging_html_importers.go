package internal

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/net/html"
)

type imessageHTMLImporter struct{}
type facebookHTMLImporter struct{}

func (imessageHTMLImporter) Format() string { return FormatIMessageHTML }
func (imessageHTMLImporter) Priority() int  { return 640 }
func (imessageHTMLImporter) Detect(head []byte, filename string) bool {
	if !htmlExtension(filename) {
		return false
	}
	s := strings.ToLower(string(head))
	stock := strings.Contains(s, `class="message`) &&
		(strings.Contains(s, `class="sent`) || strings.Contains(s, `class="received`)) &&
		(strings.Contains(s, `class="timestamp`) || strings.Contains(s, `class="sender`))
	owner := strings.Contains(s, `class="bubble from-me`) || strings.Contains(s, `class="bubble from-them`)
	return stock || owner
}
func (imessageHTMLImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runHTMLRecords(sink, r, "imessage")
}

func (facebookHTMLImporter) Format() string { return FormatFacebookHTML }
func (facebookHTMLImporter) Priority() int  { return 630 }
func (facebookHTMLImporter) Detect(head []byte, filename string) bool {
	if !htmlExtension(filename) {
		return false
	}
	s := strings.ToLower(string(head))
	if strings.Contains(s, `_a6-g`) && strings.Contains(s, `_a6-h`) {
		return true
	}
	return strings.Contains(s, `class="message`) && strings.Contains(s, `class="meta`) &&
		!strings.Contains(s, `class="sent`) && !strings.Contains(s, `class="received`)
}
func (facebookHTMLImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runHTMLRecords(sink, r, "facebook")
}

func htmlExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".html" || ext == ".htm"
}

type htmlCapture struct {
	raw      []byte
	pos      string
	depth    int
	linger   bool
	overflow bool
}

// runHTMLRecords tokenizes the document incrementally and builds at most one
// bounded logical message fragment. It never constructs a whole-file DOM and
// never resolves src/href resources. Owner-custom iMessage bubbles and Facebook
// cards linger through their following metadata/attachment sibling.
func runHTMLRecords(sink ImportSink, r io.Reader, platform string) error {
	z := html.NewTokenizer(r)
	var current *htmlCapture
	recordNo := 0
	flush := func() error {
		if current == nil {
			return nil
		}
		recordNo++
		if current.overflow {
			return sink.Reject(current.pos, "HTML logical record exceeds size bound", current.raw, false)
		}
		rec, err := projectHTMLRecord(current.raw, current.pos, platform)
		if err != nil {
			return sink.Reject(current.pos, err.Error(), current.raw, true)
		}
		return sink.Record(rec)
	}

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if err := z.Err(); err != nil && err != io.EOF {
				return fmt.Errorf("tokenize HTML: %w", err)
			}
			return flush()
		}
		raw := append([]byte(nil), z.Raw()...)
		tok := z.Token()
		isTarget, linger := htmlRecordStart(tok, tt, platform)
		if current != nil && current.linger && current.depth == 0 && isTarget {
			if err := flush(); err != nil {
				return err
			}
			current = nil
		}
		if current == nil && isTarget {
			current = &htmlCapture{pos: fmt.Sprintf("html-record:%d", recordNo+1), linger: linger}
		}
		if current == nil {
			continue
		}
		if !current.overflow {
			if len(current.raw)+len(raw) > maxRawRecordBytes {
				remaining := maxRawRecordBytes - len(current.raw)
				if remaining > 0 {
					current.raw = append(current.raw, raw[:remaining]...)
				}
				current.overflow = true
			} else {
				current.raw = append(current.raw, raw...)
			}
		}
		switch tt {
		case html.StartTagToken:
			current.depth++
		case html.EndTagToken:
			if current.depth > 0 {
				current.depth--
			}
		}
		if current.depth == 0 && !current.linger {
			if err := flush(); err != nil {
				return err
			}
			current = nil
		}
	}
}

func htmlRecordStart(tok html.Token, tt html.TokenType, platform string) (bool, bool) {
	if tt != html.StartTagToken || tok.Data != "div" {
		return false, false
	}
	classes := tokenClassSet(tok)
	if platform == "google-voice" {
		return classes["message"] || classes["haudio"], false
	}
	if platform == "facebook" {
		if classes["_a6-g"] {
			return true, true
		}
		return classes["message"], false
	}
	if classes["bubble"] && (classes["from-me"] || classes["from-them"]) {
		return true, true
	}
	return classes["message"] || classes["announcement"], false
}

func projectHTMLRecord(raw []byte, pos, platform string) (*SourceRecord, error) {
	root, err := html.Parse(bytes.NewReader(raw))
	if err != nil || root == nil {
		return nil, fmt.Errorf("invalid HTML record")
	}
	if platform == "facebook" {
		return projectFacebookHTML(root, raw, pos)
	}
	if platform == "google-voice" {
		return projectGoogleVoiceHTML(root, raw, pos)
	}
	return projectIMessageHTML(root, raw, pos)
}

func projectFacebookHTML(root *html.Node, raw []byte, pos string) (*SourceRecord, error) {
	sender, content, timestamp, layout := "", "", "", "legacy"
	if card := findNodeClass(root, "_a6-g"); card != nil {
		layout = "card"
		sender = nodeText(findNodeClass(card, "_a6-h"))
		content = nodeText(findNodeClass(card, "_a6-p"))
		timestamp = nodeText(findNodeClass(root, "_a72d"))
	} else if message := findNodeClass(root, "message"); message != nil {
		meta := nodeText(findNodeClass(message, "meta"))
		content = nodeText(findFirstTag(message, "p"))
		sender, timestamp = splitSenderTimestamp(meta)
	}
	attachmentMetadata, attachmentRefs := collectAttachmentLinks(root, "facebook")
	if content == "" && len(attachmentRefs) > 0 {
		content = fmt.Sprintf("[%d attachment(s)]", len(attachmentRefs))
	}
	if sender == "" || content == "" {
		return nil, fmt.Errorf("Facebook message missing sender or content/attachment")
	}
	role, direction := sender, "inbound"
	if strings.EqualFold(sender, "me") || strings.EqualFold(sender, "you") {
		direction = "outbound"
	}
	metadata := map[string]interface{}{
		"platform": "facebook", "format": "html", "layout": layout,
		"direction": direction, "sender_label": sender, "raw_timestamp": timestamp,
		"msg_type": facebookMessageType(content), "attachments": attachmentMetadata,
	}
	return &SourceRecord{Kind: KindMessage, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		OccurredAt: parseMessagingTime(timestamp), Participants: uniqueStrings(role), Content: content,
		Metadata: metadata, AttachmentReferences: attachmentRefs}, nil
}

func projectIMessageHTML(root *html.Node, raw []byte, pos string) (*SourceRecord, error) {
	if bubble := findNodeClass(root, "bubble"); bubble != nil && (hasNodeClass(bubble, "from-me") || hasNodeClass(bubble, "from-them")) {
		outbound := hasNodeClass(bubble, "from-me")
		content := nodeText(bubble)
		meta := nodeText(findNodeClass(root, "meta"))
		sender, timestamp := splitSenderTimestamp(meta)
		if sender == "" {
			if outbound {
				sender = "Me"
			} else {
				sender = "Unknown"
			}
		}
		attachments, attachmentRefs := collectAttachmentLinks(root, "imessage")
		if content == "" && len(attachments) > 0 {
			content = fmt.Sprintf("[%d attachment(s)]", len(attachments))
		}
		role, direction := sender, "inbound"
		if outbound {
			role, direction = ownerRole, "outbound"
		}
		return &SourceRecord{Kind: classifyMessageContent(content), SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
			OccurredAt: parseMessagingTime(timestamp), Participants: uniqueStrings(ownerRole, role), Content: content,
			Metadata: map[string]interface{}{"platform": "imessage", "format": "html", "variant": "owner-custom",
				"direction": direction, "sender_label": sender, "raw_timestamp": timestamp, "attachments": attachments},
			AttachmentReferences: attachmentRefs}, nil
	}
	if ann := findNodeClass(root, "announcement"); ann != nil {
		timestamp := nodeText(findNodeClass(ann, "timestamp"))
		content := strings.TrimSpace(strings.TrimPrefix(nodeText(ann), timestamp))
		return &SourceRecord{Kind: "event", SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
			OccurredAt: parseMessagingTime(timestamp), Content: content,
			Metadata: map[string]interface{}{"platform": "imessage", "format": "html", "kind": "announcement", "raw_timestamp": timestamp}}, nil
	}
	message := findNodeClass(root, "message")
	if message == nil {
		return nil, fmt.Errorf("iMessage record missing message container")
	}
	inner := findNodeClass(message, "sent")
	outbound := inner != nil
	if inner == nil {
		inner = findNodeClass(message, "received")
	}
	if inner == nil {
		return nil, fmt.Errorf("iMessage message missing sent/received container")
	}
	timestamp := nodeText(findNodeClass(inner, "timestamp"))
	sender := nodeText(findNodeClass(inner, "sender"))
	if sender == "" {
		if outbound {
			sender = "Me"
		} else {
			sender = "Unknown"
		}
	}
	parts := findNodesClass(inner, "bubble")
	texts := make([]string, 0, len(parts))
	for _, part := range parts {
		if text := nodeText(part); text != "" {
			texts = append(texts, text)
		}
	}
	content := strings.Join(texts, "\n")
	attachments, attachmentRefs := collectAttachmentLinks(inner, "imessage")
	if content == "" && len(attachments) > 0 {
		content = fmt.Sprintf("[%d attachment(s)]", len(attachments))
	}
	role, direction := sender, "inbound"
	if outbound {
		role, direction = ownerRole, "outbound"
	}
	return &SourceRecord{Kind: classifyMessageContent(content), SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		OccurredAt: parseMessagingTime(timestamp), Participants: uniqueStrings(ownerRole, role), Content: content,
		Metadata: map[string]interface{}{"platform": "imessage", "format": "html", "direction": direction,
			"sender_label": sender, "raw_timestamp": timestamp, "attachments": attachments},
		AttachmentReferences: attachmentRefs}, nil
}

func tokenClassSet(tok html.Token) map[string]bool {
	out := make(map[string]bool)
	for _, attr := range tok.Attr {
		if attr.Key == "class" {
			for _, class := range strings.Fields(attr.Val) {
				out[class] = true
			}
		}
	}
	return out
}

func hasNodeClass(node *html.Node, class string) bool {
	if node == nil {
		return false
	}
	for _, attr := range node.Attr {
		if attr.Key == "class" {
			for _, candidate := range strings.Fields(attr.Val) {
				if candidate == class {
					return true
				}
			}
		}
	}
	return false
}

func findNodeClass(root *html.Node, class string) *html.Node {
	if root == nil {
		return nil
	}
	if hasNodeClass(root, class) {
		return root
	}
	for child := root.FirstChild; child != nil; child = child.NextSibling {
		if found := findNodeClass(child, class); found != nil {
			return found
		}
	}
	return nil
}

func findNodesClass(root *html.Node, class string) []*html.Node {
	out := make([]*html.Node, 0)
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if hasNodeClass(node, class) {
			out = append(out, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return out
}

func findFirstTag(root *html.Node, tag string) *html.Node {
	if root == nil {
		return nil
	}
	if root.Type == html.ElementNode && root.Data == tag {
		return root
	}
	for child := root.FirstChild; child != nil; child = child.NextSibling {
		if found := findFirstTag(child, tag); found != nil {
			return found
		}
	}
	return nil
}

func nodeText(root *html.Node) string {
	if root == nil {
		return ""
	}
	parts := make([]string, 0)
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			if text := strings.TrimSpace(node.Data); text != "" {
				parts = append(parts, text)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return strings.Join(parts, " ")
}

func splitSenderTimestamp(meta string) (string, string) {
	for _, sep := range []string{" - ", " – ", " — "} {
		if i := strings.LastIndex(meta, sep); i > 0 {
			return strings.TrimSpace(meta[:i]), strings.TrimSpace(meta[i+len(sep):])
		}
	}
	return "", ""
}

func collectAttachmentLinks(root *html.Node, platform string) ([]map[string]interface{}, []AttachmentReference) {
	out := make([]map[string]interface{}, 0)
	refs := make([]AttachmentReference, 0)
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			uri := ""
			for _, attr := range node.Attr {
				if attr.Key == "href" || attr.Key == "src" {
					uri = attr.Val
				}
			}
			if uri != "" && (hasNodeClass(node, "attachment") || hasNodeClass(node, "attachment-link") ||
				node.Data == "img" || node.Data == "video" || node.Data == "audio") {
				ref := newAttachmentReference(node.Data, uri, nodeText(node))
				if platform == "imessage" {
					ref = newIMessageAttachmentReference(node.Data, uri, nodeText(node))
				}
				out = append(out, attachmentReferenceMetadata(ref))
				refs = append(refs, ref)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return out, refs
}

func classifyMessageContent(content string) string {
	lower := strings.ToLower(content)
	if strings.Contains(lower, "call") && (strings.Contains(lower, "facetime") || strings.Contains(lower, "missed") || strings.Contains(lower, "incoming") || strings.Contains(lower, "outgoing")) {
		return KindCall
	}
	return KindMessage
}

func facebookMessageType(content string) string {
	lower := strings.ToLower(content)
	for _, marker := range []string{"sent a photo", "sent a video", "sent an attachment", "shared a file"} {
		if strings.Contains(lower, marker) {
			return "media"
		}
	}
	for _, marker := range []string{"shared a link", "sent a post", "shared a post"} {
		if strings.Contains(lower, marker) {
			return "share"
		}
	}
	return "text"
}

func init() {
	RegisterImporter(imessageHTMLImporter{})
	RegisterImporter(facebookHTMLImporter{})
}
