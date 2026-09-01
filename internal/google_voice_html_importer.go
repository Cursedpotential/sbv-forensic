package internal

// Byline amendment: Codex · GPT-5 · 2026-08-18 (combined-change hygiene).

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type googleVoiceHTMLImporter struct{}

func (googleVoiceHTMLImporter) Format() string { return FormatGoogleVoice }
func (googleVoiceHTMLImporter) Priority() int  { return 850 }
func (googleVoiceHTMLImporter) Detect(head []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".html" && ext != ".htm" {
		return false
	}
	s := strings.ToLower(string(head))
	container := strings.Contains(s, "hchatlog") || strings.Contains(s, "hfeed")
	record := strings.Contains(s, "haudio") ||
		(strings.Contains(s, "message") && (strings.Contains(s, "tel:") || strings.Contains(s, "class=\"dt") || strings.Contains(s, "class='dt")))
	return container && record
}
func (googleVoiceHTMLImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runHTMLRecords(sink, r, "google-voice")
}

func projectGoogleVoiceHTML(root *html.Node, raw []byte, pos string) (*SourceRecord, error) {
	record := findNodeClass(root, "haudio")
	kind := KindMessage
	if record == nil {
		record = findNodeClass(root, "message")
	}
	if record == nil {
		return nil, fmt.Errorf("Google Voice record missing message/haudio container")
	}

	timestamp := firstNodeAttribute(record, []string{"dt", "published", "timestamp"}, []string{"title", "datetime"})
	if timestamp == "" {
		timestamp = nodeText(firstNodeWithAnyClass(record, "dt", "published", "timestamp"))
	}
	contactNode := firstNodeWithAnyClass(record, "sender", "vcard", "fn", "contact")
	contact := nodeText(contactNode)
	tel := firstLinkValue(record, "tel:")
	if contact == "" {
		contact = tel
	}

	transcript := nodeText(firstNodeWithAnyClass(record, "transcript", "description"))
	body := nodeText(findFirstTag(record, "q"))
	if body == "" {
		body = transcript
	}
	duration := nodeText(firstNodeWithAnyClass(record, "duration"))
	labels := collectNodeTextsByClass(record, "label", "category", "tag")
	audioRefs, attachmentRefs := collectGoogleVoiceAudioRefs(record)
	allText := strings.ToLower(nodeText(record) + " " + strings.Join(labels, " "))
	if record == findNodeClass(root, "haudio") {
		if strings.Contains(allText, "voicemail") || transcript != "" {
			kind = KindVoicemail
		} else {
			kind = KindCall
		}
	} else if strings.Contains(allText, "voicemail") {
		kind = KindVoicemail
	} else if strings.Contains(allText, "call") && body == "" {
		kind = KindCall
	}
	if body == "" {
		body = strings.TrimSpace(nodeText(record))
	}
	if body == "" && len(audioRefs) == 0 {
		return nil, fmt.Errorf("Google Voice record has no message, transcript, or audio reference")
	}
	direction := googleVoiceDirection(record, allText)
	sender := ""
	recipients := []SourceParty(nil)
	if direction == "inbound" {
		sender = contact
		recipients = []SourceParty{{Identity: "self", Role: "to"}}
	} else if direction == "outbound" {
		sender = "self"
		if contact != "" {
			recipients = []SourceParty{{Identity: contact, Role: "to"}}
		}
	}
	metadata := map[string]interface{}{
		"platform": "google_voice", "format": "html", "direction": direction,
		"contact_label": contact, "telephone": tel, "raw_timestamp": timestamp,
		"duration": duration, "labels": labels, "transcript": transcript,
		"audio_attachments": audioRefs,
	}
	return &SourceRecord{
		Kind: kind, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		OccurredAt: parseMessagingTime(timestamp), Participants: uniqueStrings(contact, tel),
		Sender: sender, Recipients: recipients, Content: body,
		Metadata: metadata, AttachmentReferences: attachmentRefs,
	}, nil
}

func firstNodeWithAnyClass(root *html.Node, classes ...string) *html.Node {
	for _, class := range classes {
		if node := findNodeClass(root, class); node != nil {
			return node
		}
	}
	return nil
}

func firstNodeAttribute(root *html.Node, classes, attributes []string) string {
	for _, class := range classes {
		if node := findNodeClass(root, class); node != nil {
			for _, wanted := range attributes {
				for _, attr := range node.Attr {
					if attr.Key == wanted && strings.TrimSpace(attr.Val) != "" {
						return strings.TrimSpace(attr.Val)
					}
				}
			}
		}
	}
	return ""
}

func firstLinkValue(root *html.Node, prefix string) string {
	if root == nil {
		return ""
	}
	if root.Type == html.ElementNode && root.Data == "a" {
		for _, attr := range root.Attr {
			if attr.Key == "href" && strings.HasPrefix(strings.ToLower(attr.Val), prefix) {
				return strings.TrimSpace(attr.Val[len(prefix):])
			}
		}
	}
	for child := root.FirstChild; child != nil; child = child.NextSibling {
		if value := firstLinkValue(child, prefix); value != "" {
			return value
		}
	}
	return ""
}

func collectNodeTextsByClass(root *html.Node, classes ...string) []string {
	values := make([]string, 0)
	for _, class := range classes {
		for _, node := range findNodesClass(root, class) {
			if value := nodeText(node); value != "" {
				values = append(values, value)
			}
		}
	}
	return uniqueStrings(values...)
}

func collectGoogleVoiceAudioRefs(root *html.Node) ([]map[string]interface{}, []AttachmentReference) {
	out := make([]map[string]interface{}, 0)
	refs := make([]AttachmentReference, 0)
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "audio" || node.Data == "a") {
			uri := ""
			for _, attr := range node.Attr {
				if attr.Key == "href" || attr.Key == "src" {
					uri = strings.TrimSpace(attr.Val)
				}
			}
			lower := strings.ToLower(uri)
			if uri != "" && (node.Data == "audio" || hasNodeClass(node, "audio") ||
				strings.HasSuffix(lower, ".mp3") || strings.HasSuffix(lower, ".wav") || strings.HasSuffix(lower, ".ogg")) {
				ref := newAttachmentReference("audio", uri, nodeText(node))
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

var googleVoiceDirectionRE = regexp.MustCompile(`(?i)\b(incoming|outgoing|received|placed|sent)\b`)

func googleVoiceDirection(record *html.Node, text string) string {
	if hasNodeClass(record, "outgoing") || strings.Contains(text, "outgoing") || strings.Contains(text, "placed") || strings.Contains(text, "sent") {
		return "outbound"
	}
	if hasNodeClass(record, "incoming") || strings.Contains(text, "incoming") || strings.Contains(text, "received") {
		return "inbound"
	}
	if googleVoiceDirectionRE.MatchString(text) {
		return "unknown"
	}
	return "unknown"
}

func init() { RegisterImporter(googleVoiceHTMLImporter{}) }
