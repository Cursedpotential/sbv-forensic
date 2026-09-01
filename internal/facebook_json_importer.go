package internal

// Byline amendment: Codex · GPT-5 · 2026-08-18 (combined-change hygiene).

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxFacebookContextBytes = 16 << 20

type facebookJSONImporter struct{}

func (facebookJSONImporter) Format() string { return FormatFacebookJSON }
func (facebookJSONImporter) Priority() int  { return 815 }

var facebookMessageFilenameRE = regexp.MustCompile(`(?i)^message_[0-9]+\.json$`)

func (facebookJSONImporter) Detect(head []byte, filename string) bool {
	if !strings.EqualFold(filepath.Ext(filename), ".json") {
		return false
	}
	s := strings.ToLower(string(head))
	hasParticipants := strings.Contains(s, `"participants"`)
	top := hasParticipants &&
		(strings.Contains(s, `"messages"`) || strings.Contains(s, `"title"`) || strings.Contains(s, `"thread_path"`))
	messageShape := strings.Contains(s, `"sender_name"`) && strings.Contains(s, `"timestamp_ms"`)
	// message_N.json is Meta's stable thread filename. It permits bounded deep
	// validation in Run when an unusually large participants roster pushes the
	// first message beyond the detection peek. Arbitrary .json still requires
	// the complete top-level + message signature in the peek.
	if facebookMessageFilenameRE.MatchString(filepath.Base(filename)) {
		return hasParticipants
	}
	return top && messageShape
}

func (facebookJSONImporter) Run(sink ImportSink, r *bufio.Reader) error {
	return runFacebookJSONImport(sink, r, maxRawRecordBytes)
}

type facebookContext struct {
	raw                 map[string]interface{}
	participants        []string
	participantsDisplay []string
	title               string
	titleDisplay        string
	threadPath          string
	threadPathDisplay   string
	exportOrder         string
}

func runFacebookJSONImport(sink ImportSink, r *bufio.Reader, recordLimit int) (retErr error) {
	prefix, err := seekJSONArrayCapture(r, "messages", maxFacebookContextBytes)
	if err != nil {
		return fmt.Errorf("Facebook context scan: %w", err)
	}
	root, err := sink.ArtifactDir()
	if err != nil {
		return err
	}
	spoolDir := filepath.Join(root, "facebook-spools")
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return err
	}
	spool, err := os.CreateTemp(spoolDir, "messages-*.bin")
	if err != nil {
		return err
	}
	defer func() {
		quarantinedPath, quarantineErr := quarantineFacebookSpool(root, spool)
		if quarantineErr != nil {
			slog.Error("Facebook import spool quarantine failed", "path", spool.Name(), "error", quarantineErr)
			retErr = errors.Join(retErr, quarantineErr)
			return
		}
		slog.Debug("Facebook import spool quarantined", "path", quarantinedPath)
	}()

	recordCount := 0
	overflowCount := 0
	overflowSignatureCount := 0
	signatureSeen := false
	ascending, descending := 0, 0
	var previousTimestamp *int64
	for {
		first, done, err := nextJSONArrayValueStart(r)
		if err != nil {
			return err
		}
		if done {
			break
		}
		if first != '{' {
			return fmt.Errorf("Facebook messages[%d] is not an object", recordCount)
		}
		raw, h2, rawSize, overflow, err := readExactJSONObject(r, first, recordLimit)
		if err != nil {
			return err
		}
		if overflow {
			overflowCount++
			if facebookJSONPrefixHasObjectKeys(raw, "sender_name", "timestamp_ms") {
				overflowSignatureCount++
				signatureSeen = true
			}
		} else {
			var probe map[string]interface{}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&probe); err == nil {
				if facebookMessageHasCredibleSignature(probe) {
					signatureSeen = true
				}
				if value, ok := facebookTimestamp(probe["timestamp_ms"]); ok {
					if previousTimestamp != nil {
						if value > *previousTimestamp {
							ascending++
						} else if value < *previousTimestamp {
							descending++
						}
					}
					previousTimestamp = &value
				}
			}
		}
		if err := writeFacebookSpoolRecord(spool, overflow, rawSize, h2, raw); err != nil {
			return err
		}
		recordCount++
	}

	tail, err := readBoundedRemainder(r, maxFacebookContextBytes-len(prefix))
	if err != nil {
		return fmt.Errorf("Facebook trailing context: %w", err)
	}
	contextBytes := append(append(append([]byte(nil), prefix...), ']'), tail...)
	context, err := parseFacebookContext(contextBytes)
	if err != nil {
		return err
	}
	if !signatureSeen {
		return fmt.Errorf("not a Facebook Messenger export: messages lack sender_name/timestamp_ms signature")
	}
	if overflowCount == recordCount && overflowSignatureCount != overflowCount {
		return fmt.Errorf("not a Facebook Messenger export: oversized messages lack literal sender_name/timestamp_ms keys")
	}
	switch {
	case descending > 0 && ascending == 0:
		context.exportOrder = "reverse_chronological_as_exported"
	case ascending > 0 && descending == 0:
		context.exportOrder = "chronological_as_exported"
	default:
		context.exportOrder = "source_array_order_mixed_or_unknown"
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for sequence := 0; sequence < recordCount; sequence++ {
		overflow, rawSize, h2, raw, err := readFacebookSpoolRecord(spool)
		if err != nil {
			return err
		}
		pos := fmt.Sprintf("messages[%d]", sequence)
		if overflow {
			if err := sink.RejectHashed(pos, "Facebook message exceeds record size bound", h2, RecordHashCanonRawV1, rawSize); err != nil {
				return err
			}
			continue
		}
		rec, err := projectFacebookJSONMessage(raw, pos, sequence, context)
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
	return nil
}

// quarantineFacebookSpool closes the temporary replay spool and moves it under
// the import-local owner-reviewed quarantine on every exit. A uniquely-created
// wrapper directory makes the move collision-safe without deleting or
// overwriting any earlier artifact.
func quarantineFacebookSpool(root string, spool *os.File) (string, error) {
	if spool == nil {
		return "", nil
	}
	path := spool.Name()
	closeErr := spool.Close()
	quarantineRoot := filepath.Join(root, "to_be_deleted")
	if err := os.MkdirAll(quarantineRoot, 0700); err != nil {
		return "", errors.Join(closeErr, fmt.Errorf("create Facebook spool quarantine: %w", err))
	}
	base := filepath.Base(path)
	for sequence := 0; sequence < 10_000; sequence++ {
		dirName := base + ".quarantine"
		if sequence > 0 {
			dirName = fmt.Sprintf("%s.quarantine-%d", base, sequence)
		}
		destinationDir := filepath.Join(quarantineRoot, dirName)
		if err := os.Mkdir(destinationDir, 0700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", errors.Join(closeErr, fmt.Errorf("reserve Facebook spool quarantine path: %w", err))
		}
		destination := filepath.Join(destinationDir, base)
		if err := os.Rename(path, destination); err != nil {
			return "", errors.Join(closeErr, fmt.Errorf("move Facebook spool to quarantine %q: %w", destination, err))
		}
		return destination, closeErr
	}
	return "", errors.Join(closeErr, fmt.Errorf("could not reserve collision-safe Facebook spool quarantine path"))
}

func facebookMessageHasCredibleSignature(obj map[string]interface{}) bool {
	sender := firstString(obj, "sender_name") != ""
	_, timestamp := facebookTimestamp(obj["timestamp_ms"])
	if sender && timestamp {
		return true
	}
	// Meta's explicit membership/admin event types may omit one ordinary
	// message field. Keeping this allowlist narrow avoids claiming arbitrary
	// JSON merely because it contains one familiar-looking property.
	return isFacebookSystemMessageType(firstString(obj, "type")) && (sender || timestamp)
}

func facebookJSONPrefixHasObjectKeys(raw []byte, required ...string) bool {
	wanted := make(map[string]bool, len(required))
	for _, key := range required {
		wanted[key] = false
	}
	inString, escaped := false, false
	stringStart := 0
	objectDepth, arrayDepth := 0, 0
	keyObjectDepth, keyArrayDepth := 0, 0
	for i, b := range raw {
		if !inString {
			switch b {
			case '{':
				objectDepth++
			case '}':
				objectDepth--
			case '[':
				arrayDepth++
			case ']':
				arrayDepth--
			case '"':
				inString = true
				escaped = false
				stringStart = i + 1
				keyObjectDepth = objectDepth
				keyArrayDepth = arrayDepth
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if b == '\\' {
			escaped = true
			continue
		}
		if b != '"' {
			continue
		}
		inString = false
		j := i + 1
		for j < len(raw) && isJSONSpace(raw[j]) {
			j++
		}
		if keyObjectDepth == 1 && keyArrayDepth == 0 && j < len(raw) && raw[j] == ':' {
			key := string(raw[stringStart:i])
			if _, ok := wanted[key]; ok {
				wanted[key] = true
			}
		}
	}
	for _, found := range wanted {
		if !found {
			return false
		}
	}
	return true
}

func seekJSONArrayCapture(r *bufio.Reader, wanted string, limit int) ([]byte, error) {
	captured := make([]byte, 0, 4096)
	inString, escaped := false, false
	var token bytes.Buffer
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("find %s array: %w", wanted, err)
		}
		if len(captured) >= limit {
			return nil, fmt.Errorf("top-level context before %s exceeds %d-byte bound", wanted, limit)
		}
		captured = append(captured, b)
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
					found, err := consumeJSONColonAndArrayCapture(r, &captured, limit)
					if err != nil {
						return nil, err
					}
					if found {
						return captured, nil
					}
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

func consumeJSONColonAndArrayCapture(r *bufio.Reader, captured *[]byte, limit int) (bool, error) {
	colon := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return false, err
		}
		if len(*captured) >= limit {
			return false, fmt.Errorf("top-level JSON context exceeds %d-byte bound", limit)
		}
		*captured = append(*captured, b)
		if isJSONSpace(b) {
			continue
		}
		if !colon {
			if b != ':' {
				return false, nil
			}
			colon = true
			continue
		}
		return b == '[', nil
	}
}

func readBoundedRemainder(r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("top-level context exceeds bound")
	}
	limited := &io.LimitedReader{R: r, N: int64(limit + 1)}
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("top-level context exceeds %d-byte bound", maxFacebookContextBytes)
	}
	return data, nil
}

func writeFacebookSpoolRecord(w io.Writer, overflow bool, rawSize int64, h2 string, raw []byte) error {
	status := byte(0)
	if overflow {
		status = 1
		raw = nil
	}
	hashBytes, err := hex.DecodeString(h2)
	if err != nil || len(hashBytes) != 32 {
		return fmt.Errorf("invalid Facebook spool H2")
	}
	if err := binary.Write(w, binary.LittleEndian, status); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(rawSize)); err != nil {
		return err
	}
	if _, err := w.Write(hashBytes); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint32(len(raw))); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readFacebookSpoolRecord(r io.Reader) (bool, int64, string, []byte, error) {
	var status byte
	if err := binary.Read(r, binary.LittleEndian, &status); err != nil {
		return false, 0, "", nil, err
	}
	var rawSize uint64
	if err := binary.Read(r, binary.LittleEndian, &rawSize); err != nil {
		return false, 0, "", nil, err
	}
	hashBytes := make([]byte, 32)
	if _, err := io.ReadFull(r, hashBytes); err != nil {
		return false, 0, "", nil, err
	}
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return false, 0, "", nil, err
	}
	raw := make([]byte, int(length))
	if _, err := io.ReadFull(r, raw); err != nil {
		return false, 0, "", nil, err
	}
	return status == 1, int64(rawSize), hex.EncodeToString(hashBytes), raw, nil
}

func parseFacebookContext(raw []byte) (facebookContext, error) {
	var obj map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&obj); err != nil {
		return facebookContext{}, fmt.Errorf("invalid Facebook top-level context: %w", err)
	}
	participantsRaw, ok := obj["participants"].([]interface{})
	if !ok {
		return facebookContext{}, fmt.Errorf("not a Facebook Messenger export: participants array missing")
	}
	titleRaw, titlePresent := obj["title"].(string)
	if !titlePresent {
		return facebookContext{}, fmt.Errorf("not a Facebook Messenger export: title missing")
	}
	participants := make([]string, 0, len(participantsRaw))
	participantsDisplay := make([]string, 0, len(participantsRaw))
	for _, value := range participantsRaw {
		participant, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		name := firstString(participant, "name")
		display, _ := reversibleFacebookRepair(name)
		participants = append(participants, name)
		participantsDisplay = append(participantsDisplay, display)
	}
	titleDisplay, _ := reversibleFacebookRepair(titleRaw)
	threadPath := firstString(obj, "thread_path")
	threadPathDisplay, _ := reversibleFacebookRepair(threadPath)
	delete(obj, "messages")
	return facebookContext{raw: obj, participants: uniqueStrings(participants...),
		participantsDisplay: uniqueStrings(participantsDisplay...), title: titleRaw,
		titleDisplay: titleDisplay, threadPath: threadPath, threadPathDisplay: threadPathDisplay}, nil
}

var facebookMediaFields = []struct{ key, kind string }{
	{"photos", "photo"}, {"videos", "video"}, {"audio_files", "audio"},
	{"files", "file"}, {"gifs", "gif"},
}

func projectFacebookJSONMessage(raw []byte, pos string, sequence int, context facebookContext) (*SourceRecord, error) {
	var obj map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid Facebook message object: %w", err)
	}
	senderOriginal := firstString(obj, "sender_name")
	senderDisplay, senderRepaired := reversibleFacebookRepair(senderOriginal)
	contentOriginal := firstString(obj, "content")
	contentDisplay, contentRepaired := reversibleFacebookRepair(contentOriginal)
	messageType := firstString(obj, "type")
	if messageType == "" {
		messageType = "Generic"
	}
	media, mediaRefs := facebookMediaDescriptors(obj)
	sticker, stickerRef := facebookStickerDescriptor(obj)
	attachmentRefs := append([]AttachmentReference(nil), mediaRefs...)
	if stickerRef != nil {
		attachmentRefs = append(attachmentRefs, *stickerRef)
	}
	share := facebookShareDescriptor(obj)
	reactions := facebookReactionDescriptors(obj)
	callDuration, hasCallDuration := obj["call_duration"]
	isCall := strings.EqualFold(messageType, "Call") || hasCallDuration
	isSystem := isFacebookSystemMessageType(messageType)

	content := strings.TrimSpace(contentDisplay)
	switch {
	case content != "":
	case isCall:
		content = facebookCallFallback(callDuration, obj["missed"])
	case len(media) > 0:
		kinds := make([]string, 0, len(media))
		for _, item := range media {
			kinds = append(kinds, fmt.Sprint(item["kind"]))
		}
		content = fmt.Sprintf("[Facebook attachment event: %s]", strings.Join(uniqueStrings(kinds...), ", "))
	case sticker != nil:
		content = "[Facebook sticker event]"
	case len(share) > 0:
		content = strings.TrimSpace(fmt.Sprintf("[Facebook share] %v %v", share["share_text_display"], share["link"]))
	case len(reactions) > 0:
		content = fmt.Sprintf("[Facebook reaction-only event: %d reaction(s)]", len(reactions))
	case isSystem:
		content = fmt.Sprintf("[Facebook system event: %s]", messageType)
	default:
		content = "[Facebook structured message without display text]"
	}

	rawMetadata := metadataJSONSizeSafe(map[string]interface{}{"raw_message": obj, "raw_thread_context": context.raw})
	rawRetained := rawMetadata["projection_truncated"] != true
	metadata := rawMetadata
	metadata["platform"] = "facebook"
	metadata["format"] = "messenger-json"
	metadata["source_sequence"] = sequence
	metadata["export_order"] = context.exportOrder
	metadata["thread_title_original"] = context.title
	metadata["thread_title_display"] = context.titleDisplay
	metadata["thread_path_original"] = context.threadPath
	metadata["thread_path_display"] = context.threadPathDisplay
	metadata["participants_original"] = context.participants
	metadata["participants_display"] = context.participantsDisplay
	metadata["sender_name_original"] = senderOriginal
	metadata["sender_name_display"] = senderDisplay
	metadata["content_original"] = contentOriginal
	metadata["content_display"] = contentDisplay
	metadata["mojibake_repaired"] = senderRepaired || contentRepaired || context.title != context.titleDisplay
	metadata["raw_message_retained"] = rawRetained
	metadata["message_type"] = messageType
	metadata["reactions"] = reactions
	metadata["media"] = media
	metadata["sticker"] = sticker
	metadata["share"] = share
	metadata["call_duration"] = callDuration
	metadata["missed"] = obj["missed"]
	metadata["ip"] = obj["ip"]
	metadata["users"] = obj["users"]
	metadata["is_system_event"] = isSystem
	metadata = metadataJSONSizeSafe(metadata)
	if metadata["projection_truncated"] == true {
		metadata["platform"] = "facebook"
		metadata["format"] = "messenger-json"
		metadata["source_sequence"] = sequence
		metadata["export_order"] = context.exportOrder
		metadata["message_type"] = messageType
		metadata["raw_message_retained"] = false
		metadata["media_count"] = len(media)
		metadata["reaction_count"] = len(reactions)
		metadata["has_sticker"] = sticker != nil
		metadata["has_share"] = len(share) > 0
	}

	kind := KindMessage
	if isCall {
		kind = KindCall
	} else if isSystem {
		kind = "event"
	} else if len(reactions) > 0 && contentOriginal == "" && len(media) == 0 && sticker == nil && len(share) == 0 {
		kind = "reaction"
	}
	participants := append([]string(nil), context.participantsDisplay...)
	participants = append(participants, senderDisplay)
	recipientNames := make([]string, 0, len(participants))
	for _, participant := range uniqueStrings(participants...) {
		if participant != "" && participant != senderDisplay {
			recipientNames = append(recipientNames, participant)
		}
	}
	recipientRole := "to"
	if len(recipientNames) > 1 {
		recipientRole = "group"
	}
	recipients := make([]SourceParty, 0, len(recipientNames))
	for _, participant := range recipientNames {
		recipients = append(recipients, SourceParty{Identity: participant, Role: recipientRole})
	}
	return &SourceRecord{Kind: kind, SourcePos: pos, Raw: raw, RawCanon: RecordHashCanonRawV1,
		RawSize:    int64(len(raw)),
		OccurredAt: firstTime(obj, "timestamp_ms"), Participants: uniqueStrings(participants...),
		Sender: senderDisplay, Recipients: recipients, Content: content,
		Metadata: metadata, AttachmentReferences: attachmentRefs}, nil
}

func facebookTimestamp(value interface{}) (int64, bool) {
	if number, ok := value.(json.Number); ok {
		parsed, err := number.Int64()
		return parsed, err == nil
	}
	return 0, false
}

func isFacebookSystemMessageType(messageType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(messageType))
	normalized = strings.NewReplacer("_", "", "-", "", " ", "").Replace(normalized)
	switch normalized {
	case "subscribe", "unsubscribe", "system", "systemmessage", "admin", "admintext", "adminmessage":
		return true
	default:
		return false
	}
}

func reversibleFacebookRepair(value string) (string, bool) {
	if value == "" {
		return value, false
	}
	var out strings.Builder
	latinRunes := make([]rune, 0, len(value))
	changed := false
	flush := func() {
		if len(latinRunes) == 0 {
			return
		}
		original := string(latinRunes)
		latin1 := make([]byte, len(latinRunes))
		for i, r := range latinRunes {
			latin1[i] = byte(r)
		}
		repaired := string(latin1)
		var reversed strings.Builder
		for _, b := range []byte(repaired) {
			reversed.WriteRune(rune(b))
		}
		if utf8.Valid(latin1) && repaired != original && reversed.String() == original {
			out.WriteString(repaired)
			changed = true
		} else {
			out.WriteString(original)
		}
		latinRunes = latinRunes[:0]
	}
	for _, r := range value {
		if r <= 255 {
			latinRunes = append(latinRunes, r)
			continue
		}
		flush()
		out.WriteRune(r)
	}
	flush()
	if !changed {
		return value, false
	}
	return out.String(), true
}

func facebookMediaDescriptors(obj map[string]interface{}) ([]map[string]interface{}, []AttachmentReference) {
	out := make([]map[string]interface{}, 0)
	refs := make([]AttachmentReference, 0)
	for _, field := range facebookMediaFields {
		items, ok := obj[field.key].([]interface{})
		if !ok {
			continue
		}
		for _, value := range items {
			entry, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			descriptor, ref := facebookCompanionDescriptor(field.kind, entry)
			out = append(out, descriptor)
			refs = append(refs, ref)
		}
	}
	return out, refs
}

func facebookStickerDescriptor(obj map[string]interface{}) (map[string]interface{}, *AttachmentReference) {
	entry, ok := obj["sticker"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	descriptor, ref := facebookCompanionDescriptor("sticker", entry)
	return descriptor, &ref
}

func facebookCompanionDescriptor(kind string, entry map[string]interface{}) (map[string]interface{}, AttachmentReference) {
	original := firstString(entry, "uri")
	ref := newAttachmentReference(kind, original, "", "your_facebook_activity/messages", "messages")
	descriptor := attachmentReferenceMetadata(ref)
	descriptor["creation_timestamp"] = entry["creation_timestamp"]
	return descriptor, ref
}

func facebookReactionDescriptors(obj map[string]interface{}) []map[string]interface{} {
	items, _ := obj["reactions"].([]interface{})
	out := make([]map[string]interface{}, 0, len(items))
	for _, value := range items {
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		reactionOriginal := firstString(entry, "reaction")
		actorOriginal := firstString(entry, "actor")
		reactionDisplay, _ := reversibleFacebookRepair(reactionOriginal)
		actorDisplay, _ := reversibleFacebookRepair(actorOriginal)
		out = append(out, map[string]interface{}{"reaction_original": reactionOriginal,
			"reaction_display": reactionDisplay, "actor_original": actorOriginal, "actor_display": actorDisplay})
	}
	return out
}

func facebookShareDescriptor(obj map[string]interface{}) map[string]interface{} {
	share, ok := obj["share"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	textOriginal := firstString(share, "share_text")
	textDisplay, _ := reversibleFacebookRepair(textOriginal)
	ownerOriginal := firstString(share, "original_content_owner")
	ownerDisplay, _ := reversibleFacebookRepair(ownerOriginal)
	return map[string]interface{}{"link": firstString(share, "link"),
		"share_text_original": textOriginal, "share_text_display": textDisplay,
		"original_content_owner_original": ownerOriginal, "original_content_owner_display": ownerDisplay}
}

func facebookCallFallback(duration, missed interface{}) string {
	label := "Facebook call"
	if value, ok := missed.(bool); ok && value {
		label = "Missed Facebook call"
	}
	if duration != nil {
		return fmt.Sprintf("[%s: %v seconds]", label, duration)
	}
	return "[" + label + "]"
}

func init() { RegisterImporter(facebookJSONImporter{}) }
