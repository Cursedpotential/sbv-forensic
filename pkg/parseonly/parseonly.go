// Package parseonly exposes SBV's importer decoders without exposing SBV's
// scheduler, SQLite engine, hashing, normalization, or custody side effects.
// It is intentionally a narrow facade for platform-owned adapters.
package parseonly

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lowcarbdev/sbv/internal"
)

// Canonical platform format identifiers. The values deliberately use the
// platform's snake_case convention instead of SBV's legacy hyphenated names.
const (
	FormatSMSBackupXML = "smsbackuprestore_xml"
	FormatNDJSON       = "ndjson"
	FormatCSV          = "csv"
	FormatTranscript   = "messages_transcript"
	FormatIMessageTXT  = "imessage_txt"
	FormatIMessageHTML = "imessage_html"
	FormatFacebookHTML = "facebook_messenger_html"
	FormatGoogleVoice  = "google_voice_html"
	FormatEML          = "email_eml"
	FormatMBOX         = "email_mbox"
	FormatGoogleChat   = "google_chat_json"
	FormatFacebookJSON = "facebook_messenger_json"
	FormatChatGPTJSON  = "chatgpt_official_json"
)

type formatMapping struct {
	Canonical string
	SBV       string
}

var formatMappings = []formatMapping{
	{FormatSMSBackupXML, internal.FormatSMSBackupXML},
	{FormatNDJSON, internal.FormatNDJSON},
	{FormatCSV, internal.FormatCSV},
	{FormatTranscript, internal.FormatTranscript},
	{FormatIMessageTXT, internal.FormatIMessageTXT},
	{FormatIMessageHTML, internal.FormatIMessageHTML},
	{FormatFacebookHTML, internal.FormatFacebookHTML},
	{FormatGoogleVoice, internal.FormatGoogleVoice},
	{FormatEML, internal.FormatEML},
	{FormatMBOX, internal.FormatMBOX},
	{FormatGoogleChat, internal.FormatGoogleChat},
	{FormatFacebookJSON, internal.FormatFacebookJSON},
	{FormatChatGPTJSON, "chatgpt-official-json"},
}

// Formats returns every explicitly mapped SBV format in canonical platform
// spelling. Email importers remain mapped for inventory/documentation, but
// New rejects them because their importer contract only returns streamed hashes
// and does not expose exact record bytes through SourceRecord.Raw.
func Formats() []string {
	formats := make([]string, 0, len(formatMappings))
	for _, mapping := range formatMappings {
		formats = append(formats, mapping.Canonical)
	}
	return formats
}

// Importer is a parse-only facade around one registered SBV importer.
type Importer struct {
	canonical string
	inner     internal.Importer
}

// ArtifactKind distinguishes an exact streamed source record from one decoded
// child attachment. Both remain parse outputs; neither is evidence custody.
type ArtifactKind string

const (
	ArtifactRawRecord  ArtifactKind = "raw_record"
	ArtifactAttachment ArtifactKind = "attachment"
)

// Artifact is a source-scoped, file-backed parse output offered to a
// caller-owned immutable sink. The sink must consume StagedPath synchronously
// and mint a stable locator plus its independently calculated SHA-256 digest.
type Artifact struct {
	Kind              ArtifactKind
	SourceAssociation string
	AttemptID         string
	ParentSourcePos   string
	AttachmentOrdinal uint64
	OriginalName      string
	MIME              string
	StagedPath        string
	ByteCount         int64
}

// ArtifactRegistration is the governed registration request for a fully
// published and verified parse output.
type ArtifactRegistration struct {
	Artifact
	ObjectURI    string
	DigestSHA256 string
}

// ArtifactLocator is storage-neutral so the vendored parser does not import
// the platform engine contract. ContentHash is an integrity digest, not an
// H1/H2/H3 custody assertion.
type ArtifactLocator struct {
	StorageClass string
	URI          string
	ContentHash  string
}

// ArtifactRegistrar binds a published object to its retained source version
// before the locator is allowed into a parser bundle.
type ArtifactRegistrar interface {
	RegisterArtifact(context.Context, ArtifactRegistration) (ArtifactLocator, error)
}

// ImmutableArtifactSink owns artifact persistence. ArtifactDir is a private,
// source-scoped staging directory; Store must synchronously persist the exact
// regular file into a write-once location and return its stable locator.
type ImmutableArtifactSink interface {
	ArtifactDir(context.Context, string, string) (string, error)
	Store(context.Context, Artifact) (ArtifactLocator, error)
	CompleteAttempt(context.Context, string, string) error
	QuarantineAttempt(context.Context, string, string, string) error
}

// New resolves one mapped importer. It refuses the email importers because
// their public importer output cannot provide exact raw record bytes required
// by RawRecordEnvelope.
func New(format string) (*Importer, error) {
	canonical := strings.TrimSpace(format)
	for _, mapping := range formatMappings {
		if mapping.Canonical != canonical {
			continue
		}
		if canonical == FormatEML || canonical == FormatMBOX {
			return nil, fmt.Errorf("SBV format %q is excluded: importer only exposes streamed hashes, not exact raw record bytes", canonical)
		}
		inner, ok := internal.ImporterByFormat(mapping.SBV)
		if !ok {
			return nil, fmt.Errorf("SBV importer %q is not registered", mapping.SBV)
		}
		return &Importer{canonical: canonical, inner: inner}, nil
	}
	return nil, fmt.Errorf("unsupported SBV platform format %q", format)
}

// Record is the lossless parse-only projection of an SBV SourceRecord. Raw
// bytes are required for accepted/rejected records; no hash is calculated here.
type Record struct {
	Status               Status
	StatusReason         string
	Kind                 string
	SourcePos            string
	Raw                  []byte
	OccurredAt           *time.Time
	Participants         []string
	Sender               string
	Recipients           []Recipient
	Content              string
	Metadata             map[string]any
	RawLocator           *ArtifactLocator
	Attachments          []Attachment
	AttachmentReferences []AttachmentReference
	AttachmentFailures   []AttachmentFailure
	CapturedAttachments  uint64
}

// Attachment is one losslessly persisted child of a source record.
type Attachment struct {
	AttachmentOrdinal uint64
	SourceAssociation string
	ParentSourcePos   string
	OriginalName      string
	MIME              string
	DigestSHA256      string
	ByteCount         int64
	ConversionStatus  string
	ConversionError   string
	Locator           ArtifactLocator
}

// AttachmentFailure preserves one source part whose payload did not decode.
// Partial decoded bytes never receive a final attachment locator.
type AttachmentFailure struct {
	AttachmentOrdinal uint64 `json:"attachment_ordinal"`
	SourceAssociation string `json:"source_association"`
	ParentSourcePos   string `json:"parent_source_pos"`
	OriginalName      string `json:"original_name,omitempty"`
	MIME              string `json:"mime,omitempty"`
	ConversionStatus  string `json:"conversion_status"`
	ConversionError   string `json:"conversion_error"`
}

// AttachmentReference preserves a source-declared companion pointer when the
// referenced bytes are not present in the parsed source. It is metadata, not
// an immutable attachment locator.
type AttachmentReference struct {
	Kind                  string `json:"kind"`
	URIOriginal           string `json:"uri_original,omitempty"`
	URI                   string `json:"uri,omitempty"`
	DisplayText           string `json:"display_text,omitempty"`
	ResolutionStatus      string `json:"resolution_status"`
	SafeRelative          bool   `json:"safe_relative"`
	SourceReportedMissing bool   `json:"source_reported_missing"`
	ResolvedHash          string `json:"resolved_hash,omitempty"`
}

type Status string

const (
	StatusParsed   Status = "parsed"
	StatusRejected Status = "rejected"
)

type Recipient struct {
	Identity string `json:"identity"`
	Role     string `json:"role"`
}

// Parse runs only the selected decoder and emits records in exact decoder
// order. It does not call SBV's engine, write SQLite, hash, normalize, or grant
// authority. SBV has one generic Reject callback, so rejects are represented as
// rejected; malformed/unparsed distinctions are never guessed. A reject with
// incomplete bytes or a RejectHashed callback fails closed because it cannot
// satisfy the platform raw-span contract.
func (i *Importer) Parse(ctx context.Context, source io.Reader, emit func(context.Context, Record) error) error {
	return i.parse(ctx, source, "", "", nil, emit)
}

// ParseWithArtifacts runs the decoder with a caller-owned immutable artifact
// sink. sourceAssociation must identify the exact retained source version.
func (i *Importer) ParseWithArtifacts(ctx context.Context, source io.Reader, sourceAssociation string, artifacts ImmutableArtifactSink, emit func(context.Context, Record) error) error {
	if strings.TrimSpace(sourceAssociation) == "" {
		return errors.New("parse-only SBV artifact parsing requires a source association")
	}
	if artifacts == nil {
		return errors.New("parse-only SBV artifact parsing requires an immutable artifact sink")
	}
	attemptID, err := newAttemptID()
	if err != nil {
		return err
	}
	return i.parse(ctx, source, sourceAssociation, attemptID, artifacts, emit)
}

func (i *Importer) parse(ctx context.Context, source io.Reader, sourceAssociation, attemptID string, artifacts ImmutableArtifactSink, emit func(context.Context, Record) error) error {
	if i == nil || i.inner == nil {
		return errors.New("parse-only SBV importer is nil")
	}
	if source == nil {
		return errors.New("parse-only SBV importer requires a source reader")
	}
	if emit == nil {
		return errors.New("parse-only SBV importer requires an emit callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sink := &parseSink{ctx: ctx, emit: emit, sourceAssociation: sourceAssociation, attemptID: attemptID, artifacts: artifacts}
	if err := i.inner.Run(sink, bufio.NewReader(&contextReader{ctx: ctx, source: source})); err != nil {
		parseErr := fmt.Errorf("SBV %s parse: %w", i.canonical, err)
		if artifacts != nil {
			if quarantineErr := quarantineAttempt(ctx, artifacts, sourceAssociation, attemptID, parseErr.Error()); quarantineErr != nil {
				return errors.Join(parseErr, quarantineErr)
			}
		}
		return parseErr
	}
	if artifacts != nil {
		if sink.quarantine {
			if err := quarantineAttempt(ctx, artifacts, sourceAssociation, attemptID, "attachment decode failure"); err != nil {
				return err
			}
		} else if err := artifacts.CompleteAttempt(ctx, sourceAssociation, attemptID); err != nil {
			_ = quarantineAttempt(ctx, artifacts, sourceAssociation, attemptID, "attempt completion failed: "+err.Error())
			return fmt.Errorf("complete SBV artifact attempt: %w", err)
		}
	}
	return ctx.Err()
}

func newAttemptID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create SBV parse attempt identity: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func quarantineAttempt(ctx context.Context, artifacts ImmutableArtifactSink, sourceAssociation, attemptID, reason string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := artifacts.QuarantineAttempt(cleanup, sourceAssociation, attemptID, reason); err != nil {
		return fmt.Errorf("quarantine SBV artifact attempt: %w", err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.source.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

type parseSink struct {
	ctx               context.Context
	emit              func(context.Context, Record) error
	sourceAssociation string
	attemptID         string
	artifacts         ImmutableArtifactSink
	artifactDir       string
	quarantine        bool
}

func (s *parseSink) ImportID() int64 { return 0 }

func (s *parseSink) ArtifactDir() (string, error) {
	if s.artifacts == nil {
		return "", errors.New("SBV record requires an immutable artifact sink")
	}
	if s.artifactDir != "" {
		return s.artifactDir, nil
	}
	dir, err := s.artifacts.ArtifactDir(s.ctx, s.sourceAssociation, s.attemptID)
	if err != nil {
		return "", fmt.Errorf("open source-scoped artifact staging directory: %w", err)
	}
	abs, err := filepath.Abs(strings.TrimSpace(dir))
	if err != nil || strings.TrimSpace(dir) == "" {
		return "", errors.New("immutable artifact sink returned an invalid staging directory")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat artifact staging directory: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("immutable artifact sink staging path is not a directory")
	}
	s.artifactDir = abs
	return abs, nil
}

func (*parseSink) Claim(int) {}

func (s *parseSink) Record(record *internal.SourceRecord) error {
	if record == nil {
		return errors.New("SBV importer emitted a nil record")
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	converted := convertRecord(record, StatusParsed, "")
	converted.CapturedAttachments = uint64(len(record.Attachments))
	if len(record.Raw) == 0 {
		if strings.TrimSpace(record.RawPath) == "" {
			return errors.New("SBV record has no exact raw bytes or streamed raw path")
		}
		locator, _, err := s.storeArtifact(Artifact{
			Kind: ArtifactRawRecord, SourceAssociation: s.sourceAssociation, AttemptID: s.attemptID,
			ParentSourcePos: record.SourcePos, StagedPath: record.RawPath, ByteCount: record.RawSize,
		})
		if err != nil {
			return fmt.Errorf("persist exact raw record %q: %w", record.SourcePos, err)
		}
		converted.RawLocator = &locator
	}
	for ordinal, attachment := range record.Attachments {
		if attachment.ConversionStatus == "decode_failed" || strings.TrimSpace(attachment.ConversionError) != "" {
			s.quarantine = true
			converted.Status = StatusRejected
			converted.StatusReason = "one or more MMS attachments failed base64 decoding"
			converted.AttachmentFailures = append(converted.AttachmentFailures, AttachmentFailure{
				AttachmentOrdinal: uint64(ordinal), SourceAssociation: s.sourceAssociation,
				ParentSourcePos: record.SourcePos, OriginalName: attachment.OriginalName,
				MIME: attachment.MIME, ConversionStatus: attachment.ConversionStatus,
				ConversionError: attachment.ConversionError,
			})
			continue
		}
		locator, digest, err := s.storeArtifact(Artifact{
			Kind: ArtifactAttachment, SourceAssociation: s.sourceAssociation, AttemptID: s.attemptID,
			ParentSourcePos: record.SourcePos, AttachmentOrdinal: uint64(ordinal),
			OriginalName: attachment.OriginalName, MIME: attachment.MIME,
			StagedPath: attachment.StoredPath, ByteCount: attachment.ByteCount,
		})
		if err != nil {
			return fmt.Errorf("persist attachment %d for %q: %w", ordinal, record.SourcePos, err)
		}
		if attachment.DecodedHash != "" && attachment.DecodedHash != digest {
			return fmt.Errorf("attachment %d for %q digest disagrees with decoder digest", ordinal, record.SourcePos)
		}
		converted.Attachments = append(converted.Attachments, Attachment{
			AttachmentOrdinal: uint64(ordinal), SourceAssociation: s.sourceAssociation,
			ParentSourcePos: record.SourcePos,
			OriginalName:    attachment.OriginalName, MIME: attachment.MIME,
			DigestSHA256: digest, ByteCount: attachment.ByteCount,
			ConversionStatus: attachment.ConversionStatus, ConversionError: attachment.ConversionError,
			Locator: locator,
		})
	}
	if uint64(len(converted.Attachments)+len(converted.AttachmentFailures)) != converted.CapturedAttachments {
		return errors.New("SBV attachment capture accounting is not one-to-one")
	}
	return s.emit(s.ctx, converted)
}

func (s *parseSink) storeArtifact(artifact Artifact) (ArtifactLocator, string, error) {
	if s.artifacts == nil {
		return ArtifactLocator{}, "", errors.New("immutable artifact sink is unavailable")
	}
	root, err := s.ArtifactDir()
	if err != nil {
		return ArtifactLocator{}, "", err
	}
	path, err := filepath.Abs(strings.TrimSpace(artifact.StagedPath))
	if err != nil || strings.TrimSpace(artifact.StagedPath) == "" {
		return ArtifactLocator{}, "", errors.New("artifact has an invalid staged path")
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return ArtifactLocator{}, "", errors.New("artifact staged path escapes the sink root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ArtifactLocator{}, "", fmt.Errorf("stat staged artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ArtifactLocator{}, "", errors.New("staged artifact must be a regular file")
	}
	if info.Size() != artifact.ByteCount {
		return ArtifactLocator{}, "", fmt.Errorf("staged artifact size %d does not match declared %d", info.Size(), artifact.ByteCount)
	}
	digest, err := hashFile(path)
	if err != nil {
		return ArtifactLocator{}, "", err
	}
	locator, err := s.artifacts.Store(s.ctx, artifact)
	if err != nil {
		return ArtifactLocator{}, "", err
	}
	if strings.TrimSpace(locator.StorageClass) == "" || strings.TrimSpace(locator.URI) == "" {
		return ArtifactLocator{}, "", errors.New("immutable artifact sink returned an incomplete locator")
	}
	if locator.ContentHash != digest {
		return ArtifactLocator{}, "", errors.New("immutable artifact sink locator digest does not match staged bytes")
	}
	return locator, digest, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open staged artifact: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash staged artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *parseSink) Reject(sourcePos, reason string, raw []byte, rawComplete bool) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if !rawComplete || len(raw) == 0 {
		return errors.New("SBV rejected span lacks complete raw bytes; malformed/unparsed status cannot be inferred safely")
	}
	return s.emit(s.ctx, Record{Status: StatusRejected, StatusReason: strings.TrimSpace(reason), SourcePos: sourcePos, Raw: append([]byte(nil), raw...)})
}

func (*parseSink) RejectHashed(_, _, _, _ string, _ int64) error {
	return errors.New("SBV RejectHashed cannot satisfy parse-only raw-span contract without exact bytes")
}

func convertRecord(record *internal.SourceRecord, status Status, reason string) Record {
	metadata := make(map[string]any, len(record.Metadata)+1)
	for key, value := range record.Metadata {
		metadata[key] = value
	}
	return Record{
		Status: status, StatusReason: reason, Kind: record.Kind, SourcePos: record.SourcePos,
		Raw: append([]byte(nil), record.Raw...), OccurredAt: record.OccurredAt,
		Participants: append([]string(nil), record.Participants...), Sender: record.Sender,
		Recipients: convertRecipients(record.Recipients), Content: record.Content, Metadata: metadata,
		AttachmentReferences: convertAttachmentReferences(record.AttachmentReferences),
	}
}

func convertRecipients(values []internal.SourceParty) []Recipient {
	result := make([]Recipient, 0, len(values))
	for _, value := range values {
		result = append(result, Recipient{Identity: value.Identity, Role: value.Role})
	}
	return result
}

func convertAttachmentReferences(values []internal.AttachmentReference) []AttachmentReference {
	result := make([]AttachmentReference, 0, len(values))
	for _, value := range values {
		result = append(result, AttachmentReference{
			Kind: value.Kind, URIOriginal: value.URIOriginal, URI: value.URI,
			DisplayText: value.DisplayText, ResolutionStatus: value.ResolutionStatus,
			SafeRelative: value.SafeRelative, SourceReportedMissing: value.SourceReportedMissing,
			ResolvedHash: value.ResolvedHash,
		})
	}
	return result
}
