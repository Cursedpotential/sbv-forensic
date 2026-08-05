package internal

// importer.go — the pluggable importer interface + registry for the universal
// evidence parser engine.
//
// SBV's contract (owner-locked): it is an ISOLATED extraction/viewer worker,
// never platform truth. An importer's only job is to walk one source file,
// hand every raw logical source record to the engine sink UNMODIFIED (the raw
// bytes are the H2 input — hashing precedes normalization, always), and report
// what the source claims to contain. The engine (engine.go) owns identity,
// hashing, storage, dedup, counting, and reconciliation; importers own format
// knowledge only.
//
// Detection is registry-driven with EXPLICIT priorities: importers are asked in
// descending priority order and the first Detect() == true wins. Ties break by
// registration order. Priorities are deliberately spread out so a future format
// can slot between existing ones without renumbering.

import (
	"bufio"
	"sort"
	"sync"
	"time"
)

// Format identifiers (the `format` value stored on imports + import_records).
const (
	FormatSMSBackupXML = "smsbackuprestore-xml"
	FormatNDJSON       = "ndjson"
	FormatCSV          = "csv"
	FormatTranscript   = "messages-transcript"
	FormatIMessageTXT  = "imessage-txt"
	FormatIMessageHTML = "imessage-html"
	FormatFacebookHTML = "facebook-messenger-html"
	FormatGoogleVoice  = "google-voice-html"
	FormatEML          = "email-eml"
	FormatMBOX         = "email-mbox"
	FormatGoogleChat   = "google-chat-json"
	FormatFacebookJSON = "facebook-messenger-json"
)

// Record kinds. XML yields message/call (the SMS vertical); non-XML formats
// default to their own neutral kinds — nothing forces them into SMS semantics.
const (
	KindMessage   = "message"
	KindCall      = "call"
	KindRow       = "row"    // CSV default
	KindObject    = "object" // NDJSON default
	KindVoicemail = "voicemail"
	KindEmail     = "email"
)

// Resource bounds (parser safety). A single raw logical record larger than
// these is REJECTED with a reason, never buffered unbounded.
const (
	maxRawRecordBytes  = 64 << 20 // one materialized record (MMS data uses the streaming exception)
	maxLineRecordBytes = 16 << 20 // one NDJSON line / one CSV record
	maxCSVFields       = 1024
	detectPeekBytes    = 8192
	rejectExcerptBytes = 512
)

// SourceRecord is one raw logical source record an importer encountered, plus
// the importer's best-effort format-neutral projection of it. Raw is the EXACT
// byte span of the record as it appears in the source file, BEFORE any
// decoding/normalization — it is the H2 input and must never be reformatted.
type SourceRecord struct {
	Kind          string                 // message | call | row | object | ...
	SourcePos     string                 // human-readable position in the source ("bytes 120-456", "line 42", ...)
	Raw           []byte                 // exact raw logical source-record bytes (H2 input)
	RawCanon      string                 // H2 canon tag for this span (h2-rawelement-v1 for XML, h2-rawrecord-v1 otherwise)
	PrecomputedH2 string                 // lowercase SHA-256 when Raw was streamed and not materialized
	RawSize       int64                  // exact logical span length (len(Raw) when materialized)
	OccurredAt    *time.Time             // when the recorded event occurred, if derivable
	Participants  []string               // who was involved, if derivable
	Content       string                 // primary human-readable content, if derivable
	Metadata      map[string]interface{} // full format-specific field map (never lossy)

	// Optional legacy projections. The XML vertical fills exactly one of these
	// so the messages table (and every legacy API) keeps working unchanged.
	LegacyMessage *Message
	LegacyCall    *CallLog
	Attachments   []AttachmentArtifact // decoded/spooled child artifacts, never inline payloads
	// AttachmentReferences are source-declared companion objects whose bytes are
	// not necessarily present in this import. They are stored independently from
	// Metadata so the API can reliably distinguish reference-only, missing,
	// unsafe, and resolved attachment states across every source format.
	AttachmentReferences []AttachmentReference
}

// AttachmentArtifact is a bounded file-backed child of one source record.
type AttachmentArtifact struct {
	OriginalName     string
	MIME             string
	DecodedHash      string
	ByteCount        int64
	StoredPath       string // absolute internal path; API stores/returns a safe relative path
	ConversionStatus string
	DerivedPath      string
	DerivedHash      string
	DerivedMIME      string
	DerivedByteCount int64
	ConversionError  string
}

// AttachmentReference is a source-declared pointer to a companion object.
// URI is populated only when the value is a safe path relative to a user-
// supplied bundle root. Importers never search the host filesystem for it.
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

// ImportSink is the engine-provided surface an importer reports into. Every
// encountered record ends in exactly one of Record (accepted or deduplicated —
// the engine decides which) or Reject (with reason + source position).
type ImportSink interface {
	ImportID() int64
	ArtifactDir() (string, error)
	// Claim records what the source itself claims to contain (e.g. the XML
	// count attribute). Cumulative across multiple calls.
	Claim(n int)
	// Record hands one raw logical source record to the engine. A non-nil error
	// is fatal (storage failure) — the importer must stop and return it.
	Record(rec *SourceRecord) error
	// Reject records a source record (or span) that could not be accepted.
	// rawComplete is true only when raw is the exact complete logical record;
	// complete rejects receive H2 and enter H3, partial excerpts do not.
	Reject(sourcePos, reason string, raw []byte, rawComplete bool) error
	// RejectHashed records a complete logical span that was streamed rather
	// than materialized. The supplied H2 must be the exact raw-span SHA-256.
	RejectHashed(sourcePos, reason, h2, canon string, rawSize int64) error
}

// Importer is one pluggable format handler.
type Importer interface {
	// Format is the stable format identifier stored on imports/import_records.
	Format() string
	// Priority orders detection; higher is asked first. Explicit by design.
	Priority() int
	// Detect reports whether this importer handles the given file, judged from
	// the first detectPeekBytes of content plus the filename.
	Detect(head []byte, filename string) bool
	// Run streams the source through the sink. It must be streaming (bounded
	// memory) and must never modify or reorder the raw record bytes it hashes.
	Run(sink ImportSink, r *bufio.Reader) error
}

var (
	registryMu       sync.RWMutex
	importerRegistry []Importer
)

// RegisterImporter adds an importer to the registry, kept sorted by descending
// priority (stable — ties keep registration order).
func RegisterImporter(imp Importer) {
	registryMu.Lock()
	defer registryMu.Unlock()
	importerRegistry = append(importerRegistry, imp)
	sort.SliceStable(importerRegistry, func(i, j int) bool {
		return importerRegistry[i].Priority() > importerRegistry[j].Priority()
	})
}

// RegisteredImporters returns the registry in detection order (copy).
func RegisteredImporters() []Importer {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Importer, len(importerRegistry))
	copy(out, importerRegistry)
	return out
}

// DetectImporter picks the highest-priority importer whose Detect matches.
// Returns nil if nothing claims the file.
func DetectImporter(head []byte, filename string) Importer {
	return detectFrom(RegisteredImporters(), head, filename)
}

// detectFrom runs detection over an explicit importer list (assumed already in
// priority order) — split out so tests can exercise priority behavior directly.
func detectFrom(imps []Importer, head []byte, filename string) Importer {
	for _, imp := range imps {
		if imp.Detect(head, filename) {
			return imp
		}
	}
	return nil
}

// ImporterByFormat resolves an importer by its stable format id.
func ImporterByFormat(format string) (Importer, bool) {
	for _, imp := range RegisteredImporters() {
		if imp.Format() == format {
			return imp, true
		}
	}
	return nil, false
}
