package internal

// attachment_references.go defines one conservative companion-reference
// vocabulary shared by archive/HTML/text importers. A safe relative path is a
// candidate for resolution only inside an explicitly supplied bundle/root; it
// is never permission to inspect the host filesystem.

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
)

const (
	AttachmentReferenceOnly         = "reference_only"
	AttachmentSourceReportedMissing = "source_reported_missing"
	AttachmentUnsafeReference       = "unsafe_reference"
	AttachmentExternalReference     = "external_reference"
	AttachmentResolved              = "resolved"
)

func newAttachmentReference(kind, value, display string, allowedRootPrefixes ...string) AttachmentReference {
	original := strings.TrimSpace(value)
	display = strings.TrimSpace(display)
	missing := original == "" || strings.Contains(strings.ToLower(original+" "+display), "attachment missing")
	ref := AttachmentReference{
		Kind: kind, URIOriginal: original, DisplayText: display,
		ResolutionStatus:      AttachmentReferenceOnly,
		SourceReportedMissing: missing,
	}
	if missing {
		ref.ResolutionStatus = AttachmentSourceReportedMissing
		return ref
	}

	normalized := strings.TrimSpace(strings.ReplaceAll(original, `\`, "/"))
	if parsed, err := url.Parse(normalized); err == nil && parsed.Scheme != "" {
		ref.ResolutionStatus = AttachmentExternalReference
		return ref
	}
	if filepath.VolumeName(normalized) != "" {
		ref.ResolutionStatus = AttachmentUnsafeReference
		return ref
	}

	lower := strings.ToLower(normalized)
	for _, prefix := range allowedRootPrefixes {
		prefix = strings.Trim(strings.ReplaceAll(prefix, `\`, "/"), "/") + "/"
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			normalized = normalized[len(prefix):]
			lower = strings.ToLower(normalized)
			break
		}
		// Some exporter paths use /Attachments/... as a virtual archive-root
		// marker. Only strip the slash for an explicitly allowed prefix.
		if strings.HasPrefix(lower, "/"+strings.ToLower(prefix)) {
			normalized = normalized[len(prefix)+1:]
			lower = strings.ToLower(normalized)
			break
		}
	}
	if normalized == "" || strings.HasPrefix(normalized, "/") {
		ref.ResolutionStatus = AttachmentUnsafeReference
		return ref
	}
	clean := path.Clean(normalized)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		ref.ResolutionStatus = AttachmentUnsafeReference
		return ref
	}
	ref.URI = clean
	ref.SafeRelative = true
	return ref
}

func newIMessageAttachmentReference(kind, value, display string) AttachmentReference {
	original := strings.TrimSpace(value)
	normalized := original
	if strings.HasPrefix(strings.ToLower(strings.ReplaceAll(normalized, `\`, "/")), "/attachments/") {
		normalized = strings.TrimPrefix(strings.ReplaceAll(normalized, `\`, "/"), "/")
	}
	ref := newAttachmentReference(kind, normalized, display)
	ref.URIOriginal = original
	return ref
}

func attachmentReferenceMetadata(ref AttachmentReference) map[string]interface{} {
	return map[string]interface{}{
		"kind": ref.Kind, "uri_original": ref.URIOriginal, "uri": ref.URI,
		"display_text": ref.DisplayText, "resolution_status": ref.ResolutionStatus,
		"unresolved": ref.ResolutionStatus != AttachmentResolved,
		"missing":    ref.SourceReportedMissing, "source_reported_missing": ref.SourceReportedMissing,
		"safe_relative": ref.SafeRelative,
	}
}
