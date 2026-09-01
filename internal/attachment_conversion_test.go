package internal

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type copyingTestConverter struct {
	availability error
	fail         error
}

func (c copyingTestConverter) Availability() error { return c.availability }
func (c copyingTestConverter) Convert(_ context.Context, input, output, _ string) error {
	if c.fail != nil {
		return c.fail
	}
	source, err := os.Open(input)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(output, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(destination, source, make([]byte, 32<<10))
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func TestPrepareAttachmentDerivativeHashesSeparateFile(t *testing.T) {
	root := t.TempDir()
	originalDir := filepath.Join(root, "attachments")
	if err := os.MkdirAll(originalDir, 0700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(originalDir, "voice.amr")
	payload := []byte("streamed original remains authoritative")
	if err := os.WriteFile(original, payload, 0600); err != nil {
		t.Fatal(err)
	}
	artifact := prepareAttachmentDerivative(root, AttachmentArtifact{
		OriginalName: "voice.amr", MIME: "audio/amr", StoredPath: original,
		DecodedHash: HashBytesSHA256(payload), ByteCount: int64(len(payload)),
	}, copyingTestConverter{})
	if artifact.ConversionStatus != "completed" || artifact.DerivedMIME != "audio/mpeg" ||
		artifact.DerivedHash != HashBytesSHA256(payload) || artifact.DerivedByteCount != int64(len(payload)) {
		t.Fatalf("artifact=%+v", artifact)
	}
	if artifact.DerivedPath == original || filepath.Dir(artifact.DerivedPath) != filepath.Join(root, "derived") {
		t.Fatalf("unsafe derivative path %q", artifact.DerivedPath)
	}
	originalBytes, err := os.ReadFile(original)
	if err != nil || string(originalBytes) != string(payload) {
		t.Fatalf("original changed: %q err=%v", originalBytes, err)
	}
}

func TestPrepareAttachmentDerivativeMakesUnavailableAndFailureVisible(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "image.heic")
	if err := os.WriteFile(original, []byte("not-a-real-heic"), 0600); err != nil {
		t.Fatal(err)
	}
	base := AttachmentArtifact{OriginalName: "image.heic", MIME: "image/heic", StoredPath: original}
	unavailable := prepareAttachmentDerivative(root, base, copyingTestConverter{availability: errors.New("tool missing")})
	if unavailable.ConversionStatus != "unavailable" || unavailable.ConversionError != "tool missing" {
		t.Fatalf("unavailable=%+v", unavailable)
	}
	failed := prepareAttachmentDerivative(root, base, copyingTestConverter{fail: errors.New("bad media")})
	if failed.ConversionStatus != "failed" || failed.DerivedPath != "" || failed.ConversionError != "bad media" {
		t.Fatalf("failed=%+v", failed)
	}
	entries, err := os.ReadDir(filepath.Join(root, "to_be_deleted"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed derivative was not quarantined: entries=%d err=%v", len(entries), err)
	}
	notRequired := prepareAttachmentDerivative(root, AttachmentArtifact{
		OriginalName: "photo.jpg", MIME: "image/jpeg", StoredPath: original,
	}, copyingTestConverter{availability: errors.New("must not be consulted")})
	if notRequired.ConversionStatus != "not_required" || notRequired.ConversionError != "" {
		t.Fatalf("not required=%+v", notRequired)
	}
}

func TestPrepareAttachmentDerivativePreservesDecodeFailure(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "partial.jpg")
	if err := os.WriteFile(original, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	got := prepareAttachmentDerivative(root, AttachmentArtifact{
		OriginalName: "partial.jpg", MIME: "image/jpeg", StoredPath: original,
		ConversionStatus: "decode_failed", ConversionError: "illegal base64 data",
	}, copyingTestConverter{})
	if got.ConversionStatus != "decode_failed" || got.ConversionError != "illegal base64 data" || got.DerivedPath != "" {
		t.Fatalf("decode failure was overwritten: %+v", got)
	}
}
