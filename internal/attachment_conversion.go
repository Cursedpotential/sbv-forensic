package internal

// attachment_conversion.go creates optional browser-friendly derivatives from
// file-backed originals. Originals remain authoritative and untouched. Every
// derivative is produced file-to-file, separately hashed, and stored under the
// authenticated import artifact root.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const conversionTimeout = 30 * time.Minute

type derivativePlan struct {
	kind string
	ext  string
	mime string
}

type attachmentConverter interface {
	Availability() error
	Convert(context.Context, string, string, string) error
}

type ffmpegAttachmentConverter struct {
	path string
}

func defaultAttachmentConverter() attachmentConverter {
	path, err := exec.LookPath("ffmpeg")
	if err != nil {
		return ffmpegAttachmentConverter{}
	}
	return ffmpegAttachmentConverter{path: path}
}

func (c ffmpegAttachmentConverter) Availability() error {
	if c.path == "" {
		return fmt.Errorf("ffmpeg executable is unavailable")
	}
	return nil
}

func (c ffmpegAttachmentConverter) Convert(ctx context.Context, input, output, kind string) error {
	args := []string{"-nostdin", "-hide_banner", "-loglevel", "error", "-y", "-i", input}
	switch kind {
	case "image-jpeg":
		args = append(args, "-frames:v", "1", "-q:v", "2")
	case "video-mp4":
		args = append(args, "-c:v", "libx264", "-c:a", "aac", "-movflags", "+faststart", "-preset", "fast", "-crf", "23")
	case "audio-mp3":
		args = append(args, "-codec:a", "libmp3lame", "-q:a", "2")
	default:
		return fmt.Errorf("unsupported conversion plan %q", kind)
	}
	args = append(args, output)
	cmd := exec.CommandContext(ctx, c.path, args...) // #nosec G204 — executable was resolved locally; args are not shell-evaluated.
	var stderr bytes.Buffer
	cmd.Stderr = &boundedWriter{w: &stderr, remaining: 64 << 10}
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("ffmpeg conversion: %w: %s", err, message)
		}
		return fmt.Errorf("ffmpeg conversion: %w", err)
	}
	return nil
}

type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	original := len(p)
	if int64(len(p)) > w.remaining {
		p = p[:w.remaining]
	}
	if len(p) > 0 {
		if _, err := w.w.Write(p); err != nil {
			return 0, err
		}
		w.remaining -= int64(len(p))
	}
	return original, nil
}

func derivativeFor(mimeType, name string) (derivativePlan, bool) {
	mimeType = strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0]))
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case isHEICContentType(mimeType) || ext == ".heic" || ext == ".heif":
		return derivativePlan{kind: "image-jpeg", ext: ".jpg", mime: "image/jpeg"}, true
	case needsVideoConversion(mimeType) || ext == ".3gp" || ext == ".3g2" || ext == ".mkv":
		return derivativePlan{kind: "video-mp4", ext: ".mp4", mime: "video/mp4"}, true
	case needsAudioConversion(mimeType) || ext == ".amr" || ext == ".awb":
		return derivativePlan{kind: "audio-mp3", ext: ".mp3", mime: "audio/mpeg"}, true
	default:
		return derivativePlan{}, false
	}
}

func prepareAttachmentDerivative(root string, attachment AttachmentArtifact, converter attachmentConverter) AttachmentArtifact {
	// Acquisition/decode failures describe the authoritative original and must
	// never be hidden by a later, optional viewing conversion decision.
	if attachment.ConversionStatus == "decode_failed" {
		return attachment
	}
	plan, needed := derivativeFor(attachment.MIME, attachment.OriginalName)
	if !needed {
		attachment.ConversionStatus = "not_required"
		attachment.ConversionError = ""
		return attachment
	}
	if converter == nil {
		attachment.ConversionStatus = "unavailable"
		attachment.ConversionError = "no attachment converter configured"
		return attachment
	}
	if err := converter.Availability(); err != nil {
		attachment.ConversionStatus = "unavailable"
		attachment.ConversionError = err.Error()
		return attachment
	}
	derivedDir := filepath.Join(root, "derived")
	if err := os.MkdirAll(derivedDir, 0700); err != nil {
		attachment.ConversionStatus = "failed"
		attachment.ConversionError = err.Error()
		return attachment
	}
	output, err := os.CreateTemp(derivedDir, "derived-*"+plan.ext)
	if err != nil {
		attachment.ConversionStatus = "failed"
		attachment.ConversionError = err.Error()
		return attachment
	}
	outputPath := output.Name()
	if err := output.Close(); err != nil {
		attachment.ConversionStatus = "failed"
		attachment.ConversionError = err.Error()
		quarantineConversionArtifact(root, outputPath)
		return attachment
	}
	ctx, cancel := context.WithTimeout(context.Background(), conversionTimeout)
	defer cancel()
	if err := converter.Convert(ctx, attachment.StoredPath, outputPath, plan.kind); err != nil {
		attachment.ConversionStatus = "failed"
		attachment.ConversionError = err.Error()
		quarantineConversionArtifact(root, outputPath)
		return attachment
	}
	info, err := os.Stat(outputPath)
	if err != nil || info.Size() == 0 {
		attachment.ConversionStatus = "failed"
		if err != nil {
			attachment.ConversionError = "stat derivative: " + err.Error()
		} else {
			attachment.ConversionError = "converter produced an empty derivative"
		}
		quarantineConversionArtifact(root, outputPath)
		return attachment
	}
	hash, err := HashFileH1(outputPath)
	if err != nil {
		attachment.ConversionStatus = "failed"
		attachment.ConversionError = "hash derivative: " + err.Error()
		quarantineConversionArtifact(root, outputPath)
		return attachment
	}
	attachment.ConversionStatus = "completed"
	attachment.ConversionError = ""
	attachment.DerivedPath = outputPath
	attachment.DerivedHash = hash
	attachment.DerivedMIME = plan.mime
	attachment.DerivedByteCount = info.Size()
	return attachment
}

func quarantineConversionArtifact(root, path string) {
	if path == "" {
		return
	}
	dir := filepath.Join(root, "to_be_deleted")
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	_ = os.Rename(path, filepath.Join(dir, filepath.Base(path)+".failed"))
}
