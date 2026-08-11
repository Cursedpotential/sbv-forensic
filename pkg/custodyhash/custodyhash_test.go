package custodyhash

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestHashBytesKnownAnswers(t *testing.T) {
	// Known SHA-256 vectors — pin the primitive.
	if got := HashBytes(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("HashBytes(empty) = %s", got)
	}
	if got := HashBytes([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashBytes(abc) = %s", got)
	}
}

func TestHashRecordH2IsRawBytes(t *testing.T) {
	raw := []byte(`<sms address="+15551234567" body="hi"/>`)
	if HashRecordH2(raw) != HashBytes(raw) {
		t.Fatal("H2 must be the raw-bytes SHA-256 of the source element")
	}
}

func TestCanonTags(t *testing.T) {
	// The tags name the EXACT construction; changing a construction requires a new tag.
	// H3 is the PRECISE tag (sbv-genesisempty), never the ambiguous legacy h3-chain-v1.
	if CanonH1 != "h1-rawbytes-v1" {
		t.Fatalf("CanonH1 drifted: %s", CanonH1)
	}
	if CanonH2 != "h2-rawelement-v1" || CanonH2Record != "h2-rawrecord-v1" {
		t.Fatalf("CanonH2 drifted: %s / %s", CanonH2, CanonH2Record)
	}
	if CanonH3 != "h3-chain-sbv-genesisempty-v1" {
		t.Fatalf("CanonH3 must be the precise tag, got: %s", CanonH3)
	}
	if CanonH3Legacy != "h3-chain-v1" {
		t.Fatalf("CanonH3Legacy drifted: %s", CanonH3Legacy)
	}
}

func TestChainH3ExactFold(t *testing.T) {
	// chain_1 = sha256("" + "\n" + h2a)
	want1 := sha256Hex("\n" + "h2a")
	if got := ChainH3([]string{"h2a"}, ""); got != want1 {
		t.Fatalf("single fold = %s want %s", got, want1)
	}
	// chain_2 = sha256(chain_1 + "\n" + h2b)
	want2 := sha256Hex(want1 + "\n" + "h2b")
	if got := ChainH3([]string{"h2a", "h2b"}, ""); got != want2 {
		t.Fatalf("two-record fold = %s want %s", got, want2)
	}
}

func TestChainH3PrevChainSeed(t *testing.T) {
	want := sha256Hex("seed" + "\n" + "h2")
	if got := ChainH3([]string{"h2"}, "seed"); got != want {
		t.Fatalf("prevChain fold = %s want %s", got, want)
	}
}

func TestChainH3OrderSensitive(t *testing.T) {
	if ChainH3([]string{"1", "2", "3"}, "") == ChainH3([]string{"3", "2", "1"}, "") {
		t.Fatal("H3 must be order-sensitive")
	}
}

func TestChainH3EmptyBatchFoldsToPrev(t *testing.T) {
	if ChainH3(nil, "") != "" {
		t.Fatal("empty batch + empty prev must be empty")
	}
	if ChainH3(nil, "seed") != "seed" {
		t.Fatal("empty batch must leave prevChain unchanged")
	}
}

func TestStreamingChainEqualsBatch(t *testing.T) {
	h2s := []string{"x", "y", "z"}
	c := NewChain("")
	for _, h := range h2s {
		c.Add(h)
	}
	if c.Value() != ChainH3(h2s, "") {
		t.Fatal("streaming Chain must equal batch ChainH3 (no divergence)")
	}
}

func TestHashReaderH1MatchesHashBytes(t *testing.T) {
	data := "the quick brown fox jumps over the lazy dog"
	got, err := HashReaderH1(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got != HashBytes([]byte(data)) {
		t.Fatalf("streaming H1 = %s want %s", got, HashBytes([]byte(data)))
	}
}
