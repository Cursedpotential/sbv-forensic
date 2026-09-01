// Package custodyhash is the SINGLE canonical implementation of the SBV forensic
// H1/H2/H3 chain-of-custody hashes.
//
// WHY THIS PACKAGE EXISTS
//
// The custody hashes were defined inside SBV's internal package (internal/custody.go)
// and the H3 chain fold was ALSO hand-inlined in internal/engine.go — two copies of the
// same construction, which is exactly how a "same-named but different" hash drift begins.
// This package is the decoupled, importable source of truth: SBV internals delegate to it,
// and any other execution site (a PG function, a DuckDB UDF, an atomic CLI call, a backup
// workflow, or a small FastAPI/HTTP mirror) matches by binding to THIS construction — so the
// same bytes always yield the same H1/H2/H3 regardless of who computes them.
//
// The construction is frozen by the canon version tags below and specified in CUSTODY.md.
// It is stdlib-only and holds no database credentials — it only COMPUTES over raw bytes.
//
// ORDERING CONTRACT (owner-verified — hashing MUST precede normalization):
//
//	H1 (raw file) -> H2 (raw per-record) -> H3 (chain) -> (only then) normalize
package custodyhash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Canon version tags — these name the EXACT construction. Never reuse a tag for a
// different construction (a bare tag that means two things is the drift bug).
const (
	CanonH1 = "h1-rawbytes-v1" // lowercase hex sha256 over raw file bytes

	// H2 spans: element for XML, logical-record for non-XML (NDJSON line / CSV record,
	// terminator excluded, quotes intact). Same primitive, format-specific span.
	CanonH2       = "h2-rawelement-v1"
	CanonH2Record = "h2-rawrecord-v1"

	// CanonH3 is THE canonical chain tag — the construction this code computes: genesis = "",
	// chain_i = hex(sha256(chain_{i-1} + "\n" + H2_i)). Named precisely so it can never be
	// confused with a different-but-valid chain (the Case Bible vault wrote one such under the
	// legacy label). ALL new import rows carry this tag; it matches custody.py::H3_CANON.
	CanonH3 = "h3-chain-sbv-genesisempty-v1"

	// CanonH3Legacy is the ambiguous pre-2026-08-02 label: a different-but-valid chain was
	// written under it too. Read-only — rows keep it, never restamped, never used for new writes.
	CanonH3Legacy = "h3-chain-v1"
)

// chainSep is the fixed single-byte separator (0x0A) between the running hex chain
// and the next record H2 in the H3 fold. Frozen by h3-chain-v1.
const chainSep = "\n"

// HashBytes is the shared primitive: lowercase hex SHA-256 of raw bytes.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HashReaderH1 computes H1 from the reader's current position: lowercase hex SHA-256
// of the raw bytes, streamed in 1 MiB chunks. Callers that retain an evidence file can
// hash and parse the same open descriptor, avoiding a path-based reopen window.
func HashReaderH1(r io.Reader) (string, error) {
	h := sha256.New()
	buf := make([]byte, 1024*1024)
	if _, err := io.CopyBuffer(h, r, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFileH1 computes the H1 file-level custody hash over the RAW file bytes.
// MUST be byte-for-byte equal to server/evidence/custody.py::_sha256_file for the
// same file — both are a plain SHA-256 over the unmodified bytes.
func HashFileH1(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return HashReaderH1(f)
}

// HashRecordH2 computes the H2 per-record custody hash over the RAW SOURCE element
// bytes (the exact bytes of a single record element as they appear in the upload),
// hashed BEFORE any parsing/normalization so it proves the original content is
// unaltered. (h2-rawelement-v1)
func HashRecordH2(rawElement []byte) string {
	return HashBytes(rawElement)
}

// ChainH3 computes the H3 batch chain digest over the ordered per-record H2 hashes,
// in source (parse) order. Left fold:
//
//	chain_0 = prevChain                             (prevChain == "" for a fresh batch)
//	chain_i = hex(sha256( chain_{i-1} + "\n" + H2_i ))
//	H3      = chain_n
//
// Order-sensitive: permuting the H2s changes H3. An empty batch folds to prevChain.
// prevChain lets successive import batches be chained end-to-end; pass "" for an
// independent per-import chain. (h3-chain-v1)
func ChainH3(orderedH2s []string, prevChain string) string {
	c := NewChain(prevChain)
	for _, h2 := range orderedH2s {
		c.Add(h2)
	}
	return c.Value()
}

// FoldChain is one stateless step of the h3-chain-v1 fold: chain' = hex(sha256(chain + "\n" + h2)).
// Use it wherever a chain is carried as a plain string field (e.g. a streaming parser's state)
// instead of a *Chain — so those sites use the SAME construction as ChainH3, never a hand-inlined copy.
func FoldChain(chain, h2 string) string {
	return HashBytes([]byte(chain + chainSep + h2))
}

// Chain is a streaming H3 accumulator for callers that receive H2s one at a time
// (e.g. a streaming parser). It uses the SAME fold as ChainH3, so a streaming caller
// and a batch caller cannot diverge. Not safe for concurrent use.
type Chain struct {
	value string
}

// NewChain starts a chain from prev ("" for a fresh, independent per-import chain).
func NewChain(prev string) *Chain {
	return &Chain{value: prev}
}

// Add folds one per-record H2 (a lowercase hex string) into the running chain.
func (c *Chain) Add(h2 string) {
	c.value = FoldChain(c.value, h2)
}

// Value returns the current chain digest (H3 once all H2s have been Added).
func (c *Chain) Value() string {
	return c.value
}
