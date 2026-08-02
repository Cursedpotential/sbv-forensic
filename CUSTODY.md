# SBV forensic custody — H1/H2/H3 canonicalization (auditable spec)

> _Byline: Claude Code · Opus 4.8 · 2026-07-09_

This is the authoritative, byte-level specification of the three custody hashes
the SBV forensic fork computes. It exists so the hashes can be independently
audited against `server/evidence/custody.py` (the Python custody gate that
cross-checks and records them). The reference implementation is
`vendored/sbv/internal/custody.go`; the tests are `internal/custody_test.go`.

## Ordering contract (owner-verified)

Hashing MUST precede normalization. The pipeline order is:

```
H1 (raw file)  →  H2 (raw per-record)  →  H3 (chain)  →  (only THEN) normalize
```

Every hash is taken over the ORIGINAL source bytes, BEFORE any field decoding,
base64 transcoding, phone-number normalization, or NormalizedRecord mapping.
This is what lets the hashes prove the source content is unaltered.

## H1 — file-level (`h1-rawbytes-v1`)

`H1 = lowercase_hex( SHA-256( raw file bytes ) )`

- Computed in `SaveUploadedFile()` as the uploaded bytes stream to disk (and in
  the auto-import path via `HashFileH1(path)`), BEFORE the parser opens the file.
- **Byte-for-byte identical** to `server/evidence/custody.py::_sha256_file` — a
  plain SHA-256 over the unmodified bytes, no reformatting. The two
  independently-derived H1s are the cross-check: they MUST agree for an unaltered
  file (match → `verified` custody event; mismatch → `integrity_violation`).

## H2 — per-record (`h2-rawelement-v1`)

`H2 = lowercase_hex( SHA-256( raw source XML element bytes ) )`

- The "raw source XML element bytes" are the **exact bytes of a single
  `<sms .../>`, `<mms>...</mms>`, or `<call .../>` element** as they appear in the
  uploaded file — from the element's opening `<` through its closing `>`
  inclusive — with surrounding inter-element whitespace excluded.
- Captured by `rawCaptureReader` using `xml.Decoder.InputOffset()` boundaries,
  then `trimLeadingXMLSpace` strips any leading whitespace so the span begins
  exactly at `<`. The bytes are hashed BEFORE `DecodeElement`'s result is
  converted/normalized (before base64-decoding MMS parts, before phone-number
  normalization, before type coercion).
- Determinism: identical raw element bytes always yield the identical hash; ANY
  change to the source bytes — including whitespace or formatting the normalizer
  would later strip — changes the hash. That is the point (see
  `TestHashRecordH2_RawNotNormalized`).
- Stored in `messages.content_hash` and surfaced additively in the
  `/api/messages`, `/api/calls`, and `/api/activity` payloads as `content_hash`.

**Independent re-derivation:** extract the same `<sms>/<mms>/<call>` element's
raw bytes from the source file (opening `<` through closing `>`, no surrounding
whitespace) and SHA-256 them. The Python side does not re-derive H2 — it records
SBV's H2 values as `evidence_hash` level-`H2` rows — but this definition makes
re-derivation fully reproducible for audit.

## H3 — batch chain (`h3-chain-v1`)

Left fold over the ordered per-record H2s (in raw source / parse order):

```
chain_0 = prevChain                                   # "" for a fresh import batch
chain_i = lowercase_hex( SHA-256( chain_{i-1} + "\n" + H2_i ) )
H3      = chain_n
```

- Separator is a single `"\n"` (0x0A) between the running hex chain and each
  record H2. The running value is the hex digest string, then the next H2 hex is
  appended and re-hashed.
- `prevChain` is `""` for an independent per-import chain (the value used by
  `ParseSMSBackupStreaming`). It exists so successive batches could be chained
  end-to-end if ever desired.
- Order-sensitive: permuting the H2s changes H3. An empty batch folds to
  `prevChain` (i.e. `""` for a fresh batch).
- Recorded once per import in the `imports` table (`chain_hash`), alongside the
  H1 (`file_hash`) and `record_count`.

## Storage & exposure

- `messages.content_hash TEXT` — the H2 for that record (idempotent migration in
  `ensureCustodyColumns`).
- `imports(id, file_hash, record_count, chain_hash, canon_version, imported_at)`
  — one row per upload/auto-import batch (H1 + H3 + count).
- `GET /api/hashes/:importID` — returns `{import_id, file_hash (H1),
  chain_hash (H3), record_count, imported_at, file_hash_canon, record_hash_canon,
  chain_canon}`. `:importID` may be a numeric id or `latest` (the batch a
  just-finished upload produced — the anchor the Python cross-check reads).

## Cross-check on the Python side

`server/evidence/tools/sbv_sms.py::_reconcile_custody` (opt-in via
`SBV_CUSTODY_ENABLED`) pulls `GET /api/hashes/latest` + the per-record H2s, then
calls `custody.reconcile_sbv_import`, which:

1. re-computes H1 independently (`ingest_artifact`) and compares to SBV's H1;
2. emits a `verified` or `integrity_violation` `custody_event`;
3. on a verified match, records the H2s + H3 as append-only `evidence_hash` rows
   (levels `H2`/`H3`, with these same canon-version tags).

The canon-version strings above are duplicated as constants in both
`internal/custody.go` and `custody.py` and MUST stay in lockstep.

---

## Tag crosswalk note (platform-side, 2026-08-02)

The bare `h3-chain-v1` tag proved ambiguous: the Case Bible vault writes a
different, equally valid H3 construction (genesis = H1,
`sha256(prev_hex + h2_hex)`) under the same tag. Platform DB rows written from
2026-08-02 carry `h3-chain-sbv-genesisempty-v1` for THIS document's
construction. The Go code below still says `h3-chain-v1` — its computation is
unchanged; only the platform's stored label gained precision. Legacy rows are
disambiguated by writer, never relabelled. Why H2/H3 are not independently
re-derived platform-side: cost of a second full XML canonicalization
implementation; H1 IS independently re-derived and must agree, and the honest
scope of the trust is stated above. See docs/DECISION_LOG.md 2026-08-02.
