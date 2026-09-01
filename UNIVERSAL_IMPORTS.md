# Universal SBV import engine

> _Byline: Codex · GPT-5 · 2026-08-02_

This fork extends SBV from an SMS Backup & Restore viewer into an isolated,
format-pluggable evidence parsing and inspection worker. It does not make SBV a
platform system of record. The platform custody gate remains authoritative and
must independently verify H1 and persist its own append-only custody events.

The original `/api/upload`, conversations, messages, calls, activity, search,
media, and UI contracts remain available. The universal API is additive.

## Invariants

One source upload creates one immutable `imports.id` before record parsing. Every
canonical record, rejection, count, H2, and H3 produced by that parse carries
that exact ID. Consumers must use it; `latest` exists only for old clients.

Custody order is fixed:

1. H1: `sha256(original file bytes)`, canon `h1-rawbytes-v1`.
2. H2: `sha256(exact raw logical record bytes)` before decoding or projection.
   XML uses `h2-rawelement-v1`; all other plugins use `h2-rawrecord-v1`.
   Each plugin's exact non-XML boundary is listed below.
3. H3: ordered left fold with empty genesis,
   `chain_i = sha256(chain_(i-1) + "\n" + H2_i)`, canon
   `h3-chain-sbv-genesisempty-v1`.
4. Only after H2 is fixed may an importer project content, participants,
   occurred time, metadata, or a legacy message/call.

Accepted, deduplicated, and rejected records all enter H3 when their complete
raw logical spans are recoverable, because every one was present in the source.
A rejection with only a partial/unrecoverable span has no H2 and does not enter
H3; its bounded excerpt, source position, and reason remain available for review.

The other platform-valid H3 construction—Case Bible's H1 genesis and
`sha256(prev_hex + h2_hex)` fold—is deliberately not produced here. It requires
its own canon tag and must never be conflated with the SBV construction.

## Supported plugins

| Format ID | Detection | Logical H2 span | Projection |
|---|---|---|---|
| `smsbackuprestore-xml` | `.xml` plus `<smses` or `<calls` | exact `<sms>`, `<mms>`, or `<call>` element bytes | neutral record plus legacy message/call viewer row |
| `ndjson` | `.ndjson`, `.jsonl`, or at least two valid object lines | exact non-empty physical line without terminator | object metadata plus best-effort content/time/participants |
| `csv` | `.csv` plus a conservative messaging header set | exact RFC 4180 logical row without its final LF/CRLF; embedded quoted newlines remain | aliases for sender/recipient/body/time/direction and original row metadata |
| `messages-transcript` | `.txt` plus bracketed date/time and sender markers | exact marker-led message block, preserving original line endings | message/call kind, sender, body, time, direction when inferable |
| `imessage-txt` | `.txt` plus iMessage Exporter timestamp/sender structure | exact timestamp-led export block, preserving original line endings | message/call/event, sender, body, time, receipt and attachment references |
| `imessage-html` | `.html` plus stock iMessage Exporter or owner-export signatures | exact captured message/container span and associated sibling metadata | direction, sender, body, time, attachment references |
| `facebook-messenger-html` | `.html` plus Facebook/Messenger archive signatures | exact captured message container | sender, body, time, attachment references |
| `google-voice-html` | `.html` plus `hChatLog`/`hfeed` and message/`haudio` signatures | exact `div.message` or `div.haudio` element | message/call/voicemail, contact/tel, time, duration, labels, transcript, unresolved audio refs |
| `email-eml` | `.eml`, or conservative RFC 5322 headers | exact complete RFC 5322 message byte stream | headers/thread IDs, recipients, date when present, MIME text/HTML, file-spooled MIME children |
| `email-mbox` | `.mbox`/`.mbx` beginning with a conservative From_ line | exact From_-anchored span through the byte before the next separator | per-message EML projection, original separator, mailbox order |
| `google-chat-json` | `.json` plus `messages[]`, creator, and date/message ID signatures | exact JSON bytes of each object in `messages[]` | creator, date, text, IDs, reactions/raw fields, safe-but-unresolved companion refs |
| `facebook-messenger-json` | `message_N.json` plus participants and bounded deep validation, or `.json` with full thread/message signature | exact JSON bytes of each object in `messages[]` | source-order messages/events/calls/reactions, thread/participant context, media/sticker/share refs, reversible display repair |

NDJSON is streamed with a bounded line reader. Invalid JSON, non-object values,
and over-limit lines become durable rejection rows; processing resumes at the
next physical line. Unknown fields remain in `metadata`.

CSV is parsed by logical record, so a quoted body containing a newline remains
one record. SMS Backup & Restore numeric directions preserve `1=inbound` and
`2/4/5/6=outbound`; `3` remains unknown rather than being guessed. HTML uses a
streaming tokenizer and builds only the current bounded message fragment. It
does not fetch `href`/`src` targets or dereference any archive path.

Google Voice likewise records audio links without fetching them. Google Chat's
single-file plugin marks group/member/companion context unresolved; it does not
claim bundle completeness. EML/MBOX MIME attachments and inline CID parts are
decoded directly to files with independent hashes. Missing or invalid `Date`
headers remain null—no import or filesystem time is substituted.

Facebook JSON is processed in the source array's order and is never silently
reversed, even though Meta commonly exports newest-first. Each record carries a
zero-based source sequence and an observed export-order classification. The
importer spools exact message objects until trailing thread context has been
read, allowing fields that Meta places after `messages[]`—title, thread path,
participant state/type, and magic words—to accompany every projection without
holding or reordering the whole conversation in memory. That replay spool is a
temporary derived duplicate: on every importer exit it is closed and moved,
without overwrite or deletion, from the active `facebook-spools` directory to
the import-local `to_be_deleted` quarantine for owner review.

Historical latin1-over-UTF-8 strings receive a display repair only when the
round trip is reversible. Original decoded strings remain separately labeled,
and the raw JSON bytes remain the H2 source. Photos, videos, audio, files, GIFs,
stickers, and their creation timestamps are preserved as unresolved references.
The `your_facebook_activity/messages/` and `messages/` prefixes are removed only
from safe relative display paths; URL, drive, absolute, and traversal paths are
never resolved or fetched.

### Large MMS attachments

An SMS Backup & Restore MMS `data=` attribute follows a special streaming path:

- the exact raw `<mms>...</mms>` byte span is SHA-256 hashed incrementally;
- base64 is decoded directly into a private, import-scoped file;
- decoded bytes receive their own SHA-256 and byte count;
- the base64 value is replaced by a small marker in a sanitized XML spool used
  only for metadata projection;
- `SourceRecord.Raw` remains nil while `PrecomputedH2` and `RawSize` carry the
  exact custody result into the engine;
- originals live under `data/<user-id>/artifacts/import-<id>/attachments`, so
  equal per-user SQLite import IDs cannot collide across users.

The explicit base64 transfer buffer is 128 KiB and the import reader buffer is
64 KiB; neither grows with attachment or source size. A generated 8 MiB fixture
streams through an `io.Pipe` (the test never assembles the encoded record), then
independently verifies raw H2, decoded SHA-256, raw byte count, manifest byte
count, `Raw == nil`, and the on-disk file size. This proves the streaming code
path and its invariants. Processing a literal 5+ GiB fixture was not performed;
5 GiB behavior is an inference from the same constant-buffer loop and must also
be validated under deployment disk, proxy, timeout, and filesystem limits.

## API

All routes require the same authenticated `/api` session as the legacy UI.

### Import

`POST /api/imports` with multipart field `file` and optional field `format`.
The original bytes are retained under the user's data directory and never
rewritten. H1 is streamed from the retained file descriptor, that same
descriptor is rewound, and parsing consumes it without a path reopen between
custody and extraction. The request currently waits for completion and returns
HTTP 201:

```json
{
  "import_id": 42,
  "format": "ndjson",
  "chain_hash": "...",
  "claimed_count": null,
  "encountered_count": 3,
  "accepted_count": 2,
  "rejected_count": 1,
  "deduplicated_count": 0,
  "reconciliation": "unverified"
}
```

An unsupported format returns HTTP 422, but still returns the failed import ID;
its terminal error and preserved original are visible in the ledger.

The total multipart request body is capped by `SBV_MAX_IMPORT_BYTES`, expressed
as a positive base-10 byte count. The default is 8 GiB. Multipart framing
counts toward the limit; oversized requests return HTTP 413 and request-owned
temporary multipart files are cleaned when handling completes. Invalid size
configuration fails closed with HTTP 500 instead of silently disabling the cap.

### Inspect

- `GET /api/imports/formats` — registered plugins in explicit priority order.
- `GET /api/imports` — import ledger, newest first.
- `GET /api/imports/:id` — custody, state, counts, and reconciliation.
- `GET /api/imports/:id/records?limit=100&offset=0&kind=&status=` — canonical
  viewer page. `status` is `accepted` or `deduplicated`.
- `GET /api/imports/:id/rejections?limit=100&offset=0` — rejected records and
  bounded excerpts.
- `GET /api/imports/:id/attachments` — file-backed attachment manifests,
  including original name, MIME, decoded SHA-256, byte count, record H2/sequence,
  conversion state, and safe import-relative path.
- `GET /api/imports/:id/attachments/:attachmentID` — download one preserved
  decoded original. Add `?variant=derived` only when the manifest reports a
  completed derivative.
- `GET /api/imports/:id/attachments/export` — stream originals and completed
  derivatives in separate ZIP directories without loading them into memory.

The read APIs refuse implicit `latest`; the caller supplies a numeric import ID.
Page size is capped at 1,000.

The existing automation endpoint now uses the same universal engine. A
server-visible supported source is detected through the registry and the job
records the exact returned import ID rather than looking up the most recent row.

## Accounting

`imports` stores:

- claimed count (nullable; from a source manifest such as XML `count`),
- encountered = accepted + rejected + deduplicated,
- accepted,
- rejected,
- deduplicated,
- hashed (all complete raw spans folded into H3),
- `reconciled`, `discrepancy`, or `unverified` verdict,
- processing/completed/error state and terminal error,
- H1, H3, canon tag, original path, and timestamps.

`import_records` holds accepted and deduplicated canonical projections in source
order. `import_rejections` holds every importer-reported unusable record in the
same encounter sequence. Existing databases are widened idempotently; legacy
rows retain their stored `h3-chain-v1` label and are never restamped.

`import_attachments` binds each decoded original to import ID, record sequence,
and record H2. It records decoded SHA-256, byte count, MIME, safe relative path,
and conversion outcome. Completed derivatives separately record relative path,
SHA-256, MIME, and byte count. Custody H2 always remains the hash of the source
record, not the extracted attachment or any later derivative.

## Adding another format

Implement `Importer` in `internal/importer.go` and register it in `init()`.
Format plugins must:

- perform bounded-memory streaming;
- emit source records in original order;
- place the exact pre-normalization logical span in `SourceRecord.Raw`, or for
  streamed large spans provide exact `PrecomputedH2` plus `RawSize`;
- give each record a durable source position;
- call `Record` or `Reject` exactly once for every encountered logical record;
- never touch databases, the network, or external references;
- declare source counts through `Claim` when the format provides one;
- use an explicit detection priority and conservative content detection;
- preserve unknown fields in metadata instead of dropping them.

The engine, not the plugin, owns H2/H3, import identity, dedup disposition,
storage, progress, and reconciliation. A plugin must never calculate a hash
from a normalized object and present it as custody H2.

## Platform integration

The Python evidence spine must upload or invoke automation, retain the returned
`import_id`, fetch `/api/imports/:id`, and independently compare H1 against the
custody gate's raw artifact hash. It should read records and rejections by that
same ID, map accepted neutral records into `NormalizedRecord`, and save the SBV
canon tags and counts with the platform provenance. No call should use
`/api/activity` as an import result or `/api/hashes/latest` as attribution.

The Python `_sbv_client.py` now streams multipart from disk, retains the returned
ID, paginates by-ID records/rejections/attachments, and streams original
attachments back to disk with manifest hash/size verification and mismatch
quarantine. The SMS integration validates local H1, H1/H2/H3
canon tags, reconstructed H3, import identity, and disposition counts before it
maps records. Legacy activity/latest methods remain for old callers but are not
used for universal-import attribution. Live service-to-platform promotion still
requires a deployed-version integration test.

The platform's existing `facebook_messenger_json.py` remains a separate
whole-file parser and has not been redirected to SBV in this branch. Doing so
correctly requires a format-neutral version of the current SMS-specific
universal validation/mapping wrapper. Until that lands, Facebook JSON is a
worker/API capability rather than the registered platform `parse.facebook`
implementation; this is an explicit integration gap, not dual authority.

Knowledge horizons do not belong here. SBV extracts facts without forming
beliefs. The platform stores `occurred_at`, `knowledge_time`, and
`disclosure_tier` and applies horizon filters at the agent/retrieval boundary.

## Current foundation limits and next plugin matrix

- A file-to-file derivative worker uses a locally resolved `ffmpeg` executable
  for HEIC/HEIF→JPEG, legacy video→MP4, and AMR-class audio→MP3. Originals are
  never replaced. Derivatives receive independent hashes/MIME/byte counts.
  Outcomes are explicit: `completed`, `not_required`, `unavailable`, or
  `failed`; failed partial outputs are quarantined under the import's
  `to_be_deleted`. The legacy byte-slice converters are not used. Video/audio
  thumbnails are not generated in this phase.
- The MMS path is constant-buffer for the base64 `data=` attribute. The
  sanitized per-record XML projection can still grow with pathological giant
  *non-data* attributes or text. Those fields need separate streaming bounds
  before the parser can claim constant memory for arbitrary hostile XML.
- `data=` matching currently targets the lowercase SMS Backup & Restore schema.
  Namespace/case variants require fixtures and explicit support, not heuristic
  custody boundaries.
- The universal multipart endpoint is synchronous. Large deployments should add
  a durable job queue without changing import identity or custody semantics.
- The default request cap is 8 GiB, large enough for a 5 GiB source plus
  multipart framing. Proxy/timeouts/free-space/filesystem quotas must be sized
  separately; the cap alone is not a successful-ingest guarantee.
- SQLite remains the local inspection store. It is not the platform SSOT and
  should not receive Postgres/Neo4j/Weaviate credentials.
- Rejection storage keeps a bounded excerpt, not the entire rejected payload;
  the retained H1 source artifact is the complete original.
- The React `Evidence` view provides upload, import-ledger, custody hash,
  record-detail, rejection-detail, attachment download, and attachment ZIP
  export. It intentionally shows only the first 250 records/rejections per
  import; deeper paging remains available through the JSON API.

Implemented and follow-on source status:

| Source | Required logical record/custody boundary | Required projection work |
|---|---|---|
| Google Chat Takeout | **Partial:** exact objects in a single `messages.json`; bundle context visibly unresolved | creator, created time, text, reactions/IDs/raw fields; safe relative refs are not resolved or fetched |
| Google Voice HTML | **Implemented:** exact `hChatLog`/`hfeed` message or call container | `haudio`, `tel`, quoted text, conservative direction, call/voicemail/duration/transcript and local audio ref |
| Google Voice CSV | exact CSV logical row | explicit export headers and voice-specific call/message semantics rather than generic aliases alone |
| EML | **Implemented:** one exact RFC 5322 message byte stream | bounded MIME/header/text handling, thread headers, text alternatives, file-spooled attachments |
| MBOX | **Implemented:** exact From_-anchored spans including separator | per-message EML projection, mailbox order, separator metadata; conservative separator recognition |
| PST/OST | **Unsupported:** no `libpff`/`pffexport` was available | retain H1 and use a separately pinned external adapter later; no fake in-process support |
| Facebook JSON | **Implemented for one `message_N.json`:** exact message objects, full variant projection, source order retained | participant/thread context, timestamps when present, reactions, shares, calls/events, safe unresolved local refs; no archive companion export |

Safe ZIP/bundle Google Chat/Facebook companion ingestion, Google Voice-specific
CSV semantics, and PST/OST remain follow-up work and are not advertised.
