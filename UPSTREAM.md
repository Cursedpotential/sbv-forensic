# vendored/sbv — SBV forensic fork provenance

> _Byline: Claude Code · Opus 4.8 · 2026-07-09_

This directory is a **git subtree** of our private forensic fork of SBV
("SMS Backup Viewer"), vendored at the repo root so it builds from source inside
the `platform-tools` image (see `docker/tools/Dockerfile`).

| | |
|---|---|
| **Upstream (original)** | `github.com/lowcarbdev/sbv` (MIT) |
| **Our fork (private mirror)** | `github.com/Cursedpotential/sbv-forensic` |
| **Vendored via** | `git subtree` (prefix `vendored/sbv`, `--squash`) |
| **Remote name** | `sbv-upstream` → `https://github.com/Cursedpotential/sbv-forensic.git` |
| **Last pulled tag** | `v0.1.11` (fork mirrors upstream full history + tags through v0.1.11) |
| **Vendored on** | 2026-07-09 |
| **Fork branch tracked** | `main` |

## What we changed vs. upstream

The fork adds a forensic chain-of-custody layer — **H1/H2/H3 hashing over the RAW
source bytes**, computed BEFORE any normalization — so our Python custody gate
(`server/evidence/custody.py`, `server/evidence/tools/sbv_sms.py`) can
cross-check and record court-admissible evidence hashes. SBV holds **no database
credentials**; it only computes the hashes and exposes them over its REST API.

Changed files (all under `vendored/sbv/`):

- `internal/custody.go` — **new**. `HashFileH1`, `HashRecordH2`, `ChainH3`, the
  `rawCaptureReader`, the `imports` table helpers, and the idempotent
  `content_hash` / `imports` migration. Full spec: **`CUSTODY.md`**.
- `internal/custody_test.go` — **new**. Determinism, known-answer, raw-not-
  normalized, and end-to-end streaming custody tests.
- `internal/parser.go` — H1 in `SaveUploadedFile` (streamed sha256 of raw bytes);
  H2 per raw `<sms>/<mms>/<call>` element + H3 chain in `ParseSMSBackupStreaming`;
  signatures carry the H1 through.
- `internal/database.go` — `content_hash` column on `messages` (H2), `imports`
  table (H1+H3+count), folded `content_hash` into the read payloads.
- `internal/models.go` — `ContentHash` on `Message` + `CallLog`.
- `internal/handlers.go` — `HandleHashes` (GET `/api/hashes/:importID`); upload
  carries H1 into background processing.
- `internal/autoimport.go` — auto-import path computes H1 too.
- `main.go` — registers `GET /api/hashes/:importID`.

Nothing else in the upstream source was modified: the build (`Dockerfile`) is
reproduced verbatim in `docker/tools/Dockerfile` (only COPY prefixes changed for
the repo-root build context).

## Updating from upstream (future pulls)

```bash
# From the repo root:
git fetch sbv-upstream main
git subtree pull --prefix=vendored/sbv sbv-upstream main --squash
# Re-apply/verify the custody hooks survived the merge; run:
#   cd vendored/sbv && go test ./...
# Then bump "Last pulled tag" + "Vendored on" above.
```

If the remote is missing (fresh clone):

```bash
git remote add sbv-upstream https://github.com/Cursedpotential/sbv-forensic.git
```

## License

Upstream SBV is MIT (see `LICENSE`). The fork preserves it.
