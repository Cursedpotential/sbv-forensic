import { useEffect, useState } from 'react'
import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8085/api'

function EvidenceImports() {
  const [imports, setImports] = useState([])
  const [selected, setSelected] = useState(null)
  const [records, setRecords] = useState([])
  const [rejections, setRejections] = useState([])
  const [attachments, setAttachments] = useState([])
  const [attachmentReferences, setAttachmentReferences] = useState([])
  const [needsCompanionBundle, setNeedsCompanionBundle] = useState(false)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const loadImports = async () => {
    const response = await axios.get(`${API_BASE}/imports`)
    setImports(response.data.imports || [])
  }

  const inspect = async (item) => {
    setSelected(item)
    setError('')
    try {
	  const [recordResponse, rejectionResponse, attachmentResponse] = await Promise.all([
        axios.get(`${API_BASE}/imports/${item.import_id}/records`, { params: { limit: 250 } }),
        axios.get(`${API_BASE}/imports/${item.import_id}/rejections`, { params: { limit: 250 } }),
		axios.get(`${API_BASE}/imports/${item.import_id}/attachments`),
      ])
      setRecords(recordResponse.data.records || [])
      setRejections(rejectionResponse.data.rejections || [])
	  setAttachments(attachmentResponse.data.attachments || [])
	  setAttachmentReferences(attachmentResponse.data.references || [])
	  setNeedsCompanionBundle(Boolean(attachmentResponse.data.needs_companion_bundle))
    } catch (err) {
      setError(err.response?.data?.error || err.message)
    }
  }

  useEffect(() => {
    loadImports().catch((err) => setError(err.response?.data?.error || err.message))
  }, [])

  const upload = async () => {
    if (!file) return
    setBusy(true)
    setError('')
    const body = new FormData()
    body.append('file', file)
    try {
      const response = await axios.post(`${API_BASE}/imports`, body, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 30 * 60 * 1000,
      })
      await loadImports()
	  const detail = await axios.get(`${API_BASE}/imports/${response.data.import_id}`)
	  await inspect(detail.data)
      setFile(null)
    } catch (err) {
      const detail = err.response?.data
      setError(detail?.error || err.message)
      if (detail?.import?.import_id) {
        await loadImports()
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="h-100 overflow-auto p-3">
      <div className="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
        <div>
          <h2 className="h5 mb-1">Evidence imports</h2>
          <div className="small text-muted">Import-scoped custody, parser dispositions, and neutral record inspection</div>
        </div>
        <div className="d-flex gap-2">
          <input
            className="form-control form-control-sm"
            type="file"
			accept=".xml,.ndjson,.jsonl,.json,.csv,.txt,.html,.htm,.eml,.mbox,.mbx,.zip"
            disabled={busy}
            onChange={(event) => setFile(event.target.files?.[0] || null)}
          />
          <button className="btn btn-primary btn-sm text-nowrap" disabled={!file || busy} onClick={upload}>
            {busy ? 'Importing…' : 'Import evidence'}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-danger py-2">{error}</div>}

      <div className="row g-3">
        <div className="col-xl-5">
          <div className="card">
            <div className="card-header fw-semibold">Import ledger</div>
            <div className="table-responsive">
              <table className="table table-sm table-hover mb-0 align-middle">
                <thead><tr><th>ID</th><th>File / format</th><th>Status</th><th>Counts</th></tr></thead>
                <tbody>
                  {imports.map((item) => (
                    <tr key={item.import_id} role="button" onClick={() => inspect(item)}
                      className={selected?.import_id === item.import_id ? 'table-primary' : ''}>
                      <td>{item.import_id}</td>
                      <td><div>{item.filename || 'legacy import'}</div><small className="text-muted">{item.format || 'legacy XML'}</small></td>
                      <td><span className={`badge ${item.status === 'error' ? 'text-bg-danger' : 'text-bg-secondary'}`}>{item.status}</span></td>
                      <td className="small">A {item.accepted_count} · R {item.rejected_count} · D {item.deduplicated_count}</td>
                    </tr>
                  ))}
                  {imports.length === 0 && <tr><td colSpan="4" className="text-muted p-3">No imports yet.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="col-xl-7">
          {!selected ? <div className="card card-body text-muted">Select an import to inspect its records and rejects.</div> : (
            <>
              <div className="card card-body mb-3">
                <div className="d-flex justify-content-between"><strong>Import {selected.import_id}</strong><span>{selected.reconciliation}</span></div>
                <code className="small text-break mt-2">H1 {selected.file_hash}</code>
                <code className="small text-break">H3 {selected.chain_hash || '(empty chain)'}</code>
                <div className="small text-muted mt-1">{selected.chain_canon}</div>
              </div>
              <div className="card mb-3">
                <div className="card-header fw-semibold">Records ({records.length} shown)</div>
                <div className="list-group list-group-flush">
                  {records.map((record) => (
                    <details className="list-group-item" key={record.id}>
                      <summary><span className="badge text-bg-light me-2">{record.seq}</span>{record.kind} · {record.status} · {record.content || '(no text)'}</summary>
                      <pre className="small mt-2 mb-0 text-wrap">{JSON.stringify(record, null, 2)}</pre>
                    </details>
                  ))}
                  {records.length === 0 && <div className="list-group-item text-muted">No accepted or deduplicated records.</div>}
                </div>
              </div>
              <div className="card">
                <div className="card-header fw-semibold text-danger">Rejections ({rejections.length} shown)</div>
                <div className="list-group list-group-flush">
                  {rejections.map((reject) => (
                    <details className="list-group-item" key={reject.id}>
                      <summary>{reject.source_pos}: {reject.reason}</summary>
                      <pre className="small mt-2 mb-0 text-wrap">{reject.raw_excerpt}</pre>
                    </details>
                  ))}
                  {rejections.length === 0 && <div className="list-group-item text-muted">No rejected records.</div>}
                </div>
              </div>
			  <div className="card mt-3">
				<div className="card-header d-flex justify-content-between align-items-center">
				  <span className="fw-semibold">Attachments ({attachments.length})</span>
				  {attachments.length > 0 && <a className="btn btn-sm btn-outline-primary" href={`${API_BASE}/imports/${selected.import_id}/attachments/export`}>Export all</a>}
				</div>
				<div className="list-group list-group-flush">
				  {attachments.map((attachment) => (
					<div className="list-group-item" key={attachment.id}>
					  <div className="d-flex justify-content-between"><span>{attachment.original_name}</span><span>{attachment.byte_count.toLocaleString()} bytes</span></div>
					  <small className="text-muted d-block">{attachment.mime_type || 'application/octet-stream'} · {attachment.conversion_status}</small>
					  <a className="btn btn-sm btn-link ps-0" href={`${API_BASE}/imports/${selected.import_id}/attachments/${attachment.id}`}>Original</a>
					  {attachment.conversion_status === 'completed' && <a className="btn btn-sm btn-link" href={`${API_BASE}/imports/${selected.import_id}/attachments/${attachment.id}?variant=derived`}>Viewable derivative</a>}
					  {attachment.conversion_error && <div className="small text-danger">{attachment.conversion_error}</div>}
					</div>
				  ))}
				  {attachments.length === 0 && <div className="list-group-item text-muted">No file-backed attachments.</div>}
				</div>
			  </div>
			  <div className="card mt-3">
				<div className="card-header fw-semibold">Companion references ({attachmentReferences.length})</div>
				<div className="list-group list-group-flush">
				  {needsCompanionBundle && <div className="list-group-item alert-warning">
					The source names companion files whose bytes were not supplied. Import the complete export ZIP, or explicitly attach its companion folder/ZIP; SBV will not search your computer automatically.
				  </div>}
				  {attachmentReferences.map((reference) => (
					<div className="list-group-item" key={reference.id}>
					  <div>{reference.display_text || reference.uri || reference.uri_original || '(unnamed attachment)'}</div>
					  <small className="text-muted">{reference.kind || 'file'} · {reference.resolution_status}</small>
					  {!reference.safe_relative && reference.resolution_status === 'unsafe_reference' && <div className="small text-danger">Unsafe path retained for evidence but never opened.</div>}
					</div>
				  ))}
				  {attachmentReferences.length === 0 && <div className="list-group-item text-muted">No unresolved companion references.</div>}
				</div>
			  </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default EvidenceImports
