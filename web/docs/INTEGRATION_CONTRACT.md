# Frontend Client Contract — frozen production API integration

This document describes the frontend mapping to frozen backend commit
`f81bcc43ec660bfa32a40076bfe5c9f146d61339`. The canonical backend domain and
Chain-of-Proof schema remain authoritative.

## Endpoints

| Method | Path | Expected responsibility |
| --- | --- | --- |
| `POST` | `/api/v1/analyses` | Accept one capture, run synchronously, and return the analysis identifier/status. |
| `GET` | `/api/v1/analyses/{analysisId}` | Return the analysis summary. |
| `GET` | `/api/v1/analyses/{analysisId}/chain` | Return canonical Chain-of-Proof JSON. |
| `GET` | `/api/v1/health` | Return service readiness suitable for client diagnostics. |

## Create analysis

`POST /api/v1/analyses` uses `multipart/form-data`. The browser supplies:

- `capture`: exactly one non-empty `.pcap` or `.pcapng` file

The browser must let `fetch` generate the multipart boundary and must not set
the `Content-Type` header manually. Authorization confirmation is a frontend
control and is not a multipart field. Backend validation remains authoritative.

Expected success payload:

```json
{
  "api_version": "v1",
  "analysis_id": "ana_0123456789abcdef",
  "analysis_status": "complete"
}
```

The frontend retains the selected local filename separately for display; it
does not expect a filename from the backend response.

## Synchronous completion and reads

The submission call does not expose a queue or polling contract. After HTTP 201,
the frontend validates both the analysis summary and Chain response. Summary
identity, schema/status, engine statuses, object IDs, and counts must agree with
the Chain before a production `AnalysisResult` is constructed.

The frontend-owned result envelope is:

```json
{
  "dataset_label": null,
  "dataset_kind": "production_analysis_result",
  "data_source": "api",
  "chain": {}
}
```

`chain` is the validated response from `GET .../chain` and must satisfy
Chain-of-Proof schema `1.0.0`. The API owns
analysis results, evidence references, observability states, policy findings,
and anomaly outputs. The frontend owns presentation and navigation only.

The demo source returns the same frontend envelope shape with
`dataset_kind: "prototype_analysis_dataset"`, `data_source: "mock"`, and the
exact label **Prototype Analysis Dataset**. Real API failures never silently
fall back to the demo source.

## Errors and HTTP meanings

Error responses should provide a stable machine `code`, safe human `message`,
and optional field/stage context. The frontend must not expose stack traces or
replace an error with invented output.

| Status | Client interpretation |
| --- | --- |
| `400` | Malformed request. |
| `401` / `403` | Authentication/authorization refusal if such controls are later in scope. |
| `404` | Unknown analysis or report. |
| `409` | Analysis state conflict. |
| `413` | Capture exceeds the backend limit. |
| `415` / `422` | Unsupported capture or validation failure. |
| `429` | Service rate limit or capacity protection. |
| `500` | Internal failure; no result may be assumed. |
| `503` | Analyzer or required service unavailable. |

Transport failure, non-success HTTP, invalid JSON, and schema mismatch are
typed client failures. Retry behavior must be bounded and state-aware.

## Evidence and observability invariants

- Every displayed conclusion must come from validated result data and retain
  its evidence references.
- Preserve `unknown`, `not_observable`, `not_assessed`, and `not_applicable`;
  do not render them as pass, fail, zero, or empty success.
- Ordinary passive TLS 1.3 captures do not make encrypted certificate contents
  observable without decryption material.
- Deterministic Policy Risk and ML Anomaly remain separate values, labels, and
  explanations. They are never summed or averaged into a new claim.
- Report HTML is a rendering of canonical JSON and must not calculate
  independent conclusions.

## Source selection

Source selection is analysis-ID based in one build. The fixed
`PROTOTYPE_ANALYSIS_ID` resolves to `MockAnalysisDataSource`; every other valid
`ana_...` identifier resolves to `ApiAnalysisDataSource` using
`NEXT_PUBLIC_API_BASE_URL`. This makes route refreshes and deep links independent
of transient Zustand state. `NEXT_PUBLIC_DATA_MODE` is not used.
