# Frontend Client Contract — pending production API implementation

This document describes the HTTP boundary the frontend expects. It is a client
contract, not a claim that these endpoints exist or have passed integration
testing. The canonical backend domain remains the approved Chain-of-Proof
schema; backend truth wins if this draft conflicts with an implemented,
reviewed contract.

## Endpoints

| Method | Path | Expected responsibility |
| --- | --- | --- |
| `POST` | `/api/v1/analyses` | Validate authorization and capture intake, create an analysis, return its identifier. |
| `GET` | `/api/v1/analyses/{analysisId}/status` | Return queue/processing/completion/failure status. |
| `GET` | `/api/v1/analyses/{analysisId}/result` | Return the validated frontend result envelope. |
| `GET` | `/api/v1/analyses/{analysisId}/report.json` | Return canonical JSON report content. |
| `GET` | `/api/v1/analyses/{analysisId}/report.html` | Return HTML rendered from canonical JSON only. |
| `GET` | `/api/v1/health` | Return service readiness suitable for client diagnostics. |

## Create analysis

`POST /api/v1/analyses` uses `multipart/form-data`. The browser supplies:

- `capture`: exactly one non-empty `.pcap` or `.pcapng` file
- `authorized`: the string `true`, after explicit analyst confirmation

The browser must let `fetch` generate the multipart boundary and must not set
the `Content-Type` header manually. Backend validation remains authoritative.

Expected success payload:

```json
{
  "analysis_id": "ana_0123456789abcdef",
  "accepted_filename": "capture.pcapng"
}
```

The frontend adds `data_source: "api"` and a null prototype label only after
the payload validates. It does not infer that analysis has completed.

## Status

Expected phases are `queued`, `processing`, `complete`, and `failed`. A status
response contains:

- `analysis_id`
- `phase`
- nullable `current_stage`
- `percent` from 0 through 100
- ordered stage diagnostics defined by the Chain-of-Proof contract
- nullable typed error with `code` and safe `message`

Progress is descriptive service state, not evidence and not a security score.

## Result envelope

`GET /api/v1/analyses/{analysisId}/result` is expected to return:

```json
{
  "dataset_label": null,
  "dataset_kind": "production_analysis_result",
  "data_source": "api",
  "chain": {}
}
```

`chain` must validate against Chain-of-Proof schema `1.0.0`. The API owns
analysis results, evidence references, observability states, policy findings,
and anomaly outputs. The frontend owns presentation and navigation only.

Mock mode returns the same frontend envelope shape with
`dataset_kind: "prototype_analysis_dataset"`, `data_source: "mock"`, and the
exact label **Prototype Analysis Dataset**. API mode never silently falls back
to mock mode.

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
- Preserve `unknown`, `not_observable`, `not_assessable`, and `not_applicable`;
  do not render them as pass, fail, zero, or empty success.
- Ordinary passive TLS 1.3 captures do not make encrypted certificate contents
  observable without decryption material.
- Deterministic Policy Risk and ML Anomaly remain separate values, labels, and
  explanations. They are never summed or averaged into a new claim.
- Report HTML is a rendering of canonical JSON and must not calculate
  independent conclusions.

## Mode selection

`NEXT_PUBLIC_DATA_MODE=mock` selects the deterministic prototype source.
`NEXT_PUBLIC_DATA_MODE=api` selects this pending HTTP client using
`NEXT_PUBLIC_API_BASE_URL`. Mode is fixed by public configuration; runtime
failures do not switch modes.
