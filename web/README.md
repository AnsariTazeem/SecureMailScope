# SecureMailScope frontend

SecureMailScope is an evidence-first interface for offline email-transport
capture assessment. This package contains the Next.js frontend only. It does
not perform packet analysis and must not infer security conclusions beyond the
validated Chain-of-Proof data it receives.

## Prerequisites

- Node.js 22.22.3
- npm 10.9.8

From `web/`:

```bash
npm install
npm run dev
npx tsc --noEmit
npm run lint
npm run build
npm audit
```

The development server is available at `http://localhost:3000` by default.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` | Base URL for real analysis submission and reads. |
| `NEXT_PUBLIC_MAX_CAPTURE_BYTES` | `536870912` | Browser-side capture size limit; defaults to the backend intake limit. |

The same build supports both sources. The fixed prototype analysis ID selects
the labelled **Prototype Analysis Dataset**; every other valid analysis ID uses
the configured production API. API failures never fall back to demo data.

## Routes

| Route | Current purpose |
| --- | --- |
| `/` | Redirects to the Start Analysis screen. |
| `/analysis/new` | F1 capture selection, validation, authorization, and prototype selection. |
| `/analysis/processing` | Synchronous API-result validation and failure handling. |
| `/analysis/complete` | F1 completion handoff and dataset disclosure. |
| `/analysis/[analysisId]/overview` | Analysis Overview — F2A implemented. |
| `/analysis/[analysisId]/sessions` | Sessions Explorer — F2B implemented. |
| `/analysis/[analysisId]/sessions/[sessionId]` | Session X-Ray — F2C implemented. |
| `/analysis/[analysisId]/proof-map` | Proof Map — F2D implemented. |
| `/analysis/[analysisId]/findings` | Findings — F2E implemented. |
| `/analysis/[analysisId]/compare` | Session Compare — F2F implemented. |
| `/analysis/[analysisId]/report` | Analysis Report — F2G implemented. |

Result routes choose their data source from the analysis ID, so production and
demo deep links work without persisted browser File objects.

## Structure

- `src/app/` — App Router route entry points and global layout
- `src/components/analysis/` — F1 workflow and reusable analysis UI
- `src/components/layout/` — application shell and navigation
- `src/components/ui/` — shared shadcn/ui primitives
- `src/lib/api/` — mock/API data-source implementations
- `src/lib/contracts/` — Zod runtime contracts and TypeScript types
- `src/lib/validation/` — browser-side capture intake rules
- `src/mocks/` — the single labelled prototype dataset
- `src/stores/` — transient client workflow state
- `docs/` — frontend architecture, UI, integration, and status records

See [Frontend Architecture](docs/FRONTEND_ARCHITECTURE.md),
[UI System](docs/UI_SYSTEM.md),
[Integration Contract](docs/INTEGRATION_CONTRACT.md), and
[Implementation Status](docs/IMPLEMENTATION_STATUS.md). Repository-wide
constraints live in [the root agent instructions](../AGENTS.md), and the
canonical production domain contract is
[the Chain-of-Proof specification](../docs/CHAIN_OF_PROOF_SPECIFICATION.md).

## Current limitation

The backend repository is in-memory at the frozen integration commit, so a real
analysis remains refresh/deep-link addressable only while that backend process
retains it. Prototype output is demonstration data, not a claim that a capture
was analyzed.
