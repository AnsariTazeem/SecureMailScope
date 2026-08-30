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
| `NEXT_PUBLIC_DATA_MODE` | `mock` | Selects the `mock` or reserved `api` data source. |
| `NEXT_PUBLIC_API_BASE_URL` | `http://localhost:8000` | Base URL used only in `api` mode. |
| `NEXT_PUBLIC_MAX_CAPTURE_BYTES` | `536870912` | Browser-side capture size limit; defaults to the backend intake limit. |

Mock mode is the currently supported F1 demonstration path. Every mock result
is labelled **Prototype Analysis Dataset**. API mode is a typed client boundary
for a production API that is not yet implemented or integration-verified; it
must fail honestly when that API is unavailable or returns invalid data.

## Routes

| Route | Current purpose |
| --- | --- |
| `/` | Redirects to the Start Analysis screen. |
| `/analysis/new` | F1 capture selection, validation, authorization, and prototype selection. |
| `/analysis/processing` | F1 deterministic progress and failure handling. |
| `/analysis/complete` | F1 completion handoff and dataset disclosure. |
| `/analysis/[analysisId]/overview` | Reserved placeholder for F2. |
| `/analysis/[analysisId]/sessions` | Reserved placeholder for a later milestone. |
| `/analysis/[analysisId]/sessions/[sessionId]` | Reserved session-detail placeholder. |
| `/analysis/[analysisId]/proof-map` | Reserved placeholder. |
| `/analysis/[analysisId]/findings` | Reserved placeholder. |
| `/analysis/[analysisId]/compare` | Reserved placeholder. |
| `/analysis/[analysisId]/report` | Reserved placeholder. |

Placeholder routes intentionally do not fabricate analysis content.

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

The production backend does not yet expose the documented frontend HTTP API.
Until that boundary is implemented and verified, only the clearly disclosed
prototype journey can complete. Prototype output is demonstration data, not a
claim that an uploaded capture was analyzed.
