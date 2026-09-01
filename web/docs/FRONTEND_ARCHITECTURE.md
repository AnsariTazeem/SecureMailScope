# Frontend Architecture

## Goals and boundaries

The frontend provides an accessible, responsive, evidence-first interface for
starting an offline capture assessment and, in later milestones, navigating a
validated Chain-of-Proof result. It does not analyze packets, calculate policy
findings, infer cryptographic properties, or repair missing evidence.

The current implementation covers the F1 workflow, the authorized F2A–F2G
result exploration milestones, and frozen V1 backend integration.

## App Router and route map

The shared root layout installs `AppProviders` and `AppShell`. Route files stay
small and delegate interactive behavior to feature components.

| Route | Rendering responsibility | Status |
| --- | --- | --- |
| `/` | Server redirect to `/analysis/new` | Implemented |
| `/analysis/new` | Start Analysis composition | F1 implemented |
| `/analysis/processing` | Completed API-result validation handoff | F1 implemented |
| `/analysis/complete` | Client result handoff and disclosure | F1 implemented |
| `/analysis/[analysisId]/overview` | Result overview | F2A implemented |
| `/analysis/[analysisId]/sessions` | Session index | F2B implemented |
| `/analysis/[analysisId]/sessions/[sessionId]` | Session detail | F2C implemented |
| `/analysis/[analysisId]/proof-map` | Evidence graph | F2D implemented |
| `/analysis/[analysisId]/findings` | Policy Risk and ML Anomaly | F2E implemented |
| `/analysis/[analysisId]/compare` | URL-backed two-session comparison | F2F implemented |
| `/analysis/[analysisId]/report` | Consolidated assessment report | F2G implemented |

Server Components are the default for route composition and static content.
Client Components are used only where browser APIs, file input, Zustand,
result handoff, or navigation events require them. Browser-only `File` objects stay in
memory and are never persisted.

## Layers and dependency direction

```text
App Router pages
  -> feature/layout components
    -> Zustand workflow actions + AnalysisDataSource interface
      -> MockAnalysisDataSource | ApiAnalysisDataSource
        -> Zod contracts
```

UI components may consume typed domain data, but contracts and data sources do
not import presentation code. Pages do not read prototype JSON directly. The
mock loader is the sole owner of prototype dataset loading and validates it at
runtime, preventing duplicated mock truth.

## Providers and shell

`AppProviders` is the client-side provider boundary. `AppShell` supplies the
desktop sidebar, mobile navigation, header, main landmark, and mock-dataset
banner. Analysis-aware navigation is disabled until an analysis identifier is
available and must not display invented result counts or states.

## Feature organization

- `components/analysis/` owns reusable workflow UI such as the step indicator,
  dropzone, selected capture card, validation list, authorization confirmation,
  assessment scope panel, and evidence boundary note.
- `components/analysis/report/` owns the narrow server-built F2G display model,
  consolidated report composition, and fail-closed report state. Its crypto
  surface is limited to the allowlisted observation/fact categories already
  established by Session X-Ray and Compare.
- `lib/contracts/` mirrors the approved Chain-of-Proof schema with Zod and
  exports inferred TypeScript types.
- `lib/api/` owns transport-independent data-source behavior and API errors.
- `lib/validation/` owns capture extension, cardinality, emptiness, and size
  checks shared by the UI and mock source.
- `stores/` owns only transient workflow state.

## Data-source boundary

`AnalysisDataSource` defines result reading; the real submission source also
creates analyses. `MockAnalysisDataSource` provides the deterministic, labelled
demo result. `ApiAnalysisDataSource` uses multipart `FormData`, then constructs
the frontend envelope from validated backend summary and Chain responses.
Network, HTTP, JSON, schema, or cross-response integrity failures remain visible.

Source selection is deterministic from the analysis ID. The fixed prototype ID
uses the mock source; every other valid analysis ID uses the real source. The UI
does not silently fall back from API data to mock data.

## Workflow data flow

```text
Capture/dropzone
  -> client intake validation
  -> explicit authorization confirmation
  -> ApiAnalysisDataSource.createAnalysis
  -> transient analysis ID in Zustand
  -> summary + Chain validation on /analysis/processing
  -> /analysis/complete disclosure
  -> validated evidence routes

Explore Demo
  -> select fixed PROTOTYPE_ANALYSIS_ID in Zustand (phase: processing)
  -> /analysis/processing simulated Prototype Demo stages
  -> phase: complete and /analysis/complete
  -> MockAnalysisDataSource.getResult
  -> labelled validated evidence routes and dashboard
```

The upload path accepts exactly one non-empty `.pcap` or `.pcapng` file within
the configured byte limit. Browser validation is an early usability check, not
a replacement for backend validation. The browser sets no multipart
`Content-Type` header manually.

Real processing supports loading, failure, missing-workflow, and retry
navigation without inventing backend stages, percentages, a queue, or polling.
The prototype-ID branch instead presents a short deterministic 0–100%
presentation sequence labelled **Prototype Demo** and **simulated**; it makes no
backend request and never claims that TShark is running. Completion supports
loading, unavailable-result, and honest prototype/API disclosure. Evidence
navigation preserves identifiers and explicit observability states from the
canonical result.

The F2G Report route follows the same trusted result path as Findings and
Compare: route-ID validation, `AnalysisDataSource.getResult`, Zod envelope
validation, graph-wide integrity validation, source/analysis identity checks,
and then a Report-only display model. That model exposes only rendered capture
identity, aggregate record counts, protocol coverage, allowlisted cryptographic
states, existing findings, graph counts, independent policy/ML state, declared
limitations, and explicit recommendations. It does not create findings,
evidence links, scores, recommendations, or export artifacts. The report JSON
and HTML endpoints documented in `INTEGRATION_CONTRACT.md` remain pending, so
F2G does not render working or simulated export controls.

## State and testing strategy

Zustand stores only the selected `File`, authorization choice, prototype choice,
analysis ID, accepted filename, workflow phase, and last error. Server-derived
Chain-of-Proof data is fetched through the data source instead of becoming a
second mutable source of truth.

Current verification uses TypeScript checking, ESLint, a production build, npm
audit, and diff whitespace checks. Focused automated tests should be added with
behavioral changes: validation unit tests, contract fixtures, data-source tests,
component accessibility interactions, and route-level happy/error journeys.
