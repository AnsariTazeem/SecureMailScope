# Frontend Architecture

## Goals and boundaries

The frontend provides an accessible, responsive, evidence-first interface for
starting an offline capture assessment and, in later milestones, navigating a
validated Chain-of-Proof result. It does not analyze packets, calculate policy
findings, infer cryptographic properties, or repair missing evidence.

The current implementation covers the F1 workflow. Result exploration routes
exist only as explicit placeholders so navigation and URLs can stabilize
without implying that F2 or later milestones are complete.

## App Router and route map

The shared root layout installs `AppProviders` and `AppShell`. Route files stay
small and delegate interactive behavior to feature components.

| Route | Rendering responsibility | Status |
| --- | --- | --- |
| `/` | Server redirect to `/analysis/new` | Implemented |
| `/analysis/new` | Start Analysis composition | F1 implemented |
| `/analysis/processing` | Client polling/progress workflow | F1 implemented |
| `/analysis/complete` | Client result handoff and disclosure | F1 implemented |
| `/analysis/[analysisId]/overview` | Result overview | Placeholder; F2 pending |
| `/analysis/[analysisId]/sessions` | Session index | Placeholder |
| `/analysis/[analysisId]/sessions/[sessionId]` | Session detail | Placeholder |
| `/analysis/[analysisId]/proof-map` | Evidence graph | Placeholder |
| `/analysis/[analysisId]/findings` | Findings | Placeholder |
| `/analysis/[analysisId]/compare` | Comparison | Placeholder |
| `/analysis/[analysisId]/report` | Report access | Placeholder |

Server Components are the default for route composition and static content.
Client Components are used only where browser APIs, file input, Zustand,
polling, or navigation events require them. Browser-only `File` objects stay in
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
- `lib/contracts/` mirrors the approved Chain-of-Proof schema with Zod and
  exports inferred TypeScript types.
- `lib/api/` owns transport-independent data-source behavior and API errors.
- `lib/validation/` owns capture extension, cardinality, emptiness, and size
  checks shared by the UI and mock source.
- `stores/` owns only transient workflow state.

## Data-source boundary

`AnalysisDataSource` defines three operations: create an analysis, read its
status, and read its result. `MockAnalysisDataSource` provides a deterministic,
labelled F1 journey. `ApiAnalysisDataSource` is reserved for the pending HTTP
contract, uses multipart `FormData`, and accepts results only after Zod
validation. Network, HTTP, JSON, or schema failures remain visible failures.

Mode selection is configuration-driven through `NEXT_PUBLIC_DATA_MODE`. The UI
does not silently fall back from API mode to mock data.

## Workflow data flow

```text
Capture/dropzone or labelled prototype choice
  -> client intake validation
  -> explicit authorization confirmation
  -> AnalysisDataSource.createAnalysis
  -> transient analysis ID in Zustand
  -> status polling on /analysis/processing
  -> AnalysisDataSource.getResult
  -> /analysis/complete disclosure
  -> later evidence routes (pending)
```

The upload path accepts exactly one non-empty `.pcap` or `.pcapng` file within
the configured byte limit. Browser validation is an early usability check, not
a replacement for backend validation. The browser sets no multipart
`Content-Type` header manually.

Processing supports loading, progress, failure, missing-workflow, and retry
navigation states. Completion supports loading, unavailable-result, and honest
prototype/API disclosure. Future evidence navigation must preserve identifiers
and explicit observability states from the canonical result.

## State and testing strategy

Zustand stores only the selected `File`, authorization choice, prototype choice,
analysis ID, accepted filename, workflow phase, and last error. Server-derived
Chain-of-Proof data is fetched through the data source instead of becoming a
second mutable source of truth.

Current verification uses TypeScript checking, ESLint, a production build, npm
audit, and diff whitespace checks. Focused automated tests should be added with
behavioral changes: validation unit tests, contract fixtures, data-source tests,
component accessibility interactions, and route-level happy/error journeys.
