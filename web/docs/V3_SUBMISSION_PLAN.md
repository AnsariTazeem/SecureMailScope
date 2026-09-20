# V3-0 — Submission-mode safety

This slice refines the V2 checkpoint at `0b714063071d415b91b650aa6787d384062c2f62`
(`frontend-v2-ui-rc1`) on `feat/frontend-v3-submission`. It does not change the
prototype fixture, evidence projections, V2 CI, backend, or deployments.

## Operating modes

`NEXT_PUBLIC_SECUREMAILSCOPE_MODE` accepts exactly `submission_demo` and
`backend_connected`. An absent value defaults to `submission_demo`; an invalid
value throws a configuration error. Next.js inlines public environment values
at build time, so changing modes requires rebuilding.

In `submission_demo`, no API URL is required. The fixed prototype ID loads the
existing validated **Prototype Analysis Dataset**, a curated synthetic contract
fixture rather than a production analyzer result. Every other analysis ID is
refused locally before creating an API data source. The typed local error says:

> Live analysis results are not available in this evaluation build. No demo result was substituted.

The API URL accessor also refuses backend access in submission mode, protecting
the existing direct read/export transports before they reach `fetch()`. There is
no implicit localhost URL and no real-request-to-demo fallback. The requirement
is zero backend API requests; normal frontend documents, assets, and Next.js
navigation requests still occur.

To enable real analysis later, explicitly configure both variables before build:

```sh
NEXT_PUBLIC_SECUREMAILSCOPE_MODE=backend_connected
NEXT_PUBLIC_API_BASE_URL=https://your-analysis-service.example
```

The URL must be absolute HTTP(S) without credentials, query, or fragment. V2
capture validation, authorization, multipart submission, summary/Chain checks,
real deep links, and source-aware exports remain available in that mode.

## Evaluator capture interactions

Submission mode uses a separate capture component without the file-retaining
react-dropzone hook. Choosing a file immediately clears the native input. Only
the presence of a selection is checked; contents, filename, size, extension, and
other file properties are not read or validated. Capture-zone file drops and
file pastes open the shared disclosure without extracting File objects.

Files are **not uploaded, stored, or analyzed**. No selected filename is shown,
no File enters React/Zustand state, and no FormData or analysis result is created
by these interactions. The browser necessarily owns a transient native FileList
during selection; clearing the input releases the application's input reference.

A root-layout `beforeInteractive` safeguard prevents file-drop navigation before
hydration. The hydrated shared guard takes over without a listener gap and opens
one dialog for file drops throughout the application. Capture-zone marking avoids
duplicate disclosure. Ordinary text and link dragging is left alone. These guards
are inactive in backend-connected mode.

The dialog uses the existing Dialog/Button components, traps focus, supports
Escape and Close, and restores the initiating control or main landmark. Its
Explore Demo action uses the existing store action and Processing → Complete →
Overview flow. The original fixture, simulated-stage disclosure, Chain JSON
download, and browser Print / Save as PDF remain intact.

## Verification

Run sequentially from `web/` with the existing locked dependencies:

```sh
npx --no-install next typegen
npx --no-install tsc --noEmit
npm run lint
node scripts/verify-v2-models.mjs
node scripts/verify-proof-map-fit.mjs
node scripts/verify-proof-map.mjs
NEXT_PUBLIC_SECUREMAILSCOPE_MODE=backend_connected NEXT_PUBLIC_API_BASE_URL=https://example.invalid node scripts/verify-report-consistency.mjs
node scripts/verify-v3-submission-safety.mjs
npm run build -- --webpack
npm audit
```

The unchanged report harness must run in explicitly connected mode because it
tests API adapter/export responses with mocked fetch. It does not connect to a
backend. The V3 harness checks source boundaries, isolated configuration cases,
real module rejection paths with a zero-call fetch counter, demo/JSON identity,
picker/drop callbacks, and the actual early safeguard. These are automated source
checks, not live browser or production-backend evidence.

Browser acceptance covers picker and zone/outside/result-route drops; one dialog;
no filename or retained File; no backend requests; Close/Escape and focus return;
demo entry and result routes; local refusal of a real ID; JSON/print; desktop and
390px layouts. Run `git diff --check` from the repository root before handoff.

## Later phases

Visual refinement, colour-system decisions, logo/branding review, and deployment
planning remain separate work. V3-0 does not authorize deployment or backend work.

## V3-1 — Judge-ready end-to-end demo

V3-1 keeps submission mode local and fail-closed while making the complete
sample investigation easier to follow. File selection and file drops clear the
native input immediately, never enter application state, prevent navigation,
and open one accessible disclosure. Its primary action follows the existing
Processing → Complete → Overview workflow. The application header is the sole
compact result-page disclosure: **Sample analysis**, with accessible detail that
no uploaded file was analyzed.

The locally simulated processing sequence now presents six investigation stages.
The completion page directs reviewers to Overview, Findings, Proof Map,
Recommendations, and Report. Findings and Proof Map have their own navigation
destinations and active states.

The validated sample fixture declares the illustrative model
`illustrative-mail-flow-isolation-forest` version `1.0.0`, a complete anomaly
stage, and two anomaly records. Both records reference existing sessions, facts,
observations, and evidence. Their feature snapshots reproduce source session
counts and durations, and their limitations state that no trained model was
executed or calibrated against an organization baseline. Every record retains
the required interpretation that unusual behavior is not proof of malicious
activity. Policy Risk remains separate.

Recommendations now has two semantic sections: **Policy recommendations** and
**ML investigation guidance**. Guidance is projected from validated anomaly
records and shows the affected session, band, normalized score, unusual
indicators, evidence count, cautious analyst steps, and a link to the session
anomaly evidence. It is never stored as deterministic remediation.

Verification on 20 September 2026:

- Next route type generation, TypeScript, ESLint, V2 model checks, proof-map
  fit and integrity checks, V3 submission safety, the focused V3-1 fixture and
  rendering harness, report consistency, and the webpack production build
  passed.
- Root verification passed: 342 tests, with two existing skips because the
  frozen T01 PCAP is absent; Ruff lint and formatting checks passed.
- Isolated installed Chrome passed 49 live-route checks at desktop and 390px.
  The run covered file-input clearing, single-dialog drop handling, focus return,
  Processing → Complete, nine sample destinations, eight arbitrary-ID local
  refusals, both anomaly records in Findings and X-Ray, Proof Map and navigation
  identity, separate ML guidance, JSON identity, print invocation, responsive
  fit, and zero backend API requests.
- Browser results and screenshots are under `/tmp/sms-v31-*`; they are temporary
  local review artifacts and are not repository evidence or a backend-analysis
  claim.
- Current V3-1 fixture SHA-256:
  `bb656b509482c7ad847f3b1fa6ab4619668a66b4e36244ee841e09051ba3be9e`.
- No dependency, manifest, lockfile, backend, deployment, or Git-history change
  was made.

## Verification record

Verified during this implementation:

- Next route type generation, TypeScript, ESLint, all four unchanged V2 scripts,
  the V3 safety script, and the webpack production build passed.
- `npm audit` reported zero vulnerabilities.
- Installed Windows Chrome, using an isolated temporary profile and CDP, passed
  34 checks against the production build: native file-input selection/clearing,
  single disclosure for zone and outside drops, Close/Escape and focus return,
  existing demo entry, nine demo destinations, eight non-prototype route refusals,
  result-route drop protection, demo JSON identity, print-action invocation,
  390px dialog/page fit, and absence of browser API requests.
- Temporary browser acceptance evidence was generated locally and independently
  reviewed, but is not stored in the repository. The browser harness used a
  harmless input marker named `.pcap`; the application never validated it.
  Native file-input assignment and drag events were driven through CDP.
- The initial browser harness attached to Chrome's extension background target
  and navigation aborted. Selecting the page target corrected the harness;
  application code did not change.
- Browser printing was intercepted to verify `window.print()` invocation;
  native print-dialog behavior, screen-reader announcements, and native touch
  gestures were not verified. No heap-snapshot proof of retention is claimed:
  non-retention is established by the isolated intake code, executed handler
  checks, empty native FileList, and unchanged store entry behavior.
- Root regression checks passed: `uv run pytest -q` returned 342 passed and
  2 existing skips for the absent frozen T01 PCAP (11.27 seconds); Ruff check
  and formatting check passed. Initial sandbox attempts could not access the
  uv cache. The permitted retry created an ignored `.venv` and installed the
  existing locked dependencies there. This was an unintended verification
  side effect relative to the no-install constraint; manifests and lockfiles
  remained unchanged and no new dependency was added to the project.
- Historical V3-0 fixture snapshot SHA-256:
  `397eef272da3d4107267a43470d32a533921cf98c5273a8160d8257ea40f40c5`.
  This snapshot no longer describes the current fixture; V3-1 intentionally
  updates it with illustrative ML anomaly records.
- `git diff --check` passed. No commit, push, merge, tag, or deployment occurred.
