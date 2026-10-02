# Frontend Implementation Status

## Current state

- Branch: `feat/frontend-v1-backend-integration`
- Dependency foundation: completed and present in `web/package.json`
- F1 Start Analysis implementation: completed from the inherited partial
  foundation, including the shell, typed data-source boundary, upload workflow,
  processing and completion routes, and labelled prototype dataset
- F1 technical verification: complete
- F2A Analysis Overview: implemented and verified on 30 August 2026
- F2B Sessions Explorer: implementation and technical verification complete on
  30 August 2026
- F2C Session X-Ray: implemented and verified on 31 August 2026
- F2D Proof Map: implemented and verified on 31 August 2026
- F2E Findings: Policy Risk and ML Anomaly views implemented and technically
  verified on 31 August 2026
- F2F Secure vs Insecure Session Compare: implemented and technically verified
  on 31 August 2026
- F2G Analysis Report: implemented and technically verified on 31 August 2026
- Production frontend API adapter: implemented against frozen backend commit
  `f81bcc43ec660bfa32a40076bfe5c9f146d61339` on 1 September 2026
- V1 judge-ready Report download/print actions: implemented and technically
  verified on 1 September 2026
- V1 two-path entry flow and simulated Prototype Demo processing: implemented
  and technically verified on 1 September 2026

## V1 backend integration verification record

The same V1 build now routes `PROTOTYPE_ANALYSIS_ID` to the labelled mock
dataset and all other valid analysis IDs to the real API. Real submission sends
only the `capture` multipart field, validates the synchronous HTTP 201 response,
then validates and cross-checks `GET /api/v1/analyses/{analysis_id}` with
`GET /api/v1/analyses/{analysis_id}/chain`. Demo selection creates no File and
makes no API request.

| Check | Result on 1 September 2026 |
| --- | --- |
| `npm run lint` | Passed with zero reported warnings or errors. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, TypeScript, static generation, and all route generation completed. |
| `git diff --check` | Passed. |
| Frozen backend contract inspection | Confirmed HTTP 201 submission fields (`api_version`, `analysis_id`, `analysis_status`), one multipart part (`capture`), synchronous orchestration, summary/Chain read routes, and stable error envelope at the pinned commit. Backend files were read only. |
| Additional loopback smoke attempt | Blocked by the workspace sandbox (`listen EPERM`); no route-smoke PASS is claimed for this integration change. |

## V1 two-path entry and Prototype Demo processing verification record

Start Analysis now exposes only two journeys. A selected PCAP/PCAPNG still
requires explicit authorization before the unchanged
`ApiAnalysisDataSource.createAnalysis` submission and real summary/Chain
validation flow. **Explore Demo** requires neither a File nor authorization: it
sets `PROTOTYPE_ANALYSIS_ID`, `usingPrototypeDataset=true`, and
`phase=processing`, then navigates through Processing and Complete before the
existing dashboard opens the validated **Prototype Analysis Dataset** through
`MockAnalysisDataSource`.

The prototype-only Processing branch advances deterministically through five
visible presentation stages and 0–100% progress. Its copy identifies
**Prototype Demo**, **simulated processing**, and explicitly states that no
backend request or TShark analysis is running. The real branch retains its
existing indeterminate summary/Chain validation UI and has no stage simulation
or percentage. No real-to-demo fallback exists.

| Check | Result on 1 September 2026 |
| --- | --- |
| `npx tsc --noEmit` | Passed with no diagnostics. |
| `npm run lint` | Passed with zero reported warnings or errors. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, TypeScript, static generation, and all route generation completed. |
| `npm audit` | Passed with zero vulnerabilities. |
| `git diff --check` | Passed. |

The discarded bundled SMTP third path, its static asset, and its ignore-rule
exception were removed. No browser automation or deployment verification was
performed. No backend, V2, report/export, dependency, or lockfile change was
made.

## V1 Report export verification record

The existing V1 Report now exposes a compact, source-aware action area without
changing the report design or turning the server-rendered workspace into a
Client Component. Real Chain downloads fetch the authoritative
`GET /api/v1/analyses/{analysis_id}/chain` response, validate it with the
existing frontend Chain contract and analysis identity, and preserve the
response bytes. Prototype downloads serialize only the already validated
Prototype Analysis Dataset Chain, use the demo-labelled
`{analysis_id}.demo-chain.json` filename, and make no production request.

The whole-report action is labelled exactly **Print / Save as PDF** and invokes
the browser print dialog; it is not represented as a server-generated artifact.
Minimal print rules hide the application shell navigation and export controls,
remove report shadows, and retain readable report content. Each displayed real
finding exposes backend-produced PDF and HTML downloads through the frozen
artifact endpoint. Demo findings expose no production artifact controls, and a
zero-finding real result still retains the Chain and print actions.

Download failures map backend unavailability, missing artifacts, response-size
limits, rendering failures, and invalid MIME/Chain responses to bounded UI
messages without exposing backend internals or substituting demo content.

| Check | Result on 1 September 2026 |
| --- | --- |
| `npx tsc --noEmit` | Passed. |
| `npm run lint` | Passed with zero reported warnings or errors. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, TypeScript, static generation, and all route generation completed. |
| `npm audit` | Passed with zero vulnerabilities. |
| `git diff --check` | Passed. |
| Frozen backend inspection | Confirmed backend HEAD remained `f81bcc43ec660bfa32a40076bfe5c9f146d61339`; Chain and finding-artifact routes, media types, response limits, and attachment filenames were inspected read-only. |

No browser executable or browser-test dependency is present, so the native
save dialog, print-preview pagination, and cross-origin download interaction
were not browser-automated. The production build and compiled client paths were
verified; no deployment, backend mutation, V2 change, dependency change,
staging, commit, or push was performed.

## Verification record

| Check | Last observed result |
| --- | --- |
| `npx tsc --noEmit` | Passed with Node.js 22.22.3. |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; all required F1 and placeholder routes were generated. |
| `npm run build -- --webpack` | Passed as additional verification using the webpack build path. |
| `npm audit` | Passed with zero vulnerabilities after registry access was permitted. |
| Local route smoke test | Passed on `127.0.0.1:3017`; all required F1 and placeholder pages returned HTTP 200 with expected markers, and `/` contained Next.js redirect metadata for `/analysis/new`. The server was stopped afterward. |
| `git diff --check` | Passed for this documentation-only correction. |

These entries report command outcomes only; they do not prove backend
integration or cryptographic correctness.

## F2A Analysis Overview verification record

The Overview now fetches through `AnalysisDataSource`, re-validates the result
with the existing Zod contract, and renders identity/status, capture integrity,
session/protocol/TLS-transition summaries, separate Policy Risk and ML Anomaly
state, passive-observation boundaries, prioritized session links, declared
limitations, and explicit loading/not-found/failure/empty states.

| Check | Observed result on 30 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed with Node.js 22.22.3 and TypeScript 5.9.3. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript checking, static generation, and all application routes completed. |
| `npm run build -- --webpack` | Passed with Next.js 16.3.3; compilation, build-time TypeScript checking, static generation, and route generation completed. The Overview was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities after registry access was permitted. |
| Loopback route smoke test | Passed on `127.0.0.1:3018`. The prototype Overview, invalid-ID state, and linked Session X-Ray placeholder returned HTTP 200 with their expected markers. The streamed invalid-ID response also contained `robots=noindex`. The server was stopped afterward. |
| `git diff --check` | Passed. |

## F2B Sessions Explorer verification record

The Sessions Explorer now fetches through `AnalysisDataSource`, re-validates
the result with the existing Zod contract, and renders validated session
identity, endpoint, protocol, capture, completeness, explicit TLS-transition,
linked-policy-finding, and transition-observability metadata. It provides
deterministic search, required filters, TanStack Table sorting, responsive
desktop and compact mobile presentations, stable Session X-Ray links, and
explicit loading/not-found/failure/empty/no-results states. The browser receives
only the narrow metadata view model needed by the explorer.

| Check | Observed result on 30 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed with Node.js 22.22.3 and TypeScript 5.9.3. |
| `npm run build` | Passed after the final F2B source changes with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript checking, static generation, and all application routes completed. |
| `npm run build -- --webpack` | Passed after the final source change with Next.js 16.3.3; compilation, build-time TypeScript checking, static generation, and all route generation completed. Sessions Explorer was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities after registry access was permitted. |
| Loopback route smoke test | Passed on `127.0.0.1:3021`. The prototype Sessions Explorer, invalid-analysis state, and unchanged Session X-Ray placeholder returned HTTP 200 with expected markers. Both stable fixture session IDs, TLS-transition labels, linked-finding states, `not_run` ML state, and prototype disclosure were present. The invalid route contained `robots=noindex`. The server was stopped afterward. |
| `git diff --check` | Passed. |

## F2C Session X-Ray verification record

Session X-Ray now fetches and re-validates the existing AnalysisResult envelope,
fails closed through a typed graph-integrity validator, preserves contract event
and evidence ordering, and renders session identity, typed protocol events,
cryptographic observations and facts, TLS 1.3 certificate observability,
direct and through-source evidence relationships, deterministic policy findings,
separate ML Anomaly state, and declared limitations. No contract, prototype
fixture, API shape, dependency, or package configuration was changed for the
F2C correctness correction.

| Check | Observed result on 31 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed with Node.js 22.22.3 and TypeScript 5.9.3. |
| Focused graph-integrity verification | Passed against in-memory copies of the validated prototype result after compiling the pure TypeScript view-model modules to `/tmp`. Verified duplicate IDs, unresolved evidence, cross-session and cross-capture evidence, unresolved fact sources, broken finding/evaluation and finding/recommendation relationships, fact-source cycles, valid transitive fact evidence, duplicate sequence-index occurrence ordering, explicit `not_observable`, Forward Secrecy `not_assessed`, neutral capability labelling, and frame-array order. The canonical fixture was not modified. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript checking, static generation, and all route generation completed. Session X-Ray was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities. |
| Loopback production smoke test | Passed on `127.0.0.1:3139`. Both prototype Session X-Ray routes, Sessions Explorer links, secure TLS state, insecure plaintext-continuation state, Forward Secrecy `Not assessed`, TLS 1.3 certificate `not observable` disclosure, evidence-inspector markers, invalid analysis/session routes, and streamed `robots=noindex` metadata were verified. The unsupported `TLS capability advertised` label was absent. The server was stopped afterward. |
| `git diff --check` | Passed after the F2C source correction. |

## F2D Proof Map verification record

The Proof Map now fetches through `AnalysisDataSource`, re-validates the result
with the existing Zod envelope, and fails closed through a graph-wide integrity
validator. The primary visualization is one deduplicated interactive
`@xyflow/react` canvas with deterministic capture, session, evidence, transition
event, observation, derived fact, and policy-finding lanes. Positions use only
entity type, declared session ownership, sequence/frame occurrence, and stable
ID; layout does not create relationships. Direct evidence is solid restrained
green, transitive fact sources are dashed slate and labelled exactly **Evidence
through declared sources**, and deterministic policy edges are purple. Policy
Risk and ML Anomaly remain separate, and no anomaly edge is inferred.

The selector exposes All sessions and each individual session, defaults to the
session with the declared finding, and filters entity/state visibility without
reconnecting edges. Node and edge inspectors use responsive Sheets and reuse the
Session X-Ray evidence inspector for safe evidence. The approximately `68dvh`
mobile canvas retains pan/zoom controls and hides its minimap; the exact
per-session ledger remains collapsed below the canvas. The large duplicate
direct-evidence grid and repeated declared-path rows are removed.

Validated prototype graph counts are: secure session
`ses_05a2650d13a55335`, 30 nodes / 36 canvas edges; insecure session
`ses_3ac703c890cdeada`, 15 nodes / 21 canvas edges; All sessions, 45 deduplicated
nodes / 57 canvas edges. The full ledger remains 61 relationships because four
explicit rule-evaluation relationships are retained in the audit fallback
without introducing a separate rule-evaluation lane on the requested canvas.

| Check | Observed result on 31 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors after the interactive-canvas correction. |
| `npx tsc --noEmit` | Passed after the interactive-canvas correction. |
| Focused graph-integrity verification | Passed against in-memory copies of the prototype result after compiling the pure validator to `/tmp`. Verified the valid graph and rejection of unresolved evidence, cross-session fact sources, fact-source cycles, contradictory Policy Risk contributions, and unresolved explicit anomaly links. The canonical fixture was not modified. |
| `npm run build` | Passed against the final source with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript, static generation, finalization, and all route generation completed. Proof Map was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities. |
| Loopback production smoke test | Passed on the final production build at `127.0.0.1:3146`. Verified the valid Prototype Analysis Dataset Proof Map, invalid analysis-ID state and `noindex`, prioritized default scope, all three node/edge count pairs, React Flow canvas/control markup, exact transitive label, collapsed ledgers, TLS 1.3 session-secrets limitation, distinct state vocabulary, removal of repeated path/direct-evidence grids, and absence of fixture-only unsafe normalized-value markers. Direct Session X-Ray routes for both prototype sessions and the Findings placeholder were also reachable during loopback checks. The server was stopped afterward. |
| `git diff --check` | Passed. |

F2D is implemented and verified through lint, TypeScript, focused integrity
checks, the default Turbopack production build, audit, and loopback smoke
coverage. No browser executable or browser-test dependency is present in the
workspace, so pointer/touch gestures, responsive Sheet placement, focus return,
and screenshot-level desktop/mobile appearance were not browser-automated in
this verification record; the responsive markup and compiled interaction paths
were inspected instead.

## F2E Findings verification record

Findings now provides two independent URL-backed views at
`/analysis/[analysisId]/findings?view=policy` and `?view=ml`, with Policy Risk
as the default when the query is absent or unsupported. The server loads through
`AnalysisDataSource`, re-validates the existing Zod envelope, applies the
graph-wide integrity validator, and sends the client only narrow display view
models. No dependency, contract, fixture, or API shape changed.

The Policy Risk view renders contract-declared capped and uncapped scores,
profile, findings, severities, contributions, categories, rule identities and
evaluation outcomes, sessions, direct evidence, evidence reached through
declared sources, rationale, impact, remediation, recommendations, and stable
Session X-Ray and Proof Map links. It provides search, contract-value filters,
TanStack Table sorting, readable mobile cards, and a responsive detail Sheet
that reuses the safe Session X-Ray evidence inspector.

The ML Anomaly view renders its engine status and model/results only when
supplied, with separate ML search, filters, sorting, result cards, and inspector
for validated non-empty results. The prototype correctly renders **ML anomaly
engine was not run** with no model, anomaly score, anomaly result, or ML
evidence edge; Policy Risk is neither copied into nor combined with ML output.

| Check | Observed result on 31 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed. |
| Contract and relationship review | Passed against the existing validated contract and graph-wide Proof Map integrity validator. Direct finding/anomaly evidence is selected only from explicit evidence IDs; through-source evidence is selected only from declared linked fact or observation source paths. Severity and Policy Risk contribution remain separate contract fields. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript, static generation, finalization, and all route generation completed. Findings was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities. |
| Loopback production smoke test | Passed on `127.0.0.1:4317` for explicit `view=policy` and `view=ml`. Verified the prototype label, Policy Risk value and profile, validated finding and session navigation, ML `not_run` copy, absence of ML numeric score/result/evidence fields, fail-closed invalid and unknown analysis states, `noindex, nofollow`, and absence of payload, credential, secret, decrypted-content, normalized-value, and feature-snapshot markers. The server was stopped afterward. |
| `git diff --check` | Passed before the status update and rerun afterward. |

No browser executable or browser-test dependency is present, so screenshot-level
desktop/mobile appearance, hydration-console output, pointer interaction, and
focus return were not browser-automated. Responsive table/card and Sheet markup,
accessible controls, URL state transitions, and compiled interaction paths were
reviewed directly.

## F2F Session Compare verification record

Session Compare now loads and re-validates the existing `AnalysisResult`
through `AnalysisDataSource`, applies the graph-wide integrity validator, and
builds a narrow display model on the server. Session A and Session B are backed
by `a` and `b` URL parameters; omitted parameters receive a deterministic pair,
while malformed, repeated, or unavailable supplied IDs fail closed without a
fallback substitution.

The workspace renders identity and capture provenance, declared email-to-TLS
transitions, a bounded allowlist of cryptographic observations and facts,
separate deterministic Policy Risk and ML Anomaly sections, explicit evidence
references, and declared limitations. Desktop tables and mobile stacked cards
represent the same exact rows. Differences compare only displayed values and
declared states; they do not create security labels or evidence relationships.
Evidence is resolved only through explicit contract references and uses the
existing safe evidence inspector. No contract, prototype fixture, API shape,
dependency, or completed page changed.

| Check | Observed result on 31 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript, static generation, finalization, and all route generation completed. Compare was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities. |
| Contract and privacy review | Passed. Comparison-normalized values are limited by type to TLS version, cipher suite, key-share group, PSK exchange mode, and the TLS 1.3 certificate-unavailable marker. Facts are limited to TLS upgrade completion, Forward Secrecy, and certificate observability. Evidence relationships use explicit IDs or declared fact sources only. |
| Loopback production smoke test | Passed on the final build at `127.0.0.1:3203`. The default, explicit, and direct swapped `a`/`b` pairs returned HTTP 200 and preserved the expected Session A/B IDs. Verified 19 exact displayed differences, all six categories, both responsive layout branches, TLS 1.3 and `session_secrets_required`, `not_observable`, `not_assessed`, ML `not_run`, separate Policy Risk/ML copy, prototype disclosure, and Session X-Ray, Proof Map, and Policy Findings links. An unavailable but well-formed session selector returned the explicit selection failure with `noindex, nofollow`; the malformed analysis route returned the streamed route not-found state with noindex metadata. Explicit unsafe fixture fields and raw normalized-value markers were absent. The server was stopped afterward. |
| `git diff --check` | Passed after the documentation update. |

No browser executable or browser-test dependency is present. Screenshot-level
desktop/mobile appearance, hydrated selector clicks, focus behavior, and browser
console output were not automated. Both responsive representations and the
compiled URL navigation/swap path were inspected, and both selector orders were
verified through direct production HTTP requests.

## F2G Analysis Report verification record

The Report route now loads and re-validates the existing `AnalysisResult`
through `AnalysisDataSource`, applies the graph-wide integrity validator, checks
the result source and analysis identity, and builds a narrow Report display
model on the server. The route renders validated analysis/capture provenance,
four evidence-backed executive metrics, responsive communication coverage, and
only the TLS/crypto observation and fact categories already allowlisted by
Session X-Ray and Compare.

The final document also renders the existing severity-ordered deterministic
findings, safe Chain-of-Proof entity counts, separate Policy Risk and neutral ML
Anomaly state, declared observability limitations, explicit contract
recommendations, and analysis-scoped links to Overview, Sessions, Proof Map,
Findings, and Compare. No overall security score, new finding, inferred evidence
relationship, fabricated certificate field, generic recommendation, dependency,
contract change, fixture change, or simulated export action was introduced.

| Check | Observed result on 31 August 2026 |
| --- | --- |
| `npm run lint` | Passed with zero warnings and zero errors. |
| `npx tsc --noEmit` | Passed. |
| `npm run build` | Passed with Next.js 16.3.3 Turbopack; compilation, build-time TypeScript, static generation, finalization, and all route generation completed. Report was emitted as a dynamic server-rendered route. |
| `npm audit` | Passed with zero vulnerabilities. |
| Contract and privacy review | Passed. Report-normalized values are limited by type to TLS version, cipher suite, key-share group, PSK exchange mode, and the TLS 1.3 certificate-unavailable marker. Facts are limited to TLS upgrade completion, Forward Secrecy, and certificate observability. Finding evidence counts use explicit finding references; the Report creates no evidence edges. |
| Loopback production smoke test | Passed on the final build at `127.0.0.1:3204`. The validated prototype Report, Overview, and Policy Findings routes returned HTTP 200. Verified exact analysis/capture identities and hashes, 2 sessions, 1 represented email protocol family, 1 deterministic finding, 2/2 allowlisted crypto coverage, separate Policy Risk and ML Anomaly sections, neutral ML `not_run`, TLS 1.3 `not_observable`/`session_secrets_required` semantics, explicit recommendation content, and correctly scoped Overview, Sessions, Proof Map, Findings, and Compare links. Malformed and unavailable analysis IDs followed the established streamed not-found convention (HTTP 200 with `noindex`) and displayed no report conclusion. Unsafe fixture details, raw normalized-field names, fabricated certificate metadata, and simulated JSON/HTML/PDF export labels were absent. The server was stopped afterward. |
| `git diff --check` | Passed after the F2G documentation update and rerun after the final verification wording. |

No browser executable or browser-test dependency is present. Screenshot-level
desktop/mobile appearance, browser hydration, keyboard/focus behavior, and
browser-console output were not automated. Responsive desktop/mobile markup and
server-rendered link/state output were inspected through the compiled source and
production HTTP responses.

## Blockers and limitations

- The real adapter is contract-verified against frozen backend source but a
  live frontend-to-backend browser smoke test was not run in this workspace.
- The clearly labelled **Prototype Analysis Dataset** is a synthetic contract
  fixture and does not analyze or upload a capture.
- The generated route smoke tests passed, but the stateful Start → Processing →
  Complete → Overview → Sessions interaction has not been exercised by an
  automated browser test.
- No frontend unit-test framework is installed. F2C graph-integrity edge cases
  were therefore exercised with dependency-free, type-checked local
  verification against in-memory fixture copies; automated browser component
  tests remain absent.
- F2A Overview, F2B Sessions, F2C Session Detail, F2D Proof Map, F2E Findings,
  F2F Compare, F2G Report, and the V1 production API adapter are implemented.
- The frozen backend repository is in-memory at this milestone, so real IDs
  remain refresh/deep-link addressable only while the backend process retains
  the corresponding Chain.

## Next exact milestone action

The authorized V1 backend-integration slice is implemented and locally
verified. Deployment, backend mutation, V2 work, and additional frontend scope
require separate authorization.

## Frontend dependency security maintenance (2026-10-01)

Scope: the existing V1 interface on `fix/frontend-dependencies`, based on
`da8c4b7`; no interface, data-contract, backend, or fixture changes.

| Dependency | Previous resolution | Updated resolution |
| --- | --- | --- |
| next / eslint-config-next | 16.3.3 | 16.3.8 |
| brace-expansion | 1.1.18 / 5.0.9 | 1.1.21 / 5.0.12 |
| fast-uri | 3.1.6 | 3.1.8 |
| hono | 4.13.5 | 4.13.12 |
| ip-address | 10.7.0 | 10.7.2 |
| undici | 7.29.0 | 7.30.0 |

The lockfile was generated through npm, without `--force` or dependency
overrides. Its regeneration also filled six transitive entries in the existing
Tailwind WASM dependency tree. No direct dependency was added.

| Verification | Actual result |
| --- | --- |
| `npm ci` | Passed; zero reported vulnerabilities. Existing ESLint 9 deprecation warning remains. |
| `npm run lint` | Passed. |
| `npx --no-install tsc --noEmit` | Passed. |
| `npm run build` | Passed with Next.js 16.3.8 Turbopack and all listed routes. |
| `npm audit --json` | Zero vulnerabilities at every severity. |
| `uv run --locked pytest -q` | 342 passed, 2 frozen-T01-PCAP-dependent skips, 48.06 seconds. |
| Ruff lint / formatting | Passed; 65 files already formatted. A WSL connection timeout affected the first formatting-check launch; the later launch passed. |
| `git diff --check` | Passed. |
| Local production HTTP smoke | Ten routes returned 200; prototype provenance remained visible on Overview and Report. Server stopped afterward. |

The HTTP check covered `/`, `/analysis/new`, `/analysis/processing`,
`/analysis/complete`, and Overview, Sessions, Proof Map, Findings, Compare,
and Report for the existing `ana_c0ffee0000000001` prototype. No capture was
uploaded. Browser hydration, interactive clicks, and live API integration were
not tested by this security slice. No staging, commit, push, merge, or
deployment was performed.

## Upload entry layout refinement (2026-10-02)

Scope: `feat/frontend-refinement`, based on released `main` at `fcb6c7b`.
The only implementation files changed are `app-shell.tsx` and `app-header.tsx`.

- Entry route `/analysis/new`: desktop sidebar, mobile navigation trigger,
  and header New analysis action are omitted; a linked SecureMailScope identity
  remains, following the V3 entry-header reference.
- Homepage: the existing redirect to `/analysis/new` is preserved.
- Processing, completion, and result routes retain their current navigation.
- File selection, authorization, real API submission, Explore Demo, data-source
  selection, result rendering, dependencies, and fixtures remain unchanged.

| Verification actually executed | Result |
| --- | --- |
| `npm ci --offline --no-audit --no-fund` | Passed; installed 665 existing locked packages from cache. Existing ESLint 9 deprecation warning remains. |
| `npm run lint` | Passed. |
| `npm run build` | Passed with Next.js 16.3.8 Turbopack and all routes. |
| `npx --no-install tsc --noEmit` | Passed. |
| `npm audit --json` | Zero vulnerabilities at every severity. |
| `uv run --locked --offline pytest -q` | 342 passed, 2 frozen-T01-PCAP-dependent skips in 21.00 seconds. |
| Ruff lint and format checks through locked offline uv | Passed; 65 files already formatted. |
| `git diff --check` | Passed. |
| Parsed production HTTP route checks | 11 routes returned 200; entry navigation absent, processing/completion/results navigation preserved, file input and Explore Demo retained. |
| Windows localhost reachability | Upload page returned 200. |

The HTTP check covered `/`, `/analysis/new`, a query-string variant,
Processing, Complete, and the existing prototype Overview, Sessions, Proof Map,
Findings, Compare, and Report. Result routes retain Prototype Analysis Dataset
provenance. An initial assertion expected upload controls on the homepage;
after observing its existing meta redirect, the check explicitly verifies that
redirect and the destination independently.

Browser initialization failed with Windows sandbox helper setup errors, so
visual screenshots, hydrated navigation, responsive interaction, and live API
uploads were not automated. The local production preview is running on port
4181 for user review. No staging, commit, push, merge, or deployment occurred.


## Verified frontend refinement — centered upload entry (2026-10-02)

- Authorized frontend-only slice on local `feat/frontend-refinement`, based on
  `main` at `fcb6c7b`; no stage, commit, push, merge, or deployment performed.
- Adopted V3's centered single-card capture layout and concise entry heading;
  removed the entry-only assessment/evidence aside panels.
- Added the requested construction status notice while keeping supported real
  uploads enabled. Included both the existing Explore Demo callout and the saved
  V3 screen's Review Available Analysis button for visual comparison.
- Intake state, validation, authorization, API submission, and demo selection
  handlers are byte-for-byte unchanged. Both demo buttons use the existing
  explicit prototype-selection workflow; no prepared-capture substitution added.
- Verification: `npm run lint`, `npm run build` (with
  `NEXT_PUBLIC_API_BASE_URL=https://securemailscope-production.up.railway.app`),
  `npx --no-install tsc --noEmit`, and `npm audit --json` passed; audit reported
  zero vulnerabilities. `uv run --locked --offline pytest -q`: 342 passed,
  2 skipped in 25.54s (existing absent frozen T01 PCAP). Both
  `uv run --locked --offline ruff check .` and
  `uv run --locked --offline ruff format --check .` passed.
- Bounded HTTP structural checks passed for 11 local routes: root redirect,
  new upload (including query string), processing, complete, and six prototype
  result views. Confirmed construction status, one upload input, two enabled demo
  actions, initially disabled Start Analysis, and retained result navigation.
  Windows `http://localhost:4181/analysis/new` returned HTTP 200.
- Check-script corrections: initial navigation assertion used the wrong aria
  label; inspected actual markup and corrected it to `Primary`. The initial
  preservation comparison also included a trailing empty status line; normalized
  that line and confirmed original worktrees/14 backend file hashes unchanged.
- Browser automation remains blocked by the Windows sandbox helper initialization
  error. Responsive visual review, hydrated button clicks, and a new Railway
  upload were not verified in this slice. The local preview remains on port 4181.


## Upload entry wording correction (2026-10-02)

- Corrected the upload box to V3's active prepared-capture wording, including
  drag states, Choose files, and the PCAP/PCAPNG size note below the box.
- Adopted V3's Capture selection/Capture integrity validation labels and waiting
  states. Accepted real captures say Format and size verified: the real flow
  validates format/size, not V3's frozen demo bundle hashes.
- Replaced the boxed amber notice with the unused V3 screen's plain status
  paragraph, red integration-in-progress emphasis, and black supporting text.
  Supporting wording reflects that real uploads remain available. Kept both
  existing demo entry presentations.
- Verified unchanged file acceptance/authorization/API/demo handlers and prior
  layout edits. `npm run build`, `npm run lint`, `npx --no-install tsc --noEmit`,
  `npm audit --json` (zero vulnerabilities), `uv run --locked --offline pytest -q`
  (342 passed, 2 existing missing-T01-PCAP skips in 11.04s),
  `uv run --locked --offline ruff check .`,
  `uv run --locked --offline ruff format --check .`, and `git diff --check` passed.
- Bounded rendered-HTML checks passed on all 11 existing local routes; checked
  exact upload/footer/waiting copy, a plain black status paragraph with red
  emphasis, both enabled demo actions, one upload input and initial authorization
  gate. Original main/V3/backend worktrees and backend user-file hashes preserved.
- Browser click/responsive visual automation remains unavailable due to the
  previously reported Windows helper error; no new real upload tested.
  Local preview stays at port 4181. No stage, commit, push, merge or deployment.


## Demo entry consolidation (2026-10-02)

- Updated the plain notice to: Production backend development is in progress.
  Explore Demo to review a sample analysis and see the full workflow.
- Removed Review Available Analysis; retained the existing Explore Demo callout.
  Real upload, validation, authorization and demo handlers remain unchanged.
- Required build/lint/TypeScript/audit (zero vulnerabilities), pytest (342 passed,
  2 existing missing-T01-PCAP skips in 28.31s), Ruff lint/format and diff checks
  passed. Commands used the same locked/offline Python environment as above.
  Focused rendered-HTML checks passed on new-entry and its query-string variant:
  exactly one enabled Explore Demo action, no review button, plain notice and
  initially gated real upload. Browser click/visual verification and a fresh
  backend upload remain untested; previously reported browser helper limitation.
- No staging, commit, push, merge or deployment. Preview remains on port 4181.


## Upload entry accessibility and mobile verification (2026-10-02)

- Fixed the observed Capture intake contrast failure (4.38:1 before the change)
  and clipped progress labels at narrow widths. Kept desktop progress horizontal
  and wrapped labels on mobile. Added 44px main controls, visible dropzone focus,
  an entry-only skip link, live validation updates, and explicit checkbox
  name/description associations. Intake validation, API and demo handlers remain
  unchanged.
- Separate headless Microsoft Edge + bundled Playwright tests worked despite
  the in-app helper limitation reported above. Axe-core 4.13.0 was installed
  only in a temporary audit directory; no project dependencies changed.
- Axe WCAG A/AA checks reported zero automatic violations across seven viewports:
  320x900, 360x800, 390x844, 768x1024, 844x390, 1024x768 and 1440x900.
  No horizontal overflow or clipped progress labels; main buttons measured at
  least 44px high. Screenshots were reviewed at mobile and desktop sizes.
- Also verified 200% text resizing, accepted/authorized and rejected-file states.
  Axe's remaining manual checkbox-label check was reviewed: the visible title
  supplies the accessible name and permission copy supplies its description.
  Actual role/name lookup, description association and Space toggle passed.
- Browser interaction checks passed for keyboard skip/focus, file choosing,
  authorization/start gating, file removal, invalid-file alert association,
  Explore Demo -> completion -> Open Overview, and mobile navigation opening
  with Enter and closing with Escape. No browser runtime errors and no requests
  to the real Railway backend during these tests; no real upload was submitted.
- Test-script corrections used the visible Open Overview link and the actual
  Mobile primary drawer label; waits included the closing animation before the
  final screenshot. Full-page selected-state audits used top scroll position to
  avoid sticky-header occlusion. These corrections did not change product code.
- Required checks passed: `npm run build` with the existing Railway public URL,
  `npm run lint`, `npx --no-install tsc --noEmit`, `npm audit --json` (zero
  vulnerabilities), `uv run --locked --offline pytest -q` (342 passed, 2 existing
  missing-T01-PCAP skips in 18.55s), both required Ruff checks, and diff checks.
- User-authorized source commits are separated by scope: `a1167cd` (entry
  navigation), `e9daefd` (entry design/copy/demo guidance), `677fdf8`
  (accessibility/mobile fixes). Verification records remain a separate commit
  for local main integration. No push or deployment is performed in this slice.
- Evidence: local headless audit JSON and PNGs outside the repository. This is
  browser/static/frontend proof, not production backend end-to-end or a manual
  assistive-technology certification. Frozen POC evidence is unchanged.
