# Frontend Implementation Status

## Current state

- Branch: `feat/frontend-v3-submission`
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
- V2 Overview cleanup: complete
- V2 Analysis-details navigation: complete and browser-verified
- V2 Session Timeline, TLS & Certificates, and Findings & Evidence: complete
- V2 Recommendations workflow: complete
- V2 Report consistency and print hierarchy: complete
- V2 proof-map Slice A and Slice B: implemented and browser-accepted
- Final V2 audit verdict: **READY WITH DOCUMENTED LIMITATIONS**; no
  application-blocking defect remains
- Remaining unverified scope: real backend workflow and live backend finding
  artifacts, native Windows print-dialog parity, touch gestures, screen-reader
  quality and unusually large future graphs
- Production build note: Turbopack fails with an environment-specific `EPERM`;
  the webpack production build passed
- Deployment state: deployed V1 remains unchanged; V2 has not been deployed
- V3-1 judge-ready submission demo: implemented and verified on 20 September
  2026; submission mode remains local, uses one compact sample disclosure, and
  presents two validated illustrative anomaly records separately from Policy
  Risk.
- V3-2 judge-presentation refinement: implemented and verified on 23 September
  2026; the original capture-selection entry is retained, result workspaces use
  the same primary terminology in local and backend modes, and Overview and
  Report lead with clearer evidence and actions.
- V3-3 judge-readability refinement: implemented and verified on 23 September
  2026; primary results now precede tutorials, filters, provenance, and model
  metadata, while compact summary grids reduce scrolling at narrow widths.

## V3-3 judge-readability refinement — 23 September 2026

Every main result route was reviewed as a judge-facing information surface.
Page introductions now state the decision task in plain language. Sessions and
Findings remove repeated analysis metadata, use shorter summary cards, and keep
search/filter controls collapsed until requested. Findings no longer emphasizes
policy-profile and anomaly-model identifiers above the actual results; those
technical values remain available through inspectors and source records.

Proof Map now presents the interactive evidence graph before its detailed
legend, which is retained in a collapsed reading guide. Session X-Ray presents
observed events before the generic STARTTLS reference sequence. Comparison uses
a compact difference summary instead of a three-column metadata strip. Report
places assessment, findings, and recommendations before screen provenance, and
its ML records and low-level policy fields are progressively disclosed. No
evidence, result, identifier, contract field, or source record was deleted.

Spacing was tightened without reducing touch targets: Overview, Sessions,
Findings, and Proof Map use two-column summary grids at narrow widths and four
columns on wide screens. Desktop review covered every primary route plus the
Findings ML, Recommendations ML, and Session X-Ray evidence views. Narrow
500 px review covered Overview, Sessions, Findings, Proof Map, Session X-Ray,
and Report; the Windows browser minimum prevented a fresh 390 px claim.

Verification passed: TypeScript, ESLint, all required V2/V3 model, graph,
submission-safety, demo, and backend-mode report-consistency scripts, webpack
production build, `npm audit` (zero vulnerabilities), root pytest (342 passed,
2 skipped because the frozen T01 PCAP is absent), Ruff lint/format, and
`git diff --check`. No backend, fixture, schema, dependency, deployment, or
Git-history operation occurred.

## V3-2 judge-presentation refinement — 23 September 2026

The original Start Analysis capture-selection page was restored after review.
Overview and Report expose an evidence-backed executive summary before dense
technical detail, with direct links from the primary finding to its evidence
and recommended action. Overview, Findings, Session X-Ray, Proof Map,
Recommendations, completion, and report actions use the same core labels in
local and backend modes instead of repeating sample-specific wording. The local
staged simulation was removed; both modes now use the same processing screen.
The browser action is labelled **Print report**, with local Save as PDF described
only as a browser option.

One compact **Sample analysis** source badge and the Report provenance record
remain intentionally truthful because the local workflow did not run the
backend analyzer. This avoids repeated interruptions without representing
fixture output as a production result.

The existing information architecture, routes, validated fixture, backend
adapter, report source-of-truth boundary, and Policy Risk/ML separation remain
unchanged. Recommendations tabs gained URL-backed state so a judge-facing link
can open the relevant action view directly. No shadcn installation was needed:
the refinement reuses the existing component system and adds no dependency.

Verification passed: Next type generation, TypeScript, ESLint, V2 model and
proof-map scripts, V3 submission-safety and demo scripts, backend-mode report
consistency, webpack production build, `npm audit` (zero vulnerabilities), root
pytest (342 passed, 2 skipped because the frozen T01 PCAP is absent), Ruff
lint/format, and `git diff --check`. No backend, fixture, schema, dependency,
deployment, or Git-history operation occurred.

## V3-1 judge-ready end-to-end demo — 20 September 2026

The fixed sample workflow now runs through judge-friendly Processing and
Complete screens into the existing investigation workspace. Submission file
interactions clear the native input, retain no file or filename, open one
accessible modal, and make no backend request. Repeated prototype notices were
removed from result pages; the application header contains the single compact
**Sample analysis** disclosure.

The validated fixture now contains two linked illustrative anomaly records and
a complete anomaly stage. Findings, Session X-Ray, Proof Map, Report, and the
new ML investigation-guidance section consume the same records. Deterministic
policy recommendations and Policy Risk remain independent.

Current V3-1 fixture SHA-256:
`bb656b509482c7ad847f3b1fa6ab4619668a66b4e36244ee841e09051ba3be9e`.

Automated verification passed: Next type generation, TypeScript, ESLint, all
required V2/V3 scripts, the focused V3-1 script, report consistency, webpack
production build, root pytest (342 passed, 2 existing missing-fixture skips),
Ruff lint/format, and `git diff --check`. Isolated Chrome passed 49 desktop and
390px checks with zero backend API requests. Temporary results and screenshots
are stored under `/tmp/sms-v31-*`. No dependency, backend, deployment, commit,
push, merge, tag, rebase, or amend operation occurred.

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

## Current V2 release limitations

- Final audit verdict: **READY WITH DOCUMENTED LIMITATIONS**. No
  application-blocking defect remains.
- The real backend workflow and live backend finding artifacts remain
  unverified. The clearly labelled **Prototype Analysis Dataset** is a synthetic
  contract fixture and does not analyze or upload a capture.
- Native Windows print-dialog parity, touch gestures, screen-reader quality and
  unusually large future graphs remain unverified.
- The frozen backend repository is in-memory at this milestone, so real IDs
  remain refresh/deep-link addressable only while the backend process retains
  the corresponding Chain.
- Turbopack's production build fails with an environment-specific `EPERM`; the
  webpack production build passed.
- Deployed V1 remains unchanged. V2 has not been pushed or deployed.

## Release-checkpoint action

Preserve the coherent V2 source and verification records as one checkpoint.
Any deployment or validation of the remaining external/platform-specific areas
requires separate authorization.


## V2 slice 1 — 6 September 2026

The user explicitly authorized V2 and supplied deployed source archives. This new entry supersedes the earlier "V2 requires separate authorization" next-action note for this frontend task. Exact source baseline, approved direction, scope mismatch and pending work are recorded in `V2_IMPLEMENTATION_PLAN.md`.

Implemented the cream shell, four-destination sidebar, Analysis details drawer, reduced overview provenance, URL-backed session investigation tabs, embedded session-scoped V1 React Flow graph, searchable evidence records, contextual Compare and dedicated Recommendations. Existing API adapters, upload, contracts, fixture and backend are unchanged.

Verification actually performed:

- `npm ci --ignore-scripts --no-audit`: installed the existing lockfile dependencies.
- `npx next typegen`, `npx tsc --noEmit`, `npm run lint`, `npm run build`: passed after resolving initial type errors; final lint has no warnings.
- `npm audit`: zero vulnerabilities.
- `node scripts/verify-v2-models.mjs`: passed session/evidence identity, graph endpoint scoping, exact recommendation steps, no mutation, explicit ML state, absent-session and invalid-reference checks.
- Production HTTP/HTML smoke checks: Start has no analysis sidebar; four main links; all three tab deep links select the expected panel; current-session graph scope; no duplicate session DOM IDs; canonical remediation; invalid session filter; existing Sessions/Findings/Proof Map/Compare/Report routes; real unavailable ID does not display demo content. Passed. These are server-rendered checks, not browser clicks.
- Root frontend-snapshot Python suite `uv run pytest -q`: 342 passed, 2 skipped in 8.91s. The pre-existing skipped integration tests require the frozen T01 PCAP not included in this snapshot. This is not the separate backend archive's test suite.
- Root `uv run ruff check .` and `uv run ruff format --check .`: passed (65 files already formatted).
- Git patch whitespace and apply/reconstruction verification are recorded in the delivered handoff. The source snapshot has no `.git` directory; no actual repository commit was made.

Browser validation remains blocked: the standard browser download timed out; an isolated browser binary launched but crashed with SIGTRAP in this runtime. No screenshot, hydrated interaction, viewport/focus or live upload end-to-end PASS is claimed. Local browser acceptance is required before deploying V2.


### User correction — preserve V1 visuals

The user requested content/workflow changes only for V2. Restored `globals.css` byte-for-byte from the deployed V1 archive, restored original shell/sidebar/header surface colours and sidebar text treatment, and restored V1 proof-map controls, labels, styles and layout. The graph retains only an optional locked session scope to support embedding it in the selected session. No dark-mode feature was added; classic-white restyling and broader visual changes are deferred. Earlier cream/taupe and collapsed-graph-filter entries describe the superseded first patch.

### V2 proof-map initial positioning — 10 September 2026

Focused frontend fix on `feat/frontend-v2`, preserving the existing uncommitted
V2 changes. Code inspection identified two automatic fit paths (React Flow's
mount-time `fitView` prop and a single animation-frame effect keyed by layout)
inside a kept-mounted, CSS-hidden tab. Neither checked actual container
visibility or measurement readiness; revealing the tab did not change the
layout key. This is a source-level diagnosis, not a browser reproduction.

Replaced those paths with `useInitialProofMapFit`: observe container resize and
React Flow store updates, wait for a visible positive-size container matching
the store viewport and all current nodes' measured dimensions/handles, then
fit immediately once for the layout. The guard preserves user pan/zoom on tab
return; session/filter changes still initialize their layout. The existing
session-keyed route and standalone graph share the hook. Manual Fit, Reset,
controls, inspector, graph styling and topology are unchanged.

Verification executed successfully:

- From `web`: `npx next typegen`, `npx tsc --noEmit`, `npm run lint`,
  `node scripts/verify-v2-models.mjs`, and `npm run build`.
- `node scripts/verify-proof-map-fit.mjs`: mocked lifecycle regression checks
  for hidden activation, viewport/node measurement ordering, stale session and
  filtered nodes, single fitting, tab-return preservation, effect cleanup/replay,
  visible initial mounts and empty graphs. This does not prove browser layout.
- `npm audit`: zero vulnerabilities. `git diff --check`: passed.
- The process identified by the existing dev lock (PID 31051) was absent
  before the production build; no dev server was started during validation.

Browser verification remains **PENDING**: no browser tool or executable was
available. Next acceptance step: first opening Findings & Evidence from another
tab; direct URL and reload; manual pan/zoom followed by tab return; another
session; standalone proof-map and manual Fit; node inspection and Escape.
No backend, contract, fixture, dependency, deployment setting or Git history
was changed.

### V2 Overview content and information placement — 11 September 2026

Reordered the Overview around analyst workflow: compact capture/status context,
existing summary cards, prioritized sessions, protocol/TLS-upgrade distributions,
then a concise assessment-coverage notice linked to Analysis details. Removed
the duplicate Policy Risk and ML Anomaly blocks. Their unique profile,
contribution-count and interpretation guidance now appears in the corresponding
summary cards; a missing or `not_run` ML result remains unavailable and is not
shown as zero or clean.

Moved the long passive-analysis and TLS 1.3 evidence-boundary explanation from
Overview into the existing Analysis details drawer. The drawer retains capture
provenance and warnings and now shows ingestion tool versions, readable engine
and analysis states alongside exact raw values, TLS 1.3 visibility records, and
every analysis-limitation summary, detail and raw code. Overview keeps visible
counts for analysis limitations, capture warnings and TLS 1.3 visibility
constraints. Prototype results retain their dataset label.

The static prototype fixture still says, verbatim, that its illustrative policy
findings are not a complete production policy engine. The UI now identifies
these statements as supplied demo metadata that may not describe the current
production backend. The fixture was not changed. Its policy-capability wording
requires a separate source-data review if the project wants it updated.

Verification executed successfully from `web`: `npx next typegen`,
`npx tsc --noEmit`, `npm run lint`, `node scripts/verify-v2-models.mjs`, and
`npm run build`. `git diff --check` passed. The existing Next dev lock named PID
29378, but that process was absent before the production build. Browser
verification is **PENDING** because no browser executable or browser-test
dependency is available: inspect desktop and 390px layouts, session links, both
Analysis details triggers, drawer close/focus behavior, and access to all moved
limitations. No graph, session, recommendation, report, backend, contract,
fixture, dependency, deployment or Git-history change was made for this slice.

### V2 Overview-to-details coverage entry — 11 September 2026

The Overview assessment-coverage action now opens its Analysis details drawer
at a dedicated Assessment coverage section containing capture warnings,
evidence boundaries and analysis limitations. When the asynchronously loaded
content is ready, that heading receives programmatic focus and is scrolled into
view through React's layout lifecycle; no timer or delayed retry is used.

Each Analysis details instance retains its initiating button ref as the dialog's
explicit final-focus target. Closing returns focus to the coverage button or the
sidebar button that opened it. The sidebar action resets its drawer body to the
top on every opening. Only the drawer body scrolls, leaving the Analysis details
heading and Close button accessible. Metadata, capture records, tool versions,
warnings, exact limitation text, details, raw states and demo labels are
unchanged.

Verification executed successfully from `web`: `npx tsc --noEmit`, `npm run
lint`, `node scripts/verify-v2-models.mjs`, and `npm run build`. `git diff
--check` passed. The existing Next dev lock named PID 32295, but that process
was absent before the production build. Browser verification remains
**PENDING** because no browser executable or browser-test dependency is
available: verify both entry positions across repeated openings, heading
announcement, close-button focus return, sticky header/Close behavior, and the
mobile drawer. No graph, fixture, dependency, backend, deployment or Git-history
change was made.

### Coverage reopening correction — 11 September 2026 (browser verification pending)

The user subsequently reported that the previous coverage-entry change still
fails in the browser: sidebar entry resets correctly, but Overview entry does
not reliably return to Assessment coverage. The preceding compilation results
did not establish a working browser interaction and do not resolve this bug.

Source inspection: Overview and sidebar instantiate separate `AnalysisDetails`
components, each with local open state. The inner `overflow-y-auto` body owns
scrolling. Previously, the coverage effect depended only on entry type and data
status, and called `scrollIntoView` on the loaded heading. It did not coordinate
with popup opening or autofocus; `scrollIntoView` can also scroll ancestors.
Base UI's installed focus manager schedules default autofocus via a microtask
and animation frame, separately from the content's layout effect. The heading
exists once data is ready, but that alone does not establish settled drawer
entry. Content currently unmounts on close; reopening was relying on remounting
to repeat navigation rather than explicitly tracking every opening.

The correction resets entry readiness on each open/close, takes explicit
control of initial focus without queuing default autofocus, and waits for both
`onOpenChangeComplete(true)` and ready content. It then focuses Assessment
coverage with `preventScroll` and sets only the body's `scrollTop`, using the
heading's position relative to that body. Sidebar entry resets to zero. A
per-opening guard prevents subsequent renders from overriding user scrolling.
The title and Close control remain outside the scroll body, and the existing
initiating-button final-focus target is preserved. Source-result content,
styles, other V2 work and graph code were not changed.

Checks actually passed: `npx tsc --noEmit`, `npm run lint`,
`node scripts/verify-v2-models.mjs`, `npm run build`, and `git diff --check`.
A temporary `/tmp/verify-analysis-details-entry.cjs` simulation exercised the
actual components with mocked React/DOM dependencies: both triggers, three
openings with retained ready state, delayed loading, body scroll targets,
focus options, final-focus refs and no repeated navigation. This is not browser
proof. With user authorization, the active dev server (parent PID 34198,
server PID 34230) was stopped and verified absent before building, then
restarted on port 3000.

Browser verification remains **PENDING**; no browser tool or executable was
available. Exact acceptance sequence: open Overview coverage, confirm heading
focus and body position, scroll to metadata or the bottom, close, then reopen
from the same button several times. Alternate with sidebar entry and confirm
it always starts at the top. Repeat with delayed loading and at 390px. Check
background scroll position stays unchanged, title/Close stay visible, and
Close/Escape return focus to the initiating button. Do not mark this bug
resolved until that browser sequence passes.

### V2 session investigation hierarchy and evidence access — 11 September 2026

The user subsequently confirmed that Overview Analysis details reopens at
Assessment coverage and the sidebar Analysis details entry opens at the top.
Other drawer acceptance checks remain pending and are not marked passed. The
user also previously confirmed initial proof-map fitting and preservation of
manual pan/zoom on tab return; this slice did not change graph implementation,
layout, filters, nodes, edges, fitting, inspector, or mount/visibility behavior.

Session investigation now keeps protocol, stream, endpoints, analysis status,
capture completeness, and production/demo source beside the heading. Prototype
results retain an explicit **Prototype Analysis Dataset** notice. Partial or
incomplete source states and exact capture warnings remain visible, while exact
session, analysis and capture IDs, timestamps, frames, packet/byte counts,
endpoints, confidence, raw status values, and capture name remain in a
keyboard-operable disclosure that is collapsed by default. The investigation
tabs follow this compact context directly.

Findings & Evidence now renders in analyst order: concise session-scoped
finding summaries, the existing full-width graph under the surrounding label
**Session proof map**, then the existing searchable evidence records, followed
by the session-scoped recommendations link. Every finding retains its supplied
title, severity and rationale, a deep link to its validated recommendation, and
finding-specific uncertainty beside the summary. All findings remain in the
existing view-model order; none is selected or reprioritized. Rule/profile
metadata, exact IDs, impact, supplied recommendation summary, exact limitation
details and direct evidence inspectors are available in a per-finding
disclosure. Full evidence metadata remains available through the existing
inspector, and the evidence collection is no longer hidden behind a collapsed
section.

The no-finding state now distinguishes a completed policy assessment with no
session-linked finding from partial source evidence and from a policy engine
that did not complete. It explicitly states that absence of a finding is not a
security conclusion. Policy Risk and ML Anomaly remain separate. Existing ML
`not_run` behavior still displays **Not run** and does not synthesize a score.
Event, finding and model-result limitations retain their supplied summaries,
codes and details beside the affected content; remaining session and
analysis-level limitations stay available in the existing final disclosure.

Verification actually performed from `web`:

- `npx next typegen`: passed.
- `npx tsc --noEmit`: passed with no diagnostics on the final source.
- `npm run lint`: passed with no reported warnings or errors on the final
  source.
- `node scripts/verify-v2-models.mjs`: passed session/evidence identity, scoped
  graph endpoints, exact recommendation steps, source immutability, explicit ML
  `not_run`, absent-session and integrity-rejection checks.
- `node scripts/verify-proof-map-fit.mjs`: passed its mocked hidden activation,
  measurement ordering, single-fit, tab-return preservation, cleanup/replay,
  session/filter change, visible mount/reload/standalone and empty-graph checks.
- `npm run build`: attempted twice and failed with the same Turbopack internal
  `EPERM` while its PostCSS worker tried to bind an internal port. The second
  attempt used the approved out-of-sandbox escalation but encountered the same
  host restriction. This is recorded as an environmental failure, not a source
  PASS.
- `npm run build -- --webpack`: passed on the final source as the established
  fallback with Next.js 16.3.3; compilation, TypeScript, page-data collection,
  static generation, finalization and all routes completed.
- `git diff --check`: passed on the final source and documentation update.

No browser executable or browser-test dependency is available. Browser checks
remain **PENDING** for: a finding summary before the graph; keyboard expansion
and collapse of metadata; recommendation and evidence destination behavior;
tab clicks, history and direct URLs; unchanged graph fit and tab-return
pan/zoom; available no-finding and partial states; and the 390px layout. No
backend, contract, fixture, dependency, deployment configuration, Overview,
Analysis details, Recommendations page, Report, or Git history was changed by
this slice.

### V2 Recommendations usability cleanup — 12 September 2026

The Recommendations workspace now follows the supplied investigation hierarchy:
action title and declared priority/severity, linked finding and readable session
context, exact remediation steps, exact verification steps, supporting evidence,
then expandable technical details. Exact finding, session and recommendation IDs
remain available beside readable protocol, stream and endpoint context. Singular
and plural counts now agree with their values.

Session filters now validate against every analysis session, including a valid
session with no linked finding. The active filter is visibly labelled and can be
cleared explicitly. A malformed or foreign session ID fails closed with a
dedicated state and never falls back to all recommendations. Unfiltered actions
follow the supplied recommendation collection order, including a supplied action
with no finding relationship; session-scoped actions still require an explicit
finding/session relationship.

An action linked to one session provides **Back to session**. An action spanning
multiple sessions exposes a separate labelled destination for every affected
session. Evidence links target the selected session's Findings & Evidence tab and
its Evidence records section. Recommendation IDs remain stable URL anchors. On
initial load and hash changes, a matching action scrolls into view and its heading
receives programmatic focus through React's layout lifecycle, with no timeout.

Recommendation loading, unavailable-analysis, source-failure, invalid-filter,
valid-session-empty, analysis-empty and incomplete-result states are now distinct.
Every empty result warns that absence is not a security conclusion. The demo
anomaly workflow remains explicitly labelled as illustrative UI; the separate ML
state continues to report **Not run** and does not create a score, result or
production ML recommendation.

Verification actually performed from `web`:

- `npx next typegen`: passed.
- `npx tsc --noEmit`: passed with no diagnostics.
- `npm run lint`: passed with no reported warnings or errors.
- `node scripts/verify-v2-models.mjs`: passed, including exact action and
  verification steps, full-session identity, valid-empty versus invalid filters,
  fail-closed invalid filtering, supplied recommendation ordering, unlinked
  supplied actions, and multi-session destination retention.
- `npm run build`: failed with the previously reported Turbopack internal
  `EPERM`. Its PostCSS path for `@xyflow/react/dist/style.css` tried to create a
  process and bind an internal port, then returned `Operation not permitted (os
  error 1)` while writing app endpoint `/page`. The normal build is not marked
  passed.
- `npm run build -- --webpack`: passed as the separate fallback using Next.js
  16.3.3; compilation, TypeScript, page-data collection, static generation,
  finalization and every route completed. No build configuration changed.
- `git diff --check`: passed. A stale `.next/dev/lock` existed, but process
  inspection found no running Next dev/start server before either build.

Browser verification remains **PENDING** because no browser executable or
browser-test dependency is available. Pending checks: session finding to exact
recommendation/focused heading; single- and multi-session return links; Evidence
records destinations; valid-empty, invalid and cleared filters; keyboard use of
tabs, links and technical disclosures; and the 390px layout. The existing source
fixture supplies one policy recommendation and no ML run; no missing fields were
invented. No backend, contract, fixture, dependency, graph, Overview, Analysis
details, session UI, Report, deployment setting or Git history was changed for
this cleanup.

### V2 Timeline and TLS & Certificates presentation — 12 September 2026

The user confirmed five Recommendations browser checks: correct action
navigation, return to session, evidence destination, filter clearing, and
explicit anomaly-demo **Not run**. These are user-confirmed results from the
preceding slice. Mobile layout, other filter cases, keyboard/focus behavior and
other untested checks are not promoted to PASS.

This slice ran on `feat/frontend-v2` and preserved the existing uncommitted V2
work. Initial review found:

- The timeline had no separate reference sequence and called the entire event
  collection observed, although source events can be inferred or unavailable.
  Event badges considered `observability` but not `event_status`.
- TLS mixed transition summaries, negotiated fields and other observations.
  Crypto rows omitted raw `value`, source identifiers and record-specific
  limitations. The TLS 1.3 visibility observation was filtered out and replaced
  with a generic explanation, hiding its exact supplied record.
- No certificate observations was labelled “not assessed” without distinguishing
  absence of supplied records from a supplied assessment state.

Resulting hierarchy:

1. **Timeline:** separate dashed reference milestones labelled **not captured
   events**, then observed/inferred source events. The reference is a static
   reading guide for in-session STARTTLS/STLS, not backend observations or an
   expected-result verdict; implicit TLS and unknown protocol are qualified.
   Exact timestamps, sequence indices, direction and evidence actions stay
   accessible. Technical event details contain original type, status,
   observability, before/after states, frames and event identity. Capture/session
   limitations and each event's uncertainty summaries remain visible; native
   keyboard-operable disclosures retain exact limitation codes and details.
2. **TLS & Certificates:** TLS negotiation and outcome; negotiated parameters
   alongside other TLS observations/Forward Secrecy assessment; certificate
   observations; individual certificate assessment results; relevant session and
   analysis limitations. The old repetitive posture-card grid was removed only
   from this tab. Existing session identity, Findings, ML status and graph
   placement/visibility are preserved.
3. Crypto values keep their supplied normalized wording. Technical disclosures
   expose the complete supplied observation/fact JSON, including raw values,
   IDs, observability, derivation/confidence metadata, source references and
   limitations. Existing direct/through-source evidence inspectors are retained.

Source mappings and state boundaries:

- `protocol_events.sequence_index` controls ordering; ties retain original
  source-array occurrence, never timestamp sorting. `event_id`, `timestamp`,
  `evidence_ids` and evidence frame/session identities are unchanged. Reference
  milestones never enter the event view model.
- Both `event_status` and `observability` qualify event presentation. An inferred
  event supported by observed evidence is labelled Derived; incomplete and
  unobservable event statuses remain qualified. Raw values remain accessible.
- Negotiation includes explicit request/accept/reject/hello/completion event
  types and supplied changes into `tls_offered`, `tls_active` or `tls_failed`.
  Generic `capability_advertised` alone does not become a TLS offer. Acceptance
  does not synthesize establishment. `derived_facts.fact_type =
  tls_upgrade_completed` supplies completion; missing facts stay Not assessed.
- `crypto_observations.kind = tls_negotiated_version` and
  `selected_cipher_suite` populate negotiated parameters. `supported_versions`,
  `record_layer_legacy_version`, key-share/PSK/resumption observations stay
  separate. Only a supplied `forward_secrecy` fact supplies that assessment.
- Certificate properties/visibility and individual structure, signature-chain,
  trusted-path, service-identity and revocation check kinds are displayed
  separately. Certificate presence never creates a validation result. Source
  `unknown`, `not_observable`, `not_assessed`, `not_applicable` values remain
  distinct from the record's evidence-provenance badge.
- `tls13_certificate_unavailable` and its supplied limitations are now preserved
  as a full row alongside any `certificate_observability` fact. The TLS 1.3
  explanation comes from the source context, not from an empty certificate
  collection or merely the negotiated version. No supplied certificate records
  means information is unavailable, not “no certificate.”

Current data limits, without assuming delivery of a backend V2 milestone:

- The bundled Prototype Analysis Dataset supplies five crypto observations:
  negotiated-version records for both sessions, a selected cipher, a key-share
  group and a TLS 1.3 certificate-visibility record. It supplies no actual
  certificate property/check observations and no `forward_secrecy` fact.
- The existing `observationKindSchema` has no dedicated offered-cipher-suite
  kind. `supported_versions` is distinct from the explicitly negotiated-version
  kind; it does not by itself identify an offer/selection role. Raw evidence
  direction/source fields remain available. No offered cipher list is invented.
- There is no source-provided expected-milestone collection or explicit session
  implicit-TLS/upgrade mode field. The reference guide cannot be scored against
  the capture or used to claim a missing event never occurred.
- Missing trust-store, service-identity, capture-time validation or revocation
  results cannot be filled in from certificate presence or a validity window.
  The UI consumes the existing frozen contract; no backend repository was read
  or changed and no new live backend capability was verified.

Files changed for this slice only:

- `web/src/components/analysis/session-xray/session-xray.tsx`
- `web/src/components/analysis/session-xray/session-xray-view-model.ts`
- `web/scripts/verify-v2-models.mjs`
- `web/docs/IMPLEMENTATION_STATUS.md`

Validation actually performed from `web`:

- `npx next typegen`, `npx tsc --noEmit`, `npm run lint`: PASS.
- `node scripts/verify-v2-models.mjs`: PASS, including new in-memory variants for
  event-status/observability interpretation, sequence ties, exact timestamps,
  frames/evidence/session identity, no synthesized milestones or missing-record
  failure, generic capability versus TLS offer, raw/normalized crypto records,
  adjacent limitations and unavailable result states. Fixture files unchanged.
- `node scripts/verify-proof-map-fit.mjs`: PASS (mocked lifecycle only).
- `node /tmp/sms-timeline-review/check-consumers.cjs`: PASS. Compared Policy
  Findings, Anomaly Findings and Compare projections using the pre-edit and
  current shared view models; their full outputs matched on the supplied demo.
  This temporary review check is not a new production test dependency.
- `npm audit`: PASS, zero vulnerabilities.
- `npm run build`: FAIL on both normal and permitted escalated attempts with the
  known Turbopack internal `EPERM`. Processing
  `@xyflow/react/dist/style.css` tried to create a worker and bind a port while
  writing app endpoint `/page`. Panic logs were preserved at
  `/tmp/next-panic-45ddd832876f8b44faa290e5cb2464d2.log` and
  `/tmp/next-panic-d6cfd3cc29ceb760b28d9caf896e82ea.log`.
- `npm run build -- --webpack`: PASS as a separate fallback with Next.js 16.3.3.
  Compilation, TypeScript, static generation and all routes completed. No build
  configuration was changed. Process inspection found no running Next dev or
  start server before building; no dev server was started during this slice.
- `git diff --check`: PASS after the final documentation update.

Browser verification for this slice remains **PENDING**: no browser tool,
executable or browser-test dependency was available. Next acceptance action:

1. At desktop and 390px, distinguish reference milestones from source events;
   inspect empty, inferred and incomplete/unobservable event states where data
   is available. Confirm visible capture gaps and readable long/raw values.
2. Open event evidence inspectors and verify session/frame destinations; operate
   event, crypto-source and limitation disclosures using the keyboard, including
   focus visibility and inspector close/focus return.
3. Compare TLS values, raw records, unavailable states and certificate visibility
   explanations against the source for both supplied demo sessions and available
   real results. Do not claim validation from a presence badge.
4. Switch all three tabs; use direct `?tab=timeline`, `?tab=crypto` and
   `?tab=findings` URLs, reload, and Back/Forward history; confirm session scope.
5. Recheck graph initial fit after first activation and direct load, then manual
   pan/zoom followed by tab return; test another session, standalone graph and
   manual Fit. Earlier user-confirmed fit behavior and mocked checks do not
   replace browser regression verification for the current screen hierarchy.

No backend, contract, fixture, dependency, graph internals, graph mount/visibility,
Overview, Analysis details, Recommendations, Report, deployment configuration,
staging, commit, push or deployment operation was changed/performed for this
slice. Existing demo/real source selection and labels are preserved.

### V2 Report content and export consistency — 12 September 2026

This frontend-only slice ran on `feat/frontend-v2`. The user's current Report
scope and the V2 plan govern this work; historical frozen POC records were not
changed. All pre-existing modified/untracked V2 files were preserved. This entry
is appended to the existing status record.

The Report, Overview, Sessions and Recommendations all select the same
`AnalysisDataSource` by analysis ID. The reserved prototype ID loads the validated
fixture; other IDs use the existing real API adapter's summary and Chain requests.
Report retains its existing envelope, identity and graph-integrity rejection
boundary. No failure falls back to demo data.

Existing export paths, confirmed from frontend implementation:

| Action | Source and scope |
| --- | --- |
| Demo Chain JSON | Existing frontend serialization of the validated demo Chain; unchanged `{analysis_id}.demo-chain.json` name, JSON shape and source values. The exact **Prototype Analysis Dataset** notice already exists in `analysis.limitations`; it is retained and tested. No new envelope was necessary. |
| Backend Chain JSON | Fresh `GET /api/v1/analyses/{analysis_id}/chain`; validates MIME, schema and analysis ID, then preserves the original response bytes. |
| Finding HTML/PDF | Existing real-only `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}/artifacts/{html|pdf}` calls; preserve backend bytes and safe attachment filenames, with existing ID-based fallback names. These are individual finding artifacts. Their current live availability was not verified. |
| Print / Save as PDF | Existing browser `window.print()` action on the displayed full report. It is not a server-generated whole-analysis PDF. Demo identification remains in the report and now also appears in the document title alongside the analysis ID. |

No full-analysis HTML download, PDF generator, new export format, dependency,
backend capability or contract change was introduced. An early review incorrectly
suggested the demo JSON lacked an in-document label; inspecting the original
Chain limitation corrected that assumption. The final implementation preserves
the original demo JSON shape and notice.

Concrete Report discrepancies corrected:

- Only five findings were shown, so larger reports/printouts omitted supplied
  findings and their finding-artifact actions. All findings now remain in source
  order with exact severity, rationale, impact, contribution, recommendation,
  session, fact and evidence identities.
- Policy Risk omitted the supplied score and hid the engine state when its score
  object was absent. Capped/uncapped scores and engine state are now explicit;
  null remains unavailable. ML stays separate, and `not_run` renders **Not run**
  without a substituted zero or synthesized result.
- Capture provenance omitted capture times, size, packet/truncation counts and
  warnings. These are retained, with complete capture and execution metadata in
  technical disclosures.
- Limitations were restricted to analysis and selected certificate records,
  deduplicated by code/summary and stripped of detail. All declared analysis,
  session, event, observation, fact, finding, policy, anomaly and stage
  limitations now retain their owner, code, summary and distinct detail.
- Aggregated crypto presentation replaced TLS 1.3 source wording and could hide
  observation records when a fact was present. Per-session source values and
  observability now remain intact, including both observations and facts.
  Missing completion/Forward Secrecy facts stay explicitly Not assessed.
- Recommendations already retained supplied steps, including unlinked actions;
  Report now adds their exact action destinations, finding relationships and all
  affected session links. Unlinked actions remain visible and are identified as
  having no supplied finding relationship. Repeated steps retain their order.
- Export labels now distinguish demo/backend Chain JSON, individual finding
  HTML/PDF and browser printing. Missing demo Chain disables its JSON action.
  Backend fetches have a 30-second timeout; existing busy states, safe errors,
  missing-artifact handling and no-demo-substitution behavior remain intact.

The report follows this section order:

1. Capture and analysis provenance.
2. Scope, completion and limitations.
3. Policy Risk and separate ML status.
4. Findings and affected sessions.
5. Recommendations and verification.
6. Evidence references and technical details.

V1 colors, cards and sidebar are retained. Dashboard metric/graph-summary grids
were replaced within Report by the report hierarchy. Long technical source
records use native keyboard-operable disclosures. A print-only copy of the same
content preserves closed-disclosure details without depending on print-event
JavaScript. Report-scoped CSS wraps long values and permits long records to break
across printed pages. Source text/JSON is rendered through React text nodes;
source strings cannot become executable markup. No frontend-generated document
is labelled as an original backend artifact.

Files changed by this slice only:

- `web/src/app/analysis/[analysisId]/report/page.tsx`
- `web/src/components/analysis/report/report-workspace.tsx`
- `web/src/components/analysis/report/report-view-model.ts`
- `web/src/components/analysis/report/report-export-actions.tsx`
- `web/src/components/analysis/report/report.module.css` (new)
- `web/src/lib/api/export-downloads.ts`
- `web/scripts/verify-report-consistency.mjs` (new; existing scripts preserved)
- `web/docs/IMPLEMENTATION_STATUS.md` (append only)

Validation actually performed:

- `npx next typegen`, `npx tsc --noEmit`, `npm run lint`: PASS on final source.
- `node scripts/verify-v2-models.mjs`: PASS on final source, preserving existing
  Timeline/TLS, session/evidence, recommendation and integrity checks.
- `node scripts/verify-report-consistency.mjs`: PASS on final source. Exercises
  the real Report renderer/view model and export functions with the unchanged
  demo and explicit in-memory variants: seven findings, unlinked/repeated/empty
  recommendation steps, exact session/finding/evidence IDs, same-summary
  limitations with distinct details/owners, partial/empty/unavailable states,
  supplied policy zero, ML Not run, exact crypto values, escaped script/image
  payloads, valid anchors and complete technical print-content copies. Compares
  Report projections with Sessions and Recommendations/Policy view models.
  Mocked API adapter checks verify the real source path and fail-closed summary
  count mismatch. Mocked export responses verify unchanged Chain/HTML/PDF bytes,
  MIME/signature/identity checks, filename fallback, HTTP 404/413/500/503,
  network failure and timeout. The PDF mock is only a signature/byte-preservation
  check, not a rendered PDF or live backend proof.
- Export/render inspection files from the final check are retained in
  `/tmp/sms-report-review-AvhGnL/`. The demo JSON was decoded and compared with
  the complete supplied Chain: analysis `ana_c0ffee0000000001`, 2 sessions,
  1 finding, 1 recommendation, 13 evidence records, Policy Risk 25, ML `not_run`
  and the original prototype notice. Rendered sections and duplicate-anchor
  absence were also inspected with Python's HTML parser. These HTML files are
  test render outputs, not a new product export format or browser proof.
- Historical V3-0 fixture snapshot SHA-256:
  `397eef272da3d4107267a43470d32a533921cf98c5273a8160d8257ea40f40c5`.
  This snapshot no longer describes the current fixture; V3-1 intentionally
  updates it with illustrative ML anomaly records.
- `npm audit`: PASS, zero vulnerabilities.
- `npm run build`: FAIL on normal and permitted escalated attempts with the
  known Turbopack `EPERM` while the `@xyflow/react/dist/style.css` PostCSS worker
  attempted to bind an internal port. Panic logs retained at
  `/tmp/next-panic-cbcf218a0971a07ba03c774888046c24.log` and
  `/tmp/next-panic-d4004bc68c4aaabf24cf4f87f42b19bb.log`.
- An earlier `npm run build -- --webpack` passed. The subsequent final-source
  sandbox run failed with `Could not parse output from TypeScript's
  --showConfig`. Direct `node node_modules/typescript/bin/tsc --showConfig`
  produced valid JSON (8,571 bytes, 127 source files). Next's exact configuration
  helper reproduced `Unexpected end of JSON input`; its subprocess returned
  exit 0 with empty stdout/stderr. Diagnostic files are retained at
  `/tmp/sms-report-tsconfig.json`, `/tmp/sms-report-next-tsc-stdout.txt` and
  `/tmp/sms-report-next-tsc-stderr.txt`. No configuration or dependency was
  changed to bypass the error.
- Final `npm run build -- --webpack` with permitted escalation: PASS on final
  source with Next.js 16.3.3. Compilation, TypeScript, static generation, build
  traces and every route completed. The normal Turbopack build remains FAIL;
  this is a separately recorded fallback without a build-configuration change.
- `git diff --check`: PASS after the final documentation update. SHA-256
  comparison confirmed all pre-existing modified/untracked files remain
  unchanged except this append-only status entry; its prior bytes are preserved
  as an exact prefix.

Remaining gaps and next acceptance work:

- Backend finding HTML/PDF content parity, availability and freshness need live
  artifact inspection against the corresponding Chain. The frontend currently
  validates transport/type/signature, not all artifact semantic values, and
  preserves backend content. No live backend discrepancy or new V2 capability
  is claimed by these mocked checks.
- The existing API adapter compares summary/Chain identity, state, versions and
  counts, but does not compare summary policy-score values or limitation arrays
  with the Chain. Workspace pages use the Chain. This adapter gap is outside the
  Report slice and was not changed. Export fetches are fresh reads; same-ID
  backend snapshot immutability was not independently verified.
- Browser checks remain **PENDING**: no browser tool, executable or browser-test
  dependency is available. Verify desktop and 390px wrapping, disclosure
  keyboard/focus behavior, exact recommendation and session/evidence navigation,
  native downloads, failure/retry states, print pagination, full technical
  content from closed disclosures, demo identification and browser save names.
- Existing Timeline/TLS browser checks remain **PENDING**: reference versus
  source event presentation; inferred/incomplete/unobservable states; exact TLS,
  raw observation and certificate-visibility values against supplied source;
  evidence inspector destinations and focus return; tab/direct-URL/history
  behavior; 390px layout; and graph initial fit/manual pan/zoom after tab return.
  Earlier user confirmations and model checks are not promoted to current
  browser PASS.

No backend repository, fixture, contract, dependency, graph, other workspace
page, sidebar, deployment configuration or Git history was changed. No server
was started for this task, and no dev/start server shared `.next` with a build.
No staging, commit, push or deployment was performed.

### V2 printed report hierarchy and pagination — 12 September 2026

User review evidence: Microsoft Print to PDF opened successfully with 34 pages;
Policy Risk appeared on page 8, the finding began on page 9, and the Policy Risk
section heading was orphaned at the bottom of page 7. Expanded source records
interrupted the narrative. These are user-reported observations; the original
Microsoft-generated PDF was not supplied as a file for independent inspection.
The preceding content checks established retained data, not good pagination.

This slice preserves the existing uncommitted V2 work and runs on
`feat/frontend-v2`. Only report presentation, report-local print CSS/helpers,
targeted checks and this appended status entry changed.

Printed hierarchy now separates the narrative from the technical appendix:

1. Compact analysis/capture identity, explicit prototype/production source,
   exact analysis and capture IDs, filenames, sizes, packet counts and hashes.
2. Scope and completion, capture warnings, supplied analysis/session limitation
   summaries and a reference to the complete limitation ownership index.
3. Supplied Policy Risk and separate ML status, including explicit Not run.
4. All findings, affected sessions, exact impact/rationale, contribution,
   observability/confidence and finding-specific uncertainty.
5. Exact supplied recommendations and action/verification steps, including
   unlinked actions and existing scoped destinations.
6. Readable evidence references with session/frame context.
7. **Technical appendix — complete source records**, beginning on a new page:
   limitation ownership index, analysis manifest, execution diagnostics, full
   provenance, sessions, policy/ML results, findings, recommendations, evidence,
   events, observations, facts, evaluations and artifact manifests.

Every previously included distinct limitation occurrence retains its owner,
code, summary and exact detail. The appendix index identifies ownership; full
limitation details remain inside the corresponding raw source record. Each
complete source record is printed once. Screen disclosures remain at their
original locations and are hidden only for printing; the printed appendix is
hidden on screen. JSON and backend artifact implementations, formats, bytes,
filenames and actions are unchanged by this slice.

Print styling replaces large flex/grid card containers with block flow and
visible overflow. Heading/card-header wrappers avoid a page break before their
first content. A short engine/score group stays together; long cards and raw
records can split naturally. Long IDs, hashes and preformatted text wrap, with
widow/orphan controls. Container/reference spacing is reduced without changing
font sizes, applying scaling or targeting an arbitrary page count.

Source-style audit found no report canvas-text rendering, print-to-image step,
filter, transform or opacity effect establishing application-caused
rasterization. Global print styles remove shadows and switch the shell to block
flow. Screen card clipping/flex behavior was relevant to pagination and is now
overridden within Report. The audit does not establish what Microsoft Print to
PDF did to the original file.

Files changed in this slice:

- `web/src/components/analysis/report/report-workspace.tsx`
- `web/src/components/analysis/report/report-print-appendix.tsx` (new)
- `web/src/components/analysis/report/report.module.css`
- `web/scripts/verify-report-consistency.mjs`
- `web/docs/IMPLEMENTATION_STATUS.md` (append only)

Verification actually performed:

- The initial shell resolved Windows npm/npx and returned a WSL runtime error.
  Subsequent commands used the existing Linux Node 22.22.3 installation at
  `/home/dell/.nvm/versions/node/v22.22.3/bin`. Nothing was installed.
- `npx next typegen`: PASS. `npx tsc --noEmit`, `npm run lint`,
  `node scripts/verify-v2-models.mjs` and
  `node scripts/verify-report-consistency.mjs`: PASS on final source.
- Report checks now project explicit screen/print visibility markers and verify
  that no raw JSON precedes the appendix, every complete source record prints
  exactly once, original screen disclosures remain available, all limitation
  ownership/detail survives, and narrative ordering/IDs/steps/uncertainty remain
  intact. Existing JSON/backend download checks remain in place. Variants cover
  seven findings, unlinked/repeated steps, empty/unavailable states, distinct
  limitation details, hostile markup and records longer than a printed page.
  The marker projection itself is a content check, not a browser layout engine.
- `npm audit`: initial sandbox DNS request failed (`EAI_AGAIN`); permitted retry
  PASS with zero vulnerabilities.
- `npm run build`: normal and permitted retries FAIL with the known Turbopack
  internal `EPERM` while the `@xyflow/react/dist/style.css` worker tried to bind a
  port. Logs preserved at `/tmp/next-panic-7cf284f7987c395cce25b57a9d2c674.log`
  and `/tmp/next-panic-e37d912852afcf3430019889ea366258.log`.
- Sandbox `npm run build -- --webpack` encountered the previously diagnosed
  TypeScript `--showConfig` output-parsing failure. Permitted webpack fallback
  PASS, including a final build after the browser-found pagination correction:
  compilation, TypeScript, static generation, build traces and all routes
  completed with Next.js 16.3.3. No build configuration changed. No dev/start
  server was running alongside any build.

Browser print verification became possible through the installed Windows Chrome
binary after permitted WSL interop access. Headless Chrome printed temporary
static renders of the real Report component using the final production CSS,
actual CSS-module class and application print wrapper. These were isolated
`/tmp` documents/profiles, not the live application route or the user's normal
browser profile. The normal closed screen disclosures were retained in demo and
larger inputs. Chrome emitted UNC-profile database/locking warnings but exited
0 and produced valid PDFs. No PDF generator/library or dependency was added to
the application; an already cached PDF reader was used solely for inspection.

The first browser run exposed a remaining score split: the Policy Risk heading
and engine were on page 1, but the score began page 2. Those PDFs remain as
`*-first.pdf` under `/tmp/sms-print-browser-review/`. The short engine/score
keep-together rule corrected that split; final PDFs were generated from the final
build and inspected for page text, heading placement and source retention.

Final headless Chromium results (Letter paper, existing 12mm CSS page margins,
no browser headers/footers):

| Input | Pages | Policy Risk + score | First finding | Recommendations | Appendix |
| --- | --- | --- | --- | --- | --- |
| Demo | 32 | 2 | 2 | 3 | 7 |
| Seven-finding variant | 49 | 2 | 2 | 7 | 11 |
| Long-record variant | 52 | 2 | 2 | 7 | 11 |

All three final PDFs contain extractable text and zero image objects. The
long-record output retained all 250 repeated evidence-value markers and all 200
limitation-detail markers across page boundaries. This confirms text was not
rasterized in these Chromium-generated artifacts; it does not diagnose the
Microsoft print driver or certify interactive PDF selection/search.

Review artifacts:

- `/tmp/sms-print-browser-review/demo.pdf`, `larger.pdf`, `long-record.pdf`
- `/tmp/sms-print-browser-review/pdf-inspection.json`, extracted `*-text.txt`,
  and `long-record-retention.json`
- Original first-attempt PDFs, Chrome logs, preparation/inspection scripts and
  temporary profiles remain in that directory.
- Final source/render consistency outputs: `/tmp/sms-report-review-ujKRmF/`.

Remaining manual acceptance is **PENDING**: open the actual application, compare
interactive browser **Save as PDF** and **Microsoft Print to PDF** using matched
paper/margin settings, confirm text selection/search and visually inspect
pagination, clipping, long IDs and page-spanning raw records. Confirm the
on-screen disclosures and links still operate normally at desktop and 390px.
Headless static-render page/text inspection does not certify live-route focus,
interactive print dialogs or every visual page break. Existing Timeline/TLS,
graph and unrelated V2 browser checks remain pending as previously recorded.
No new Microsoft-driver page-count claim is made.

No source data, fixture, contract, backend, dependency, other page, graph,
download implementation or deployment setting changed. No staging, commit,
push or deployment was performed.

Final `git diff --check`: PASS. A hash comparison confirmed that only the
allowed report/style/check files changed among pre-existing work, and the status
document's previous bytes remain an exact prefix. Existing download files and
all other uncommitted V2 files are unchanged.

## V2 proof-map Slice A — 12 September 2026

Implemented on `feat/frontend-v2` under the user's explicit frontend-only Slice A
request. Existing modified/untracked V2 work was inspected and preserved. The
initial-fit hook, session tab mounting, routes, backend, contracts, fixtures,
dependencies, other pages and deployment configuration were not changed.

Presentation and interaction:

- Neutral fact titles now accompany actual supplied values. True, false, zero,
  null, empty strings and unavailable tokens are distinct. Observation values
  are retained too. Provenance is separate from result values; no result is
  inferred from a fact name. Unknown fact types use a qualified `Fact:` label.
- Event cards qualify the event type with `event_status` and observability.
  Exact status, before/after states, timestamp and direction remain inspectable.
  Evidence previews use only established safe excerpts, source fields and frames;
  raw evidence `normalized_value` does not enter the graph presentation.
- Cards use shared 260 × 132 geometry, 48px column gaps and 28px row gaps.
  Title/value text can wrap to two lines; full values remain in inspection.
  Cards do not expand on selection. Layout still precedes visibility filtering.
  The 260 × 156 candidate and 132px candidate were compared in the browser;
  132px with reduced vertical padding fit the demo and bounded long-text probe
  without overlap, limiting the full-fit height penalty. Full-graph fit is
  still an overview; detailed reading requires existing zoom or inspection.
- Node inspection starts with meaning/value, supplied finding rationale/impact
  or event/fact context, confidence/provenance, then owned limitation summaries
  and declared relationships. Technical disclosures retain exact IDs, raw
  fact/observation values, observation normalized values, source fields,
  derivation/confidence metadata and complete limitation details. Analysis and
  session limitations retain ownership; same-summary distinct details survive.
- The existing Sheet has a visible Close button outside the scrolling body,
  Escape and an explicit final-focus target. Close retains the existing
  immediate-neighbour selection; Clear selection removes it without changing
  pan/zoom. Pane clearing, Reset, Fit and built-in zoom controls remain.
- Filter semantics are explicitly **Provenance / event state**, not result value.
  Removed unreachable unknown/not_present/not_assessed options; added the exact
  session_secrets_required option. Those source result values still display
  distinctly. Filter changes continue clearing selection and fitting their new
  visible layout. No replacement edges, traversal or Fit selection were added.

Files changed for this slice:

- `web/src/components/analysis/proof-map/proof-map-graph.tsx`
- `web/src/components/analysis/proof-map/proof-map-view-model.ts`
- `web/src/components/analysis/proof-map/proof-map-presentation.ts` (new)
- `web/scripts/verify-proof-map.mjs` (new)
- `web/scripts/verify-proof-map-fit.mjs` (existing untracked script extended)
- `web/docs/V2_IMPLEMENTATION_PLAN.md`
- `web/docs/IMPLEMENTATION_STATUS.md` (this appended entry)

Verification actually executed, using the installed Linux Node 22.22.3 from
`/home/dell/.nvm/versions/node/v22.22.3/bin` and the existing dependencies:

- Next `typegen`, `tsc --noEmit`, `npm run lint`: PASS. A separate typecheck
  overlapped build regeneration of `.next/types` and failed with TS6053 missing
  generated files. The build completed, then typegen/TypeScript/lint were rerun
  sequentially and passed. Initial launcher/path errors were corrected to run
  from `web`; no dependency was installed.
- `node scripts/verify-v2-models.mjs`: PASS, preserving the existing model,
  integrity, timeline/TLS, session/evidence and recommendation checks.
- `node scripts/verify-proof-map.mjs`: PASS. Tests supplied values and event
  status combinations, exact owned limitations, escaped actual React markup,
  safe evidence previews, reachable provenance options, graph identity/counts
  and backing contract references, fixed selected-card dimensions, non-overlap
  of lanes and source immutability. Demo remains 45 nodes / 57 canvas edges /
  61 ledger relationships; no topology was added.
- `node scripts/verify-proof-map-fit.mjs`: PASS (mocked lifecycle). Includes
  selection/Close/Clear rebuilding node objects without changing layout identity
  or issuing another fit, plus existing visibility, measurement ordering,
  cleanup/replay, session/filter and tab-return coverage.
- `npm audit`: initial sandbox DNS failure, then permitted retry PASS with zero
  vulnerabilities. No manifest/lock change.
- `npm run build`: FAIL both normally and with permitted escalation at the known
  Turbopack CSS worker port-binding EPERM. Logs preserved at
  `/tmp/next-panic-ec0cf89ece4edaa9972ba0bffd8d2827.log` and
  `/tmp/next-panic-209632ee462aa47fe437225fb64c660.log`.
- `npm run build -- --webpack`: sandbox attempt failed at the previously observed
  TypeScript --showConfig output parsing. Permitted fallback PASS, including a
  build with final 260 × 132 geometry: compilation, TypeScript, static generation,
  traces and every route. Later source edits only restored whitespace formatting;
  standalone typecheck/lint passed again. No build configuration changed.
- `git diff --check`: PASS. A pre-task file-hash snapshot in
  `/tmp/sms-proof-a-before.json` was compared to the final tree: changes to
  pre-existing files are confined to the five listed existing files above.
  The fit hook and all unrelated modified/untracked work retain their bytes.

Browser verification (actual built frontend, labelled demo data):

Used installed Windows Chrome with isolated `/tmp` profiles, reached through its
local debugging protocol using installed Windows Node 24.14.1. WSL interop and
server binding initially failed in the sandbox; permitted access worked. No
browser dependency was installed. The production frontend ran on port 3026 only
after builds finished; it never shared `.next` with a dev server/build.

Passed on the built frontend:

- Embedded graph first hidden on Timeline, then fitted after activation;
  direct Findings & Evidence load; standalone route and reload.
- Actual pointer drag pan and zoom, then tab return with identical viewport
  transform; repeated at 390px for embedded zoom/tab return.
- Enter opens the false-valued fact inspector; Close receives focus; Escape
  closes and returns focus to the initiating node. Labelled Close also returns
  focus. Selection, Close and Clear preserve the viewport transform; Clear
  removes highlighting. Existing manual Fit remains operative.
- Standalone default session, second session with 30 nodes and supplied true /
  TLS 1.3 secrets qualification, all sessions with 45 nodes. Hiding 13 evidence
  nodes preserves every remaining node coordinate.
- Desktop 1440px and 390px screenshots inspected. No mobile document horizontal
  overflow; mobile inspection uses the existing bottom Sheet with visible Close.
- Finding limitation remains before technical details. A DOM-only long-text
  stress probe (fixture/source unchanged) retained 260 × 132 dimensions with
  two title lines, two value lines and no provenance overlap. Actual React
  long/hostile source-value rendering is separately tested in the source checks.

The initial browser keyboard harness omitted Enter's text event, so it did not
produce a native button click. Event logging diagnosed that omission; the complete
key sequence passed. An additional test had a quoted-selector syntax error,
corrected in the temporary harness. Original failed-check records remain beside
the final results; neither failure was reclassified as an application PASS.

Browser evidence in `/tmp`:

- `sms-proof-a-browser-results.json` (16 passed checks),
  `sms-proof-a-browser-additional.json` (13 passed checks)
- `sms-proof-a-browser-first.json`,
  `sms-proof-a-browser-additional-first.json` (preserved failed harness attempts)
- `sms-proof-a-final-desktop.png`, `sms-proof-a-second-session.png`,
  `sms-proof-a-inspector.png`, `sms-proof-a-mobile.png`,
  `sms-proof-a-mobile-inspector.png`, `sms-proof-a-embedded-390.png`
- Temporary CDP scripts and isolated Chrome profiles.

Limits: these browser checks use the Prototype Analysis Dataset, not a live
backend/real-capture run. Native touch pinch, screen-reader announcements,
nested evidence-dialog focus, exhaustive edge keyboard interaction and larger
real analyses remain pending. Full-fit card text remains small on mobile and
in the taller session; zoom/inspection is still necessary. Generic supplied
analysis limitations retain their source wording; no backend capability is
inferred from demo metadata. Slice B support traversal remains unimplemented.
No commit, push or deployment was performed. Next action: review this Slice A
interaction and the remaining accessibility/touch cases before separately
implementing Slice B.

## V2 proof-map Slice B recovery and acceptance — 13 September 2026

### Recovered state

Recovery began on the required `feat/frontend-v2` branch with all modified and
untracked V2 work preserved. No repository server or Chrome debugging process
was still running. The interrupted work had left the Slice B application changes,
the new pure traversal helper, extended proof-map/fit scripts, and temporary
`/tmp/sms-proof-b-*` CDP files. Its partial browser result contained 11 passed
checks followed by one failed supporting-event text assertion; no later steps
had run, so that file was treated as partial evidence. The assertion expected
card text inside the Sheet rather than the Sheet's actual inspector title.
Two later focus failures were also harness artifacts: programmatic `.click()`
does not focus its target. The temporary harness was corrected to focus each
initiator before activation; application source did not change during recovery.

`web/test-results/.last-run.json` was also present with `status: failed` and
an empty `failedTests` array. It contains no command, test identity, timestamped
assertion, or Slice B evidence and was not used as an acceptance result.

### Code inspection

- Finding investigation and inspector state are separate. Selecting a finding
  builds support from the complete validated graph; inspecting support retains
  the finding. Close/Escape only dismiss the Sheet. Clear selection clears both
  states. Session or analysis identity change clears stale context.
- Eligible upstream fields are exactly `finding.fact_ids`,
  `finding.evidence_ids`, `fact.source_event_ids`,
  `fact.source_observation_ids`, `fact.source_fact_ids`,
  `event.evidence_ids`, and `observation.evidence_ids`. Evidence is terminal.
  Structural, chronology, classification, anomaly, and evaluation links are not
  traversed.
- Eligible relationships are validated before traversal for duplicate identity,
  endpoint kind, resolvability, session/capture boundary, and fact-source cycles.
  The visited set therefore cannot turn invalid input into partial success.
- Visibility is an intersection with the complete support set. Hidden canvas
  relationships and non-canvas policy-evaluation context are counted separately;
  no edge is synthesized. Investigation state is excluded from `layoutKey`.

### Automated regression results

- `node scripts/verify-proof-map.mjs`: **PASS** on the recovered source. It
  checks the exact demo identities, 9-node/10-edge support, contract backing,
  unavailable observation with no evidence IDs, hidden counts, shared sources,
  multiple findings, multi-level facts, no outward shared-evidence traversal,
  source immutability, and fail-closed unresolved/cross-boundary/cycle cases.
- `node scripts/verify-proof-map-fit.mjs`: **PASS** as a mocked lifecycle
  check. Investigation, support inspection, Close, and Clear do not refit;
  initial visibility/measurement, layout changes, and tab return retain their
  established behavior.
- No TypeScript, lint, build, or audit suite was repeated because recovery made
  no application source change and the request explicitly bounded verification
  to the remaining proof-map risks.

### Live-route browser checks

An existing webpack production artifact dated after the Slice B source was
served temporarily on port 3028. Installed Windows Chrome ran in a new isolated
profile and was driven through CDP; no dependency was installed. The final
result contains **41 PASS / 0 FAIL** checks at
`/tmp/sms-proof-b-browser.json`.

- Standalone finding activation by Enter opened the inspector and highlighted
  the exact expected 9 nodes and 10 declared canvas edges. Unrelated content
  remained visible and secondary. Selection preserved every node position and
  the viewport transform.
- The finding inspector showed title, value, rationale, impact, provenance, and
  the supplied limitation that the capture does not itself prove an active
  downgrade attacker.
- Labelled Close and Escape dismissed inspection while retaining investigation.
  Finding and support-node focus returned to the initiating node. A nested
  evidence dialog opened and returned focus to its initiating evidence button.
  Supporting node and edge inspection retained the original finding context.
- Hiding Evidence changed visible support from 9/10 to 7/6 and reported exactly
  2 hidden nodes and 4 hidden relationships. Every remaining node kept its
  position, every visible edge was a pre-filter edge, and restoring Evidence
  restored 9/10. Hiding every supporting entity kind retained the investigation
  at 0/0 and disabled Fit selection.
- Explicit Fit selection changed the viewport to the visible support. Clear
  selection removed investigation and secondary styling while preserving the
  current viewport. Changing standalone session scope cleared stale context.
  Embedded tab return preserved a manually changed zoom and the investigation.
- At 390px, finding selection, 9/10 context, bottom-Sheet Close, retained
  investigation, and Evidence-filter 7/6 counts passed without document
  horizontal overflow.

Required screenshots were generated and visually inspected:

- `/tmp/sms-proof-b-full-support.png`
- `/tmp/sms-proof-b-filtered-support.png`
- `/tmp/sms-proof-b-finding-inspector.png`

An additional mobile capture is at
`/tmp/sms-proof-b-standalone-390.png`.

These checks use the labelled Prototype Analysis Dataset and do not establish
behavior for a live backend capture or unusually large future graphs. Native
touch gestures and screen-reader announcements remain untested. The fit script
is harness-only evidence; viewport and focus results above are live-route
browser evidence. No backend, contract, fixture, dependency, deployment setting,
or application source was changed during recovery. No commit, push, or deployment
was performed.
## Verified frontend workstream — V3-4 security decision workflow (PASS, 2026-09-24)

An explicitly authorized frontend-only refinement aligned the primary analysis
journey for judges, SOC analysts, and cyber-security reviewers without changing
route structure, canonical Chain data, data-source selection, or backend code.

Verified scope:

- Overview now leads with the highest-priority deterministic finding, impact,
  direct evidence/action links, a separate Policy Risk and ML Anomaly snapshot,
  four decision metrics, prioritized sessions, and an explicit assessment
  coverage matrix.
- Sessions, Policy Findings, ML Anomaly, Comparison, Recommendations, and Report
  default to readable security decisions and affected scope rather than raw
  record identifiers, model metadata, policy internals, or duplicate counts.
- exact session/finding/result identifiers, raw scores, thresholds, model/rule
  versions, policy contributions, capture hashes, and source records remain
  available in technical disclosures, inspectors, provenance, and the report
  appendix.
- Comparison is difference-first, hides matching fields by default, and uses
  readable transition, TLS, finding, anomaly, evidence, and limitation labels.
- user-facing sample/demo chrome was removed from the analysis workspace and
  export filename; the underlying validated envelope, source checks, canonical
  data, and no-upload/backend-unavailable safety behavior were not altered or
  presented as a live analyzer run.
- severity color, spacing, responsive cards/tables, and terminology are
  consistent across the primary decision path. Policy Risk and ML Anomaly
  remain separate, and unavailable TLS/certificate evidence remains explicit.

Validation recorded on 2026-09-24:

- `npx --no-install tsc --noEmit` and `npm run lint`: passed.
- V2 model/proof-map checks, V3 submission-safety/demo checks, and the
  backend-mode report-consistency check: passed.
- `npm run build -- --webpack`: passed with compilation, TypeScript, static
  generation, traces, and all routes.
- `npm audit`: passed with zero vulnerabilities.
- `uv run pytest -q`: 342 passed, 2 skipped because the frozen T01 PCAP is not
  present in this checkout.
- `uv run ruff check .` and `uv run ruff format --check .`: passed.
- built-route Chrome review covered Overview, Sessions, Policy Findings, ML
  Anomaly, Comparison, Recommendations, and Report at 1440 px; the primary
  judge journey was also inspected at 500 px.
- `git diff --check`: passed.

No backend, controlled evidence, fixture, schema, dependency, deployment,
staging, commit, push, merge, tag, rebase, or amend operation occurred.

## Verified frontend workstream — V3-5 recording navigation (PASS, 2026-09-24)

An explicitly authorized frontend-only change improved navigation during the
recorded judge walkthrough without changing routes, analysis data, contracts,
or backend behavior.

Verified scope:

- desktop analysis routes now provide an accessible control to collapse and
  reopen the sidebar; the existing mobile navigation remains unchanged;
- the analysis header now shows route-aware breadcrumbs, including session and
  comparison drill-down context;
- the standalone Proof Map retains its functional session-scope selector; and
- the Session X-Ray embedded graph replaces its intentionally locked dropdown
  with a clear current-session scope indicator and node/relationship counts.

Validation recorded on 2026-09-24:

- `npx --no-install tsc --noEmit`, `npm run lint`, the proof-map model and fit
  checks, and `git diff --check`: passed.
- `npm run build -- --webpack`: passed with all routes generated.
- `npm audit`: passed with zero vulnerabilities.
- live desktop Chrome checks verified sidebar close/reopen state, breadcrumb
  labels, and the embedded current-session scope; a 500 px route check verified
  the mobile breadcrumb presentation.
- `uv run pytest -q`: 342 passed, 2 skipped because the frozen T01 PCAP is not
  present in this checkout.
- `uv run ruff check .` and `uv run ruff format --check .`: passed.

The truthful backend-unavailable notice was not hidden for recording. No
backend, controlled evidence, fixture, schema, dependency, deployment, staging,
commit, push, merge, tag, rebase, or amend operation occurred.

## Verified frontend workstream — V3-6 session anomaly deduplication (PASS, 2026-09-24)

An explicitly authorized frontend-only cleanup removed the repeated ML Anomaly
card from Session X-Ray. Timeline, TLS & Certificates, and Findings & Evidence
now remain focused on session evidence; anomaly results remain available in the
dedicated Findings → ML Anomaly view.

Verified scope:

- removed the tab-independent Session X-Ray ML presentation and its dead helper;
- redirected ML investigation guidance to the dedicated ML Anomaly view;
- preserved anomaly records, integrity validation, report output, and Proof Map
  relationships; and
- added regression coverage preventing the duplicate X-Ray block from returning.

Validation recorded on 2026-09-24:

- TypeScript, ESLint, V2 model checks, V3 ML checks, production build, and
  `git diff --check`: passed.
- live route checks returned HTTP 200 and confirmed the duplicate heading is
  absent from Session X-Ray and present in the dedicated ML view.
- `uv run pytest -q`: 342 passed, 2 fixture-dependent skips; Ruff check and
  format verification passed.

No canonical data, backend code, contract, fixture, dependency, deployment,
commit, or repository history was changed.

## Verified frontend workstream — V3-7 recognized capture bundle (PASS, 2026-09-24)

An explicitly authorized recording workflow now lets an analyst select and
validate controlled PCAPNG captures before entering the existing
analysis workspace. This is an exact-file frontend adapter, not a browser-based
packet analyzer and not a fallback for arbitrary captures.

Verified scope:

- added deterministic, non-sensitive `secure-chain.pcapng` and
  `insecure-chain.pcapng` files plus a generated manifest;
- added an offline standard-library generator and an independent bounded TShark
  verifier; neither script performs live capture;
- reconciled prepared-result capture hashes, sizes, timestamps, packet/frame
  references, and one duration feature with the generated observable evidence;
- the Start Analysis page now accepts the controlled capture selection,
  calculates SHA-256 locally, requires analyst authorization, and follows the
  existing Processing → Complete → Overview journey;
- exact file contents are recognized independently of filenames; a partial
  pair, duplicate, one-byte modification, or unrelated capture is rejected;
- capture contents are not uploaded in the local path, and the corresponding
  prevalidated Chain is loaded only after both hashes match; and
- backend-connected mode retains its existing one-file API submission path.

Controlled frontend fixture evidence:

- `secure-chain.pcapng`: 4,096 file bytes, 12 packets, 2,048 frame
  bytes, SHA-256
  `7f519c11f650392819e3d3d78dba5e1d286a08bc8b6375252c0097c898033a76`;
- `insecure-chain.pcapng`: 4,096 file bytes, 6 packets, 1,024 frame
  bytes, SHA-256
  `def0ffe96f4da89bf98d7192644b0caa4f590114fac2bec4612e6bd0de4c6743`;
- TShark 4.2.2 independently observed the secure SMTP STARTTLS transition,
  TLS 1.3 ClientHello/ServerHello, cipher `0x1301`, key-share group 23, and
  opaque TLS records; the insecure capture advertises STARTTLS but continues
  with a plaintext `MAIL` command and contains no TLS handshake; and
- the initial custom-block fixture attempt produced an unwanted TShark
  pseudo-frame, was preserved under
  `/tmp/securemailscope-first-walkthrough-fixture-attempt-20260924`, and was
  replaced without using `--force`.

Validation recorded on 2026-09-24:

- independent capture verifier: PASS for hashes, sizes, 12/6 packet counts,
  2048/1024 frame bytes, SMTP states, TLS 1.3 version/cipher/key share, and
  plaintext continuation;
- exact-file intake regression: PASS for valid renamed inputs and rejection of
  tampered, duplicate, and partial inputs, with manifest/dataset hash parity;
- built local HTTP checks returned 200 for Start Analysis and both capture
  downloads; downloaded bytes reproduced the two expected SHA-256 values;
- TypeScript, ESLint, V2 model, V3 submission-safety/demo, Proof Map, and
  backend-mode report-consistency checks: passed;
- `npm run build -- --webpack`: passed with every route generated;
- `npm audit`: zero vulnerabilities;
- `uv run pytest -q`: 342 passed and 2 skipped because the frozen T01 capture
  is absent; Ruff check and format verification passed; and
- `git diff --check`: passed.

These are controlled frontend walkthrough fixtures, not additions to or
replacements for the frozen selection-POC evidence. No arbitrary PCAP analysis,
live capture, certificate extraction, backend milestone, dependency,
deployment, commit, or repository-history operation is claimed.

## Verified frontend workstream — V3-8 capture naming and processing feedback (PASS, 2026-09-24)

An explicitly authorized frontend refinement shortened the controlled capture
identities and restored clear progress feedback between Start Analysis and the
completed investigation without changing the route structure or backend API.

Verified scope:

- renamed the frontend capture identities from the SMTP-specific filenames to
  `secure-chain.pcapng` and `insecure-chain.pcapng` across the public files,
  generated manifest, prepared dataset, generator, verifier, intake constants,
  workflow labels, and documentation;
- retained the exact capture bytes and SHA-256 identities, so previously
  downloaded copies remain content-compatible while the UI presents the new
  canonical names after verification;
- removed the retired public filenames; built-route checks return 200 for both
  new names and 404 for both old names;
- restored a six-stage Processing checklist with pending numbered circles, an
  active spinner, green completion ticks, status labels, and a progress bar;
- the staged presentation begins only after the result passes contract parsing
  and finding/evidence integrity validation; its labels describe workspace
  preparation rather than unperformed browser packet analysis; and
- added regression assertions covering all six stages, progress UI primitives,
  integrity validation, and the two new canonical names.

Validation recorded on 2026-09-24:

- independent bounded TShark capture verification: passed with unchanged
  hashes, sizes, packet counts, SMTP states, and TLS observations;
- exact-file intake, submission-safety, V2 model, V3 dataset, and Proof Map
  regressions: passed;
- TypeScript and ESLint: passed;
- `npm run build -- --webpack`: passed with every route generated;
- local production HTTP checks: new names returned 200/4,096 bytes and retired
  names returned 404;
- `uv run pytest -q`: 342 passed and 2 fixture-dependent skips; and
- Ruff check, Ruff format verification, and `git diff --check`: passed.

The historical backend Chain test fixtures retain their frozen internal artifact
names and are not rendered by the frontend; they were not rewritten. No backend
implementation, contract schema, dependency, deployment, commit, or repository
history operation occurred.

## Verified frontend workstream — V3-9 capture format guidance (PASS, 2026-09-25)

The Start Analysis prepared-capture picker now names PCAP and PCAPNG in its
selection prompt and accessible file label. The redundant original-file and
automatic-validation sentences were removed. The format note distinguishes
the analysis service's two supported formats from this walkthrough's exact
two supplied PCAPNG files; arbitrary captures are still not processed locally.

Verification recorded on 2026-09-25:

- Independent bounded TShark fixture verifier and exact-file intake checks:
  passed; the prepared pair's hashes and observed protocol evidence agree.
- Submission-safety, V3 demo, and Proof Map checks: passed.
- Backend-mode report-consistency check: passed with an explicit local test
  API URL; no live backend request was made.
- ESLint, TypeScript, and the webpack production build: passed.
- `uv run pytest -q`: 342 passed, 2 skipped because the frozen T01 capture is
  absent from this checkout; Ruff lint and format checks passed.
- `npm audit`: zero vulnerabilities; `git diff --check`: passed.

No backend behavior, Chain contract, fixture bytes, or deployment setting was
changed. Deployment status is recorded separately when verified.
