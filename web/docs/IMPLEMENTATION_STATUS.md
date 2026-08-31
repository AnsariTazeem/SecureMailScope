# Frontend Implementation Status

## Current state

- Branch: `feat/production-frontend`
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
- Production frontend API: pending backend implementation and integration
  verification

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

- The production HTTP endpoints in
  [INTEGRATION_CONTRACT.md](INTEGRATION_CONTRACT.md) are not implemented or
  integration-verified.
- Mock completion uses the clearly labelled **Prototype Analysis Dataset** and
  does not analyze an uploaded capture.
- The generated route smoke tests passed, but the stateful Start → Processing →
  Complete → Overview → Sessions interaction has not been exercised by an
  automated browser test.
- No frontend unit-test framework is installed. F2C graph-integrity edge cases
  were therefore exercised with dependency-free, type-checked local
  verification against in-memory fixture copies; automated browser component
  tests remain absent.
- F2A Overview, F2B Sessions, F2C Session Detail, F2D Proof Map, F2E Findings,
  F2F Compare, and F2G Report are implemented. Production frontend API/backend
  integration remains pending.

## Next exact milestone action

F2G implementation and technical verification are complete. Do not begin an
additional frontend milestone or production API/backend integration without
explicit authorization.
