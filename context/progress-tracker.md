# SecureMailScope — Progress Tracker

**Last updated:** 23 September 2026

**Current phase:** Production backend on `feat/production-backend`. Chain Commit 1 (domain contract) completed and verified at `57fe930`. Commit 2 (POC-result adapter) is the next milestone. The selection POC remains CLOSED/GO at `cf055cf`; POC verification history below is preserved unchanged.

**Implementation status:** T01 PASS (23/23 comparisons); E2/E3A PASS (authorized scope: read-only intake, TShark-native reassembly, content-based SMTP classification, STARTTLS transition states). Selection decision: GO — PS159 selected/finalized for Team Apex. T02–T08 and all binary gates remain UNTESTED.

**POC verdict:** Selection-grade technical POC CLOSED as GO (PS159 selected). This is a GO/selection decision establishing technical viability; it is not a claim that the full product or the complete original POC matrix is GREEN.

## Completed preparation

- [x] Official PS159 description reviewed and preserved verbatim in `docs/OFFICIAL_PS159.md`.
- [x] Mandatory POC capabilities frozen.
- [x] Technical architecture and stack selected.
- [x] Controlled PCAP matrix T01–T08 defined.
- [x] Binary gates G01–G11 defined.
- [x] POC exclusions separated from official final requirements.
- [x] Six reusable AI-context files prepared.
- [x] In-depth POC PRD prepared.
- [x] System design and evidence/data boundaries prepared.
- [x] Feature breakdown mapped to T01–T08 and G01–G11.
- [x] Master AI prompt and response contract prepared.
- [x] Official-source tooling decision record prepared.

## Verified milestone — environment/bootstrap and doctor (PASS, 2026-08-25)

The environment/bootstrap/doctor milestone and T01 manual verification are marked PASS. T02–T08, analyzer-path validation, and formal gates G01–G11 remain UNTESTED.

Evidence recorded on 2026-08-25:

- `securemailscope doctor` implemented (Typer CLI; deterministic prerequisite checks in `tooling.py`).
- 10 unit tests passed in 0.84 seconds.
- Ruff lint passed.
- Ruff formatting check passed.
- `git diff --check` passed.
- Real doctor run result: `READY`.
- 11/11 prerequisite checks passed.
- JSON validation of the doctor report returned true.
- Real doctor exit code: 0 (`EXIT_OK`).

Scope of this PASS: environment bootstrap and the doctor command only.

## Verified milestone — T01 manual verification (PASS, corrected attempt, 2026-08-26)

T01 controlled SMTP ECDHE PCAP: independent manual verifier PASS, 23/23 comparisons passed, 0 failed.

An earlier T01 attempt failed. That attempt is preserved locally in evidence artifacts and archives and is not overwritten. This section records the corrected run only.

Evidence recorded on 2026-08-26 (corrected run):

- T01 PCAP SHA-256: `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`
- 28 packets captured; received 28; dropped 0
- Capture runtime: recorded (see evidence log)
- Verifier runtime: 12.280 seconds
- SMTP port: 2525 (identified from content on non-standard port)
- STARTTLS split reconstruction: frames 9 and 11
- Negotiated TLS version: 1.2 (0x0303)
- Negotiated cipher suite: ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)
- ECDHE group: secp256r1 (group 23)
- Forward Secrecy: derived from packet evidence
- Observable certificates: 2 (leaf and root)
- Certificate properties: verified (subject/issuer/SAN/serial/validity/key/sig)
- OpenSSL chain verification at capture time: passed
- All 23 independent comparisons passed: artifact hashes, PCAP metadata, dumpcap evidence (received 28, dropped 0), capture interval, single stream, SMTP port 2525 identification, SMTP content/direction, STARTTLS split/reconstruction (frames 9/11), STARTTLS ordering, TLS negotiation (handshake order, version, cipher, named curve), Forward Secrecy, wire certificates (leaf/root fingerprint, properties), OpenSSL chain verification, connection lifecycle

Scope of this PASS: T01 manual verification proves only the controlled manual-verifier evidence for the SMTP ECDHE PCAP (corrected run; earlier failed attempt preserved locally in evidence artifacts and archives). It does not by itself prove the analyzer path; the analyzer-path E2/E3A checkpoint is recorded separately as PASS in the section below. Still UNTESTED with no evidence collected: IMAP/POP3 protocol identification (T02, T03), formal T05–T07 controlled fixtures (STARTTLS rejection/accepted-without-TLS/truncated/false-positive controls), ML anomaly scoring (T08), deterministic policy-risk scoring, analyzer JSON/HTML report validation, and all binary gates G01–G11.

## Verified milestone — E2/E3A analyzer-path checkpoint (PASS, 2026-08-27)

E2/E3A PASS for its authorized scope, using the unchanged T01 PCAP as the integration truth. Scope covered:

- Generic read-only PCAP/PCAPNG intake.
- Streamed SHA-256 and capture provenance (packet count, all-packet capture epochs, file size, capture format and tool versions).
- Typed analyzer errors.
- Safe shell-free external-tool execution; bounded timeout and output handling.
- TShark-native TCP follow-stream reassembly (no custom TCP sequence-number buffer).
- Ordered repeated `tls.handshake.type` values preserved (not flattened).
- Conservative content-based SMTP classification; ports used only as hints.
- Pre-TLS plaintext boundary enforced.
- Split STARTTLS reconstruction.
- Strict command < response < ClientHello ordering.
- Accepted-TLS, rejected, accepted-without-TLS, truncated and incomplete states.
- Positive-proof requirement for accepted-without-TLS (bidirectional FIN or strict plaintext).
- No raw frame-concatenation fallback for authoritative reconstruction.
- Frozen T01 analyzer facts match the independent T01 truth.

Validation facts (recorded truthfully, including one environmental flake):

- v3 full suite before the final boundary regression: 201 passed.
- Final session-state suite: 24 passed.
- One later full-suite run: 201 passed plus one environmental `tshark_observe` 20-second timeout (a tool/performance flake, not a functional assertion failure; an isolated T01 integration retry passed with 2 passed).
- Ruff check passed; Ruff formatting check passed; `git diff --check` passed.
- `securemailscope doctor` reached READY 11/11.
- PCAP SHA-256 remained unchanged: `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`.

The `tshark_observe` timeout is recorded transparently as an environmental/tool-performance flake under host resource pressure; it is not treated as a functional assertion failure and no fully clean final full-suite run is claimed after the added regression.

Scope of this PASS: the E2/E3A analyzer path for the frozen scope only (SMTP on the unchanged T01 PCAP). The E2/E3A session-state tests prove that the SMTP transition-state implementation supports accepted TLS, rejected, accepted without TLS, truncated, and incomplete cases; this is unit/state coverage and should not be mistaken for the formal controlled fixtures. The following remain UNTESTED with no evidence collected: IMAP/POP3 identification (T02, T03), TLS 1.3 invisibility handling (T04), STARTTLS rejection/accepted-without-TLS/truncated/false-positive controls via formal fixtures (T05–T07), ML anomaly scoring (T08), deterministic policy-risk scoring, analyzer JSON/HTML report validation, and all binary gates G01–G11.

## Current next action

Selection decision recorded: GO — PS159 selected/finalized for Team Apex; the selection-grade technical POC is CLOSED at `cf055cf`. Production development is now active on `feat/production-backend`. T02–T08 fixture generation and full-gate validation are no longer the immediate next action; the immediate next action is production Commit 2 (the pure POC-result adapter that maps verified analysis into the Chain-of-Proof contract).

## Exact step-by-step sequence after repository creation

| Step | What to study just before it | What to build/prove | Target time |
|---|---|---|---|
| 1. Environment | Basic purpose of PCAP, TShark, OpenSSL, loopback capture | WSL/Linux environment; Python 3.12 and `uv` locked environment; TShark, OpenSSL, tcpdump/dumpcap; version check | 20–30 min |
| 2. SMTP evidence spike | SMTP banner/EHLO/STARTTLS/220 flow; TLS ClientHello/ServerHello; TShark follow-stream and fields | Controlled CA/certificate, SMTP endpoint on port 2525, split STARTTLS, TLS 1.2 ECDHE PCAP, endpoint logs, hashes, manual evidence | 60 min after setup |
| 3. First analyzer path | TShark two-pass output, `tcp.stream`, evidence provenance | Generic PCAP intake, TShark wrapper, content-based SMTP classification, session/transition timeline, normalized evidence | 75 min |
| 4. IMAP and POP3 | IMAP tagged STARTTLS and POP3 STLS/+OK flows | Controlled T02/T03 PCAPs and protocol state machines | 45 min |
| 5. TLS/X.509/FS | TLS 1.2 vs 1.3 visibility; cipher vs key exchange; certificate chain/time/SNI validation | Version, cipher, key establishment/group, FS, X.509 extraction/validation, TLS 1.3 honest invisibility | 75 min |
| 6. Failure controls | STARTTLS rejection, accepted-without-TLS, truncated capture, false positives | T05–T07 weak/broken/truncated/negative fixtures and tests | 45 min |
| 7. Findings/reports | Transparent policy scoring; JSON Schema; HTML templating | Evidence-backed rules, priority, mitigation, separate policy score, canonical JSON, minimal HTML | 60 min |
| 8. ML proof | IsolationForest inputs, fixed seed, train/test separation, limitations | T08 controlled corpus, model hash, repeatable separate anomaly score | 45 min |
| 9. Decision | Reproducible testing and runtime measurement | Run T01–T08 twice; write `POC_RESULT.md`; issue GREEN/RED | 45 min |

This is an aggressive approximately eight-hour kill-test schedule. If setup or a core gate fails, record the blocker rather than removing a requirement.

## Mandatory just-in-time study list

Study only what is needed for the current step:

1. RFC 3207 concepts: SMTP STARTTLS command, `220` acceptance, and TLS upgrade on the same connection.
2. RFC 2595 concepts: IMAP STARTTLS and POP3 STLS responses.
3. TCP stream/reassembly basics: ordering, segmentation, retransmission, capture gaps, FIN/RST.
4. TLS 1.2 and TLS 1.3 handshake visibility, especially encrypted TLS 1.3 Certificate messages.
5. Cipher suite versus key-establishment mechanism and Forward Secrecy.
6. X.509 chain, SAN/hostname, capture-time validity, key size, and signature algorithm.
7. TShark offline two-pass analysis, display fields, decode-as, and follow-stream.
8. OpenSSL certificate creation, negotiated-session logging, fingerprinting, and `verify -attime`.
9. IsolationForest only when Step 8 begins; no advanced-ML course is required.

## Do not study or build yet

- Full React/Next.js dashboard work.
- Authentication architecture.
- PDF libraries.
- SIEM connectors.
- Cloud deployment or Docker orchestration.
- Phishing/spam/content ML.
- Custom packet dissectors or a custom TCP stack.
- Advanced supervised ML or large-dataset training.

## First technical hard checkpoint

The first 90-minute technical checkpoint begins only after the environment is ready. It passes when the controlled SMTP PCAP, endpoint/OpenSSL truth, and manual TShark evidence agree on:

- SMTP identification from content on a non-standard port;
- split STARTTLS reconstruction;
- `STARTTLS -> 220 -> ClientHello` on one stream;
- TLS 1.2 and the exact selected cipher;
- ECDHE/key-establishment evidence and FS=`yes`;
- observable certificate properties and successful capture-time verification.

If that evidence chain cannot be produced after normal setup corrections, record RED/BLOCKED and do not spend the day on reporting or UI.

## Blockers

None. Tool availability was verified on 2026-08-25 by the real doctor run (11/11 prerequisite checks passed, verdict `READY`, exit code 0).

## Production phase — Chain of Proof commit history

The PS159 selection POC is closed (GO/selection at `cf055cf`). Production development continues on branch `feat/production-backend` under the approved Chain-of-Proof contract (schema `1.0.0`). The frozen POC verification history above is preserved unchanged; production work does not rewrite it.

### Verified milestone — Chain Commit 1: domain contract (PASS, 2026-08-29)

- Commit: `feat: add chain-of-proof domain contract` at `57fe930`.
- Commit 1 **implemented the versioned Chain-of-Proof domain contract** under `src/securemailscope/chain` from the **approved external specification**, including typed domain models and invariant coverage for the contract.
- The **repository copy** of that specification, `docs/CHAIN_OF_PROOF_SPECIFICATION.md`, is **being added by the subsequent documentation synchronization** (this task), not by Commit 1. Its checksum matches the approved reference (SHA-256 `fa7b14d077a6e71c9e172898e410de08be7b0b87a237fec56e1c76c817f9bb25`).
- Existing analyzer remains stable; the contract layer is additive and does not alter frozen POC analysis, schemas, PCAPs, or expected outputs.
- No policy, ML, API, frontend, PDF, live capture, decryption, phishing detection, blocking, authentication, geolocation, or SIEM support is claimed at this commit.

Scope of this PASS: the Chain-of-Proof domain contract only. Commit 2 (the pure POC-result adapter that maps verified SMTP analysis into the chain) is the next milestone and remains **UNVERIFIED**. API, policy, ML, and report layers are later milestones.

## Production blockers and status

No production blockers recorded at Commit 1. Commit 2 (POC-result adapter) is the immediate next action. The frontend is separate and frozen; no frontend redesign is authorized during backend milestones. Policy risk and ML anomaly remain separate outputs throughout production work.

## Verified frontend workstream — V1 backend integration (PASS, 2026-09-01)

An explicitly authorized frontend-only slice on branch
`feat/frontend-v1-backend-integration` integrated the stable V1 UI with frozen
backend commit `f81bcc43ec660bfa32a40076bfe5c9f146d61339` without redesigning V1 or
modifying the backend repository.

Verified scope:

- one deployed frontend build supports both real analysis and the labelled
  Prototype Analysis Dataset;
- the fixed prototype analysis ID selects the mock source, while every other
  valid analysis ID selects the production API source, including direct route
  loads and refreshes;
- real submission sends exactly one multipart field, `capture`, to
  `POST /api/v1/analyses` and does not send frontend authorization state;
- the synchronous HTTP 201 response validates `api_version`, `analysis_id`, and
  `analysis_status` while the selected local filename remains frontend state;
- real results are constructed only from validated
  `GET /api/v1/analyses/{analysis_id}` and
  `GET /api/v1/analyses/{analysis_id}/chain` responses, with cross-response ID,
  status, version, engine, object-ID, and count checks;
- Explore Demo creates no File, requires no authorization, performs no API POST,
  and uses the existing Processing → Complete workflow before opening the
  clearly disclosed synthetic contract fixture through the mock source;
- only the prototype-ID processing branch shows deterministic 0–100% stages,
  labelled as simulated Prototype Demo presentation with explicit copy that no
  backend request or TShark analysis is running; the real processing branch
  retains summary/Chain validation without fake percentages;
- Policy Risk and ML Anomaly remain separate, and existing evidence-boundary
  and TLS 1.3 observability handling remain unchanged.

Validation recorded on 2026-09-01:

- `npm run lint`: passed with zero reported warnings or errors.
- `npx tsc --noEmit`: passed with no diagnostics.
- `npm run build`: passed with Next.js 16.3.3 Turbopack, including TypeScript
  and all route generation.
- `npm audit`: passed with zero vulnerabilities.
- `git diff --check`: passed.
- Required stale-route/data-mode/multipart greps: no `/status` or `/result`
  production API references, no `NEXT_PUBLIC_DATA_MODE` use under `web/src`,
  and only `formData.append("capture", ...)` in the API adapter.
- An additional loopback route-smoke attempt was blocked by the workspace
  sandbox (`listen EPERM`); no live browser/frontend-to-backend integration PASS
  is claimed from that attempt.

Remaining limitation: the frozen backend repository is in-memory, so a real
analysis deep link remains retrievable only while that backend process retains
the corresponding Chain. No deployment, backend mutation, V2 work, dependency
change, staging, commit, or push was performed.

## Verified frontend workstream — V3-2 judge presentation (PASS, 2026-09-23)

An explicitly authorized frontend-only refinement on branch
`feat/frontend-v3-submission` improved judge comprehension without changing the
application's route structure, validated data contracts, backend adapter, or
Chain-of-Proof source-of-truth boundary.

Verified scope:

- the original capture-selection Start Analysis page is retained;
- Overview and Report place a data-derived executive finding, impact, evidence
  counts, and direct evidence/action links before the detailed workspaces;
- processing, completion, Overview, Findings, Session X-Ray, Proof Map,
  Recommendations, and report actions use the same primary terminology in
  local and backend modes instead of repeating source-specific qualifiers;
- the local staged simulation was removed so both modes use the same processing
  presentation;
- a single compact source badge and Report provenance retain the truthful local
  dataset boundary without interrupting every workspace;
- Recommendations tab state is URL-backed for direct judge navigation; and
- report printing is labelled accurately as browser printing, with Save as PDF
  described as a possible browser option rather than a generated product
  artifact.

Validation recorded on 2026-09-23:

- `npx --no-install next typegen`: passed.
- `npx --no-install tsc --noEmit`: passed with no diagnostics.
- `npm run lint`: passed with zero reported warnings or errors.
- V2 model/proof-map checks, V3 submission-safety/demo checks, and the
  backend-mode report-consistency check: passed.
- `npm run build -- --webpack`: passed, including compilation, TypeScript,
  static generation, and all route generation.
- `npm audit`: passed with zero vulnerabilities.
- `uv run pytest -q`: 342 passed, 2 skipped because the frozen T01 PCAP is not
  present in this checkout.
- `uv run ruff check .` and `uv run ruff format --check .`: passed.
- `git diff --check`: passed.

No backend, controlled evidence, fixture, schema, dependency, deployment,
staging, commit, push, merge, tag, rebase, or amend operation occurred. The
sample remains a presentation of validated local contract data, not evidence
of a live analyzer or trained anomaly model run.

## Verified frontend workstream — V3-3 judge readability (PASS, 2026-09-23)

An explicitly authorized frontend-only review simplified information density
across all primary analysis routes without removing underlying evidence or
changing contracts, fixtures, data-source selection, routes, or backend code.

Verified scope:

- page introductions now explain the judge's immediate task in concise language;
- Sessions and Findings remove repeated analysis metadata and place optional
  search/filter controls behind accessible disclosures;
- summary metrics are reduced or compacted so the result inventory appears
  sooner, including two-column narrow layouts and four-column wide layouts;
- Proof Map shows the evidence graph before its collapsed legend;
- Session X-Ray shows observed events before its collapsed protocol reference;
- Comparison replaces a metadata strip with a concise difference count;
- Report prioritizes assessment, findings, and actions before screen provenance
  and progressively discloses detailed policy/ML records; and
- technical identifiers and complete source records remain available through
  inspectors, details, provenance sections, and the print appendix.

Validation recorded on 2026-09-23:

- `npx --no-install tsc --noEmit` and `npm run lint`: passed.
- V2 model/proof-map checks, V3 submission-safety/demo checks, and backend-mode
  report-consistency verification: passed.
- `npm run build -- --webpack`: passed with all routes generated.
- `npm audit`: passed with zero vulnerabilities.
- `uv run pytest -q`: 342 passed, 2 skipped because the frozen T01 PCAP is not
  present in this checkout.
- `uv run ruff check .` and `uv run ruff format --check .`: passed.
- Desktop Chrome review covered every primary route and the major secondary
  Policy/ML/evidence views; narrow 500 px review covered the key judge journey.
- `git diff --check`: passed.

No backend, controlled evidence, fixture, schema, dependency, deployment,
staging, commit, push, merge, tag, rebase, or amend operation occurred.
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
