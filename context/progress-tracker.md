# SecureMailScope — Progress Tracker

**Last updated:** 29 August 2026

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

## Verified frontend maintenance — dependency security update (PASS, 2026-10-01)

The authorized security update is isolated on `fix/frontend-dependencies`,
based on the V1 baseline at `da8c4b7`. Next.js and `eslint-config-next` are
pinned to `16.3.8` instead of `16.3.3`. The npm lockfile also updates the
affected brace-expansion, fast-uri, hono, ip-address, and undici resolutions
within the existing dependency constraints. No direct dependency was added.

Verification actually executed:

- `npm ci`: succeeded; zero reported vulnerabilities.
- `npm run lint`, `npx --no-install tsc --noEmit`, and `npm run build`:
  passed; the production build used Next.js 16.3.8 with Turbopack.
- `npm audit --json`: zero vulnerabilities at every severity.
- `uv sync --locked` and `uv run --locked pytest -q`: succeeded;
  342 passed and 2 skipped in 48.06 seconds. Both skips require the frozen
  T01 PCAP, which is absent from this worktree.
- `uv run --locked ruff check .` and
  `uv run --locked ruff format --check .`: passed; 65 files already formatted.
- `git diff --check`: passed.
- Ten local production HTTP routes returned 200: the homepage, new analysis,
  processing, completion, and the existing prototype Overview, Sessions,
  Proof Map, Findings, Compare, and Report routes. Overview and Report retained
  the Prototype Analysis Dataset disclosure. The local server was stopped.

The first formatting-check launch failed with WSL connection error
`0x8007274c`; its subsequent launch passed. Installation retains the existing
ESLint 9 deprecation warning; a major tooling upgrade was not part of this fix.

Application source, Python dependencies, contracts, and controlled evidence are
unchanged. No live backend upload or hydrated browser interaction was tested.
No staging, commit, push, merge, or deployment occurred; these patches are not
yet serving on the public site.

## Verified frontend refinement — upload entry shell (PASS, 2026-10-02)

Authorized slice on `feat/frontend-refinement`, based on released `main`
at `fcb6c7b`: only the shared shell and header implementation changed.
The upload route `/analysis/new` and homepage redirect shell omit the desktop
sidebar, mobile navigation menu, and duplicate header New analysis action.
The entry header retains a linked SecureMailScope identity, using V3 as the
layout reference. Processing, completion, and all results routes retain the
existing navigation. Upload, demo, API, data contracts, fixtures, dependencies,
and other screen implementations were not changed.

Verification actually executed:

- `npm ci --offline --no-audit --no-fund`: installed 665 locked packages from
  the local cache; the existing ESLint 9 deprecation warning remains.
- `npm run lint`, `npm run build`, and `npx --no-install tsc --noEmit`:
  passed. Build used Next.js 16.3.8 with the existing production API URL.
- `npm audit --json`: zero vulnerabilities at every severity.
- `uv sync --locked --offline` and `uv run --locked --offline pytest -q`:
  passed; 342 tests passed and 2 frozen-T01-PCAP-dependent tests skipped
  in 21.00 seconds.
- `uv run --locked --offline ruff check .` and
  `uv run --locked --offline ruff format --check .`: passed;
  65 files already formatted.
- `git diff --check`: passed.
- Local production HTTP checks: 11 routes returned 200. Parsed rendered HTML
  confirmed navigation is absent on entry and present on processing, completion,
  and six prototype result routes. File selection, Explore Demo, and prototype
  provenance remained present. Windows localhost reachability returned 200.

The first HTTP assertion incorrectly expected upload-form controls on `/`.
Inspection confirmed its existing meta redirect to `/analysis/new`; the
corrected check verifies that redirect separately and then the upload page.
Automated browser startup failed with the Windows sandbox helper setup error;
no screenshot, hydration, interactive-click, or live backend upload PASS is
claimed. The local production preview remains running on port 4181 for review.
No staging, commit, push, merge, or deployment was performed.


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
