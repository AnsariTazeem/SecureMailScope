# SecureMailScope — Progress Tracker

**Last updated:** 15 September 2026

**Current phase:** Backend V2 on `feat/backend-v2`. Backend V1 ends at `f81bcc4`, tagged `backend-v1-public-deployed`; Backend V2 CI begins at `94b6ac9`. The authoritative plan is `context/backend-v2-implementation-plan.md`. The selection POC remains CLOSED/GO at `cf055cf`; historical verification records below are preserved.

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

## Current Backend V2 status

VERIFIED: bounded PCAP/PCAPNG capture upload; capture validation, capinfos
metadata and SHA-256 provenance; bounded TShark analysis; synchronous
`analyze_capture_to_chain()` orchestration; supported email-session
reconstruction; Chain-of-Proof adaptation and invariant validation;
deterministic SMTP transition facts; deterministic policy evaluation;
JSON/HTML/PDF artifacts; `/api/v1` HTTP analysis and read endpoints; the
776-test baseline; and read-only Backend V2 CI.

SELECTED: the Backend V2 architecture and milestone sequence documented in the
authoritative implementation plan.

PLANNED and UNVERIFIED: durable database persistence; a durable job lifecycle
and bounded background executor; complete IMAP/POP3 transition analysis;
production ML; authentication, authorization and tenant isolation; staging;
and a repository-controlled Docker runtime.

DEFERRED: scale-out workers/queues/search and optional ledger anchoring until
prerequisites and measurements justify them. Blockchain is not implemented or
required.

CURRENT LIMITATIONS: analysis executes synchronously and may block the FastAPI
event loop; completed results exist only in the bounded in-memory repository;
there is no durable database or durable job lifecycle; and
`ml_engine_status=not_run` with no production ML execution.

Deployed Backend V1 and Frontend V1 remain unchanged. Do not modify either
production branch, Railway, Vercel, public production URLs or production API
behavior. Future integration requires a separate staging backend and staging
API URL; production deployment changes are not authorized.

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

## Historical Backend V1 — Chain-of-Proof commit history

The milestones in this section are preserved historical Backend V1 checkpoints.
Statements that a later capability was absent describe the boundary at that
checkpoint, not the current Backend V1 baseline. The PS159 selection POC is
closed at `cf055cf`; the frozen POC verification history above remains unchanged.

### Verified milestone — Chain Commit 1: domain contract (PASS, 2026-08-29)

- Commit: `feat: add chain-of-proof domain contract` at `57fe930`.
- Commit 1 **implemented the versioned Chain-of-Proof domain contract** under `src/securemailscope/chain` from the **approved external specification**, including typed domain models and invariant coverage for the contract.
- The **repository copy** of that specification, `docs/CHAIN_OF_PROOF_SPECIFICATION.md`, is **being added by the subsequent documentation synchronization** (this task), not by Commit 1. Its checksum matches the approved reference (SHA-256 `fa7b14d077a6e71c9e172898e410de08be7b0b87a237fec56e1c76c817f9bb25`).
- Existing analyzer remains stable; the contract layer is additive and does not alter frozen POC analysis, schemas, PCAPs, or expected outputs.
- No policy, ML, API, frontend, PDF, live capture, decryption, phishing detection, blocking, authentication, geolocation, or SIEM support is claimed at this commit.

Scope of this PASS: the Chain-of-Proof domain contract only. Commit 2 (the pure POC-result adapter that maps verified SMTP analysis into the chain) is completed and verified at `616b97d` and recorded in the next section. API, policy, ML, and report layers are later milestones.

### Verified milestone — Chain Commit 2: pure POC-result adapter (PASS, 2026-08-30)

- Commit: `feat: map verified smtp analysis into evidence chain` at `616b97d`.
- Commit 2 **implemented the pure POC-result adapter** that maps the already-verified SMTP analyzer output into Chain-of-Proof objects valid under the schema and graph invariants.
- Implemented behavior (conservative):
  - pure, deterministic transformation from the existing typed `AnalyzeResult` into `ChainOfProof` objects;
  - capture provenance mapping;
  - discovered TCP/SMTP session mapping;
  - content-based classification evidence;
  - STARTTLS command/response/ClientHello event mapping when positively proven;
  - stable deterministic Chain IDs;
  - evidence references carrying the available frame/session provenance;
  - capture/analysis partial and limitation propagation;
  - safe, bounded stage diagnostics;
  - safe warning and filename sanitization;
  - chain collections whose evidence is not yet implemented remain empty (`crypto_observations`, `derived_facts`, `rule_evaluations`, `findings`, `policy_risk`, `anomaly_results`, `recommendations`, `artifacts`).
- Test evidence recorded on 2026-08-30:
  - 111 adapter tests passed;
  - 142 existing Chain contract tests passed;
  - 455 full-suite tests passed;
  - Ruff check passed; Ruff formatting check passed; `git diff --check` passed.
- Independent architectural review: **GREEN** for the authorized Commit 2 scope.
- The frozen POC analyzer and evidence records (schemas, PCAPs, manifests, expected outputs) were **not modified**.

Explicit limitations:

- No deterministic `DerivedFact` production yet (Commit 3).
- No `RuleEvaluation`, `Finding`, `Recommendation`, policy-risk, or anomaly production (Commit 4 and later).
- No negotiated TLS version, cipher suite, key exchange, Forward Secrecy, or certificate details are invented; ordered TLS handshake-type observations prove message presence only.
- No API, frontend, or report implementation.
- Commit 3 remains **UNVERIFIED**.

Scope of this PASS: the pure POC-result adapter only. Commit 3 (deterministic derivation of SMTP transition facts from ordered, evidence-backed Chain events) is the next milestone and remains **UNVERIFIED**.

### Verified milestone — Chain Commit 3: deterministic SMTP transition facts (PASS, 2026-08-30)

- Commit: `feat: derive smtp transition facts from ordered evidence` at `2c1454f`.
- Commit 3 **implemented the deterministic fact derivation** that produces SMTP STARTTLS transition facts from the ordered, evidence-backed protocol events of a `ChainOfProof` document.
- Implemented behavior (conservative, evidence-bounded):
  - pure, deterministic function `derive_smtp_transition_facts` that consumes only observed SMTP events (`protocol == smtp`, `event_status == observed`, `observability == observed`, non-empty `evidence_ids`);
  - `starttls_advertised` fact (true when at least one observed `CAPABILITY_ADVERTISED` event exists; never false from absence);
  - `plaintext_commands_after_offer` fact (exact count of observed `PLAINTEXT_COMMAND_AFTER_TLS_OFFER` events strictly after an observed `CAPABILITY_ADVERTISED`; pre-offer EHLO/HELO remain `CAPABILITY_REQUEST` and are not counted);
  - `tls_upgrade_completed` fact decided by ordered scan of observed events (request < accept < finished = true; request < reject = false; accept < plaintext = false with complete capture; advertisement < plaintext = false with complete capture; capture incomplete/insufficient evidence = explicit state, not a guess);
  - facts owned by this derivation (matched by `derivation_id`) are dropped and recomputed deterministically, so repeated application is idempotent; facts from other derivations are preserved byte-for-byte.
- Test evidence recorded on 2026-08-30:
  - 175 Commit 3 focused adapter/fact tests passed;
  - 142 existing Chain contract tests passed;
  - 519 full-suite tests passed;
  - Ruff check passed; Ruff formatting check passed; `git diff --check` passed.
- Independent architectural review: **GREEN** for the authorized Commit 3 scope.
- The frozen POC analyzer and evidence records (schemas, PCAPs, manifests, expected outputs) were **not modified**.

Explicit limitations:

- No policy `RuleEvaluation`, `Finding`, `Recommendation`, policy-risk, or anomaly production (Commit 4 and later).
- No negotiated TLS version, cipher suite, key exchange, Forward Secrecy, or certificate details are derived; handshake events prove message presence only.
- No API, frontend, or report implementation.
- Commit 4 remains **UNVERIFIED**.

Scope of this PASS: the deterministic SMTP transition fact derivation only. Commit 4 (deterministic policy evaluation layer producing evidence-backed policy evaluations, findings, recommendations, and policy-risk output) is the next milestone and remains **UNVERIFIED**.

### Verified milestone — Chain Commit 4: deterministic policy evaluation engine (PASS, 2026-08-31)

- Commit: `feat: add deterministic policy evaluation engine` at `ad25711`.
- Commit 4 implemented deterministic policy-pack loading and policy evaluation over the validated Chain-of-Proof, producing evidence-backed rule evaluations, findings, recommendations and policy-risk output.
- Verified scope:
  - strict bounded YAML policy-pack loading;
  - deterministic rule evaluation;
  - conservative `UNKNOWN`/`INSUFFICIENT_EVIDENCE` handling;
  - mandatory evidence lineage;
  - deterministic findings and recommendations;
  - confidence-adjusted and capped policy-risk contributions;
  - policy-risk and ML anomaly outputs remain separate;
  - atomic, non-mutating Chain replacement.
- Full tests and quality checks passed before commit.
- The frozen POC analyzer and evidence records (schemas, PCAPs, manifests, expected outputs) were not modified.

Explicit limitations:

- No full TLS/cipher/key-exchange/Forward-Secrecy/X.509 support; TLS handshake observations remain message-presence evidence only.
- No IMAP or POP3 production support.
- No API, frontend, ML anomaly, report/PDF, live capture, authentication, decryption, phishing detection, blocking, geolocation, or SIEM implementation.
- TLS 1.3 certificate contents remain not observable without authorized session secrets.
- Ports remain hints, not protocol classification.

Scope of this PASS: deterministic policy evaluation over the validated Chain-of-Proof only. At the Commit 4 checkpoint, the Commit 5 presentation/API/artifact boundary had not yet been implemented; its verified Commit 5A portion is recorded in the next section.

### Verified milestone — Commit 5A: evidence-backed finding artifacts (PASS, 2026-08-31)

- Commit: `feat: render evidence-backed finding artifacts` at `3807118`.
- Commit 5A implemented a deterministic presentation and artifact-rendering foundation over an already validated and policy-evaluated Chain-of-Proof.
- Verified scope:
  - strict immutable selected-finding projection;
  - canonical Chain JSON;
  - autoescaped finding HTML;
  - deterministic finding PDF;
  - artifact SHA-256 digests and byte lengths;
  - evidence-backed event timeline ordered by `(sequence_index, event_id)`;
  - exact evidence frame numbers and timestamps;
  - finding rationale, impact, remediation and standards references;
  - policy-risk and ML-anomaly presentation kept separate.
- Verification evidence:
  - independently source-reviewed before commit;
  - final source archive SHA-256: `8aed36c24684ef254b1a66374ee148ccb0d339d2663317c51079e7a749d61dfd`;
  - focused presentation suite: 19 passed;
  - full suite: 618 passed;
  - Ruff check passed;
  - Ruff formatting check passed;
  - `git diff --check` passed;
  - security/forbidden-pattern scan clean.

Explicit limitations:

- Commit 5A does not analyze packets, derive new facts, evaluate policy or run ML.
- It does not write artifacts to the filesystem, expose HTTP/API routes, or implement upload or analysis-job orchestration.
- It adds no persistence, authentication or frontend code.
- It does not attribute an attacker or expose raw SMTP payloads, credentials, email addresses or arbitrary filesystem paths.

Scope of this PASS: deterministic selected-finding presentation and in-memory artifact rendering only. The separately verified Commit 5B HTTP exposure is recorded in the next section.

### Verified milestone — Commit 5B: read-only Chain API (PASS, 2026-08-31)

- Commit: `feat: expose validated chain through read-only api` at `a262b24`.
- Independently source-reviewed before commit.
- Final review archive SHA-256: `c2d181391f5b3282d9f0160e082056c2aacdb56de4fba05e5005758ef4f1d4ee`.
- Focused API suite: 101 passed.
- Full suite: 719 passed.
- Ruff check passed.
- Ruff formatting check passed.
- `git diff --check` passed.
- Forbidden-pattern/security scan clean.

Commit 5B implemented a thin, read-only FastAPI exposure layer over an injected repository of validated Chain-of-Proof objects and the verified Commit 5A presentation/artifact services. Its seven read-only GET resources cover health, analysis summaries, canonical Chain retrieval, session events, safe evidence, finding presentations and existing artifacts; the exact route list is recorded in `context/architecture.md`.

Verified properties:

- versioned `/api/v1` read-only boundary;
- dependency-injected `AnalysisChainRepository`;
- bounded, thread-safe in-memory implementation;
- isolated deep snapshots on registration and retrieval;
- invariant validation on registration and again after repository retrieval;
- authoritative Chain ID validation;
- typed API-specific projections;
- direct reuse of Commit 5A `FindingPresentation` and artifact services;
- canonical deterministic JSON bytes and response byte-size bounds;
- SHA-256, ETag, content-length, `no-store` and `nosniff` headers;
- stable non-sensitive error envelopes;
- explicitly configured CORS with wildcard origins rejected;
- OpenAPI response schemas;
- canonical Chain JSON and existing finding HTML/PDF artifact exposure;
- no duplicated analyzer, fact, policy, ML or presentation business logic.

Commit 5B does not add PCAP upload; POST/PUT/PATCH/DELETE analysis behavior; background jobs or queues; database persistence; authentication or authorization; frontend implementation; analyzer, policy or ML execution; live capture; SIEM; phishing detection; blocking; email decryption; geolocation; external AI APIs; silent online dependencies; or filesystem artifact writing. The default production application repository is empty; test data is injected only in tests.

Scope of this PASS: read-only HTTP exposure of validated Chain and existing Commit 5A presentation/artifact services. FastAPI does not perform packet analysis, fact derivation, policy evaluation or ML execution. Current production capability remains bounded by verified SMTP coverage. TLS 1.3 certificate details remain `not_observable` without authorized session secrets. Ports remain hints and protocol classification remains content-based. Policy risk and ML anomaly remain separate outputs.

### Commit 5 vertical boundary status

Commit 5A completed deterministic presentation and in-memory artifacts. Commit
5B completed the thin read-only HTTP exposure. At that historical checkpoint,
upload and orchestration were not yet implemented; they were added by the
verified milestones below.

### Verified milestone — Commit 6A: synchronous analysis orchestration (PASS)

- Commit: `639fd47`.
- Added synchronous `analyze_capture_to_chain()` orchestration across capture
  validation/provenance, bounded TShark analysis, supported email-session
  reconstruction, Chain adaptation, deterministic SMTP fact derivation, policy
  evaluation, final invariant validation and bounded repository registration.
- This is synchronous request-path execution, not a durable job lifecycle or a
  bounded background executor.

### Verified milestone — Commit 6B: secure capture upload and Backend V1 boundary (PASS)

- Commit: `f81bcc4`, tagged `backend-v1-public-deployed`.
- Added bounded PCAP/PCAPNG upload through `POST /api/v1/analyses`, including
  multipart bounds, capture validation, private temporary handling, capinfos
  metadata, SHA-256 provenance and cleanup.
- Backend V1 verification baseline: 776 tests passed.
- Backend V2 read-only CI begins at `94b6ac9`; it contains no deployment step,
  secret use, OIDC write permission or repository write permission.

## Backend V2 limitations and status

### Verified milestone — V2-1 Slice 1: analysis identity and fingerprint contracts (PASS)

Milestone V2-1 Slice 1 implemented the identity contracts required before
durable persistence or asynchronous jobs:

- opaque, public-safe, random 128-bit job IDs that are separate from capture
  and analysis identities;
- validated raw lowercase-hex SHA-256 capture and configuration digests using
  the existing Chain digest convention;
- strict immutable packet-toolchain, protocol-plugin and optional executed-ML
  identities, including ML inference-runtime identity/version;
- a versioned analysis-fingerprint input containing capture, analyzer, Chain
  schema, exact TShark/capinfos, analysis configuration, policy pack, profile,
  sorted plugin and conditional ML identity;
- deterministic raw SHA-256 fingerprints over existing canonical JSON bytes;
- explicit exclusion of job/request IDs, execution timestamps, filenames,
  paths and raw capture bytes.

Verification evidence recorded on 2026-09-14:

- `uv lock --check`: passed;
- `uv run --locked ruff check .`: passed;
- `uv run --locked ruff format --check .`: passed;
- focused identity suite: 118 passed;
- complete suite: 894 passed;
- no dependency or lock-file change.

Scope of this PASS is analysis identity and fingerprint contracts only. The
remaining V2-1 repository protocols and shared repository behavior tests are
still SELECTED and UNVERIFIED. Durable storage, event-loop isolation, durable
jobs, API V2, complete IMAP/POP3 transitions, production ML,
authentication/tenant isolation, staging and Docker runtime are PLANNED and
remain UNVERIFIED. No production deployment change is authorized.

### Verified milestone — V2-1 Slice 2: analysis-result storage contracts (PASS)

Milestone V2-1 Slice 2 added database-agnostic storage-domain boundaries for
completed analysis results while retaining the verified Backend V1 in-memory
adapter and `/api/v1` behavior:

- segregated runtime-checkable `AnalysisResultReader` and
  `AnalysisResultRegistry` protocols plus an `AnalysisResultRepository`
  composite built only from those two contracts;
- a storage error hierarchy distinguishing optional-result absence, invalid
  registration, identity conflict, unavailable capacity, stored corruption,
  unsupported stored schema version and internal storage failure;
- compatibility inheritance for the existing `RepositoryInvalidChainError`,
  `RepositoryConflictError` and `RepositoryCapacityError` names;
- the existing `AnalysisChainRepository` remains the V1 read-only compatibility
  protocol, while orchestration's existing `AnalysisChainRegistry` now requires
  registration only;
- the existing in-memory adapter remains bounded and thread-safe, and now
  reconstructs and validates strict Chain models plus complete Chain invariants
  on retrieval, compares full canonical Chain bytes for idempotency, and
  translates ordinary copy, dump, reconstruction, invariant and canonical
  serialization failures into the appropriate incoming-result or
  stored-integrity category without mutating repository state;
- `/api/v1` read helpers depend only on the reader contract, the application
  composition root uses the composite contract, and stored-integrity failures
  retain the established safe `invalid_chain` HTTP response.

Verification evidence recorded on 2026-09-14:

- `uv lock --check`: passed;
- `uv run --locked ruff check .`: passed;
- `uv run --locked ruff format --check .`: passed (105 files checked);
- focused repository/storage suite: 27 passed;
- broader repository/orchestration/API compatibility suite: 159 passed;
- complete suite: 907 passed;
- no dependency or lock-file change.

Scope of this PASS is completed-analysis result protocols, storage errors,
in-memory conformance and focused contract tests only. Job repository contracts
and explicit repeated-upload semantics remain SELECTED and UNVERIFIED V2-1
work. Durable persistence, database tables/migrations, durable jobs, background
execution, API V2, authentication/tenant isolation, staging, Docker runtime and
deployment remain unimplemented. No production deployment change is authorized.

### Verified milestone — V2-1 Slice 3: job domain and repository contracts (PASS)

Milestone V2-1 Slice 3 added the persistence-neutral analysis-job domain and a
bounded in-memory repository boundary without changing Backend V1 API or
orchestration behavior:

- one strict, frozen `JobSnapshot` separates random job ID, exact-capture
  SHA-256, optional analysis fingerprint and final validated analysis ID;
- the closed initial job-state vocabulary is `accepted`, `queued`, `running`,
  `completed`, `failed` and `interrupted`, with state-specific field and UTC
  timestamp-order invariants; both terminal non-success states require a safe
  public failure code, and neither may expose a partial analysis ID;
- runtime-checkable reader, creator and updater protocols are segregated, with
  a composite containing only those operations;
- database-agnostic job errors distinguish missing jobs, invalid snapshots,
  identity/content conflicts, stale revisions, unavailable capacity and stored
  corruption while reusing the Slice 2 storage application/integrity hierarchy;
- the bounded thread-safe in-memory adapter reconstructs complete strict
  snapshots at every trust boundary, stores and returns isolated snapshots,
  rejects corrupted state, never evicts or upserts, and permits only exact
  same-job-ID creation to be idempotent;
- optimistic updates require the stored revision to equal the caller's expected
  revision and the replacement to advance exactly once; a deterministic
  12-party barrier test verified exactly one winner and 11 typed stale-revision
  conflicts from revision zero;
- each independently accepted upload receives a new random job ID. Identical
  capture bytes may share a capture digest, and identical complete
  output-affecting inputs may share a fingerprint, but neither value causes job
  or result deduplication. A shared final analysis ID is possible only if a
  future authorized, owner-scoped result-reuse decision selects the same
  validated deterministic result;
- there is no lookup or global deduplication by capture digest or analysis
  fingerprint, no Idempotency-Key handling and no cross-user existence oracle.

Verification evidence recorded on 2026-09-15:

- `uv lock --check`: passed;
- `uv run --locked ruff check .`: passed;
- `uv run --locked ruff format --check .`: passed (112 files checked);
- focused job model/repository suite: 109 passed;
- existing identity suite, including the golden fingerprint vector: 118 passed;
- existing repository/orchestration/API compatibility suite: 159 passed;
- complete suite: 1,016 passed in 32.48 seconds;
- no dependency or lock-file change.

Scope of this PASS is immutable job snapshots, segregated job repository
contracts, the bounded thread-safe in-memory adapter, optimistic revision
semantics, fail-closed corruption handling and explicit repeated-upload
identity rules only. The job repository is in-memory and is not wired into
FastAPI or synchronous orchestration. No durable database, asynchronous API,
job executor, transition state machine, leasing, recovery, retry,
backpressure, authentication, authorization or tenant scope exists yet. API V2,
staging, Docker runtime and deployment remain unimplemented. No production
deployment change is authorized.
