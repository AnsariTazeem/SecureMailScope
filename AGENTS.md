# SecureMailScope — Repository Agent Instructions

## Purpose

SecureMailScope is **currently in Backend V2 development** on branch
`feat/backend-v2`, building on the deployed Backend V1 baseline for SIH 2026
PS159: AI-assisted cryptographic security posture assessment of email
communications. The authoritative implementation plan is
`context/backend-v2-implementation-plan.md`.

The selection POC was a **technical viability/kill test** and **closed as GO at
`cf055cf`**. Its verified analyzer scope is limited to: generic capture
intake/provenance, safe bounded TShark, native TCP reassembly, conservative
content-based SMTP classification, SMTP STARTTLS transition analysis, typed
models/errors, the T01 manual verification PASS (23/23), and the E2/E3A
analyzer-path checkpoint PASS.

Backend V1 ends at commit `f81bcc4`, tagged `backend-v1-public-deployed`.
Backend V2 CI begins at `94b6ac9`. Backend V2 work occurs only on
`feat/backend-v2`; deployed Backend V1, Frontend V1, `feat/production-backend`,
`feat/production-frontend`, production URLs, Railway/Vercel configuration and
production API behavior must remain unchanged.

Current capability labels are strict:

- **VERIFIED:** bounded PCAP/PCAPNG upload; capture validation, capinfos
  metadata and SHA-256 provenance; bounded TShark analysis; synchronous
  `analyze_capture_to_chain()` orchestration; supported email-session
  reconstruction; Chain adaptation and invariant validation; deterministic
  SMTP transition facts and policy evaluation; JSON/HTML/PDF artifacts; the
  `/api/v1` analysis and read endpoints; the 776-test baseline; and read-only
  Backend V2 CI.
- **SELECTED:** the Backend V2 architecture and milestone sequence in
  `context/backend-v2-implementation-plan.md`.
- **PLANNED:** durable repositories and job lifecycle, bounded background
  execution, staging-only deployment/runtime support, complete IMAP/POP3
  transition analysis, production ML, and authentication/tenant isolation.
- **DEFERRED:** scale-out workers/queues/search and optional ledger anchoring
  until prerequisites and measurements justify them.
- **UNVERIFIED:** every selected, planned or deferred capability until supported
  by implementation evidence and tests.

The current verified service is still synchronous and may block the FastAPI
event loop. Results exist only in the bounded in-memory repository. There is no
durable database, durable job lifecycle, bounded background executor,
production ML, authentication, authorization, tenant isolation, staging
deployment or repository-controlled Docker runtime. Complete IMAP and POP3
transition analysis is not verified; `ml_engine_status` remains `not_run`.

### Historical Backend V1 milestone record

The following Commit 1–5B descriptions are preserved historical milestone
boundaries. Statements that upload or orchestration were absent apply only at
the named checkpoint.

**Chain Commit 1** (`feat: add chain-of-proof domain contract`) is complete at
`57fe930`; **Chain Commit 2** (`feat: map verified smtp analysis into evidence
chain`), the pure POC-result adapter, is **completed and verified at `616b97d`**.
**Chain Commit 3** (`feat: derive smtp transition facts from ordered evidence`) is
**completed and verified at `2c1454f`**: deterministic derivation of SMTP
transition facts from ordered, evidence-backed Chain events.
**Chain Commit 4** (`feat: add deterministic policy evaluation engine`) is
**completed and verified at `ad25711`**: deterministic policy-pack loading and
policy evaluation over the validated Chain-of-Proof, producing evidence-backed
rule evaluations, findings, recommendations and policy-risk output. **Commit
5A** (`feat: render evidence-backed finding artifacts`) is **completed and
verified at `3807118`**: a deterministic presentation and artifact-rendering
foundation over an already validated and policy-evaluated Chain-of-Proof.

Commit 5A produces a strict immutable selected-finding projection, canonical
Chain JSON, autoescaped finding HTML, deterministic finding PDF, artifact
SHA-256 digests and byte lengths, an evidence-backed event timeline ordered by
`(sequence_index, event_id)`, exact evidence frame numbers and timestamps,
finding rationale, impact, remediation and standards references, and separate
policy-risk and ML-anomaly presentation.

Commit 5A does not analyze packets, derive new facts, evaluate policy, run ML,
write artifacts to the filesystem, expose HTTP/API routes, implement upload or
analysis-job orchestration, add persistence, authentication or frontend code,
attribute an attacker, or expose raw SMTP payloads, credentials, email
addresses or arbitrary filesystem paths.

**Commit 5B** (`feat: expose validated chain through read-only api`) is
**completed and verified at `a262b24`**: a thin, read-only FastAPI exposure
layer over an injected repository of validated Chain-of-Proof objects and the
verified Commit 5A presentation/artifact services. Its versioned `/api/v1`
boundary provides typed, bounded, deterministic access to analysis summaries,
canonical Chain JSON, session events, safe evidence, finding presentations and
existing JSON/HTML/PDF artifacts. It uses a dependency-injected
`AnalysisChainRepository`, validates Chain invariants at repository and API
boundaries, and does not duplicate analyzer, fact, policy, ML or presentation
business logic.

Commit 5A completed deterministic presentation and in-memory artifacts; Commit
5B completed the thin read-only HTTP exposure. The declared backend Commit 5
presentation/API/artifact boundary is therefore completed and verified through
`3807118` and `a262b24`.

At the Commit 5B checkpoint, that commit did not add PCAP upload, write analysis
methods, background jobs, persistence, authentication, ML execution or
deployment, and its default repository was empty. The frontend remained a
separate workstream. TLS 1.3 certificate details remained `not_observable`
without authorized session secrets, ports remained hints, and Policy Risk and
ML Anomaly remained separate.

Commits `639fd47` and `f81bcc4` subsequently completed synchronous orchestration
and secure capture upload. Deterministic Policy Risk and ML Anomaly remain
separate. Blockchain is neither implemented nor required; optional ledger
anchoring is deferred.

Correctness, reproducibility, evidence integrity, and honest limitations take
precedence over feature breadth or presentation polish.

## Mandatory startup sequence

Before planning or changing code:

1. Read `MASTER_PROMPT.md`.
2. Read `context/project-overview.md`.
3. Read `context/progress-tracker.md`.
4. Use the routing table in `MASTER_PROMPT.md` to select the remaining
   task-specific documents.
5. Inspect `git status --short` and preserve all existing user changes.
6. Inspect the relevant implementation and tests before editing.

Do not infer completion from a planned directory, unchecked checklist, design
document, or generated artifact. `context/progress-tracker.md` is the current
production implementation truth; `docs/POC_RESULT.md` is the frozen
selection-POC evidence record.

## Canonical repository documents

- `docs/OFFICIAL_PS159.md`: verbatim official problem statement
- `docs/PRD.md`: frozen POC requirements and acceptance gates
- `docs/SYSTEM_DESIGN.md`: system boundaries, components, and data flow
- `docs/FEATURE_BREAKDOWN.md`: implementation order and checkpoints
- `docs/TOOLING.md`: approved tools and dependency rationale
- `context/project-overview.md`: concise project context
- `context/architecture.md`: historical POC architecture plus active production architecture
- `context/rules.md`: detailed AI workflow and code rules
- `context/progress-tracker.md`: current verified implementation status
- `context/ui-context.md`: minimal report/UI rules when relevant
- `docs/POC_RESULT.md`: evidence record and final GREEN/RED recommendation
- `docs/CHAIN_OF_PROOF_SPECIFICATION.md`: approved Chain-of-Proof production contract (schema `1.0.0`)

When documents appear inconsistent, do not silently reinterpret them. Stop and
report the exact conflict. The official statement defines the original problem;
the PRD defines the strict POC subset and acceptance gates; the progress tracker
and POC result define what has actually been verified.

## Authority boundaries: frozen POC versus production

The repository contains a **frozen POC history**, a protected deployed Backend
V1 baseline, and active Backend V2 work on `feat/backend-v2`:

- The PS159 selection POC is **closed** and frozen at `cf055cf`. Do not rewrite,
  reinterpret, weaken, or extend the frozen POC records: `docs/POC_RESULT.md`,
  `docs/PRD.md`, `docs/SYSTEM_DESIGN.md`, the frozen capture fixtures, and the
  POC expected outputs.
- Backend development builds on the verified POC core. The Chain target
  phase is governed by the approved Chain-of-Proof contract in
  `docs/CHAIN_OF_PROOF_SPECIFICATION.md` (schema `1.0.0`) and by
  `context/architecture.md` (Backend V2 section).
- Backend V1 ends at `f81bcc4` (`backend-v1-public-deployed`); Backend V2 CI
  begins at `94b6ac9`. Do not modify either production branch or any deployed
  V1 service. Future integration requires a separate staging backend and API
  URL and explicit deployment approval.
- Preserve the entire POC verification history in `context/progress-tracker.md`
  when appending production progress.

## Required Chain specification

Before any production Chain-of-Proof work, read
`docs/CHAIN_OF_PROOF_SPECIFICATION.md`. It is the approved production contract
(schema `1.0.0`) and defines the domain models, graph invariants, observability
and confidence enums, protocol-transition semantics, TLS/X.509 evidence rules,
policy-as-code contract, risk/anomaly separation, integrity rules, the Commit
sequence, and the definition of done. Do not silently alter its technical
content; report any conflict for an explicit decision.

### Contract shape versus verified status

- The Chain specification defines the **contract shape**; it does **not** prove
  that every optional capability it mentions is implemented or currently
  authorized. For example, an optional PDF-related field does not authorize PDF
  implementation.
- `context/progress-tracker.md` defines **verified implementation status**.
- Current explicit product constraints control whether optional features such
  as PDF are authorized.
- Deterministic finding PDF rendering was explicitly authorized and verified
  within Commit 5A. That authorization does not include filesystem writes or
  frontend work; read-only artifact exposure was separately completed and
  verified in Commit 5B.

## Plan/review/test/commit workflow (production)

1. Plan the smallest authorized slice against the frozen requirement and the
   Chain-of-Proof contract; confirm it is authorized by the current request.
2. Implement without rewriting or weakening the frozen POC contract.
3. Review the change against the existing implementation and tests before
   committing; never stage, commit, or push unless explicitly requested.
4. Run the required verification (see below) and record only what actually ran.
5. Append verified progress to `context/progress-tracker.md` only after a
   material, verified state change.
6. Do not fabricate evidence. Never derive ground truth from the analyzer being
   evaluated, and never edit evidence JSON, manifests, logs, or reports to
   convert a failure into a pass.
7. Frontend implementation remains a separate workstream; do not treat it as a
   backend capability claim.

## Historical planned POC proof matrix

This is the original planned T01–T08/G01–G11 matrix. It is preserved as
historical requirements and does **not** claim the closed selection POC
completed the matrix. Current production milestones use the Chain specification
(`docs/CHAIN_OF_PROOF_SPECIFICATION.md`) and their separately authorized
acceptance tests.

The controlled test matrix must prove:

1. Automatic content-based identification of SMTP, IMAP, and POP3, including
   the intended non-standard-port tests.
2. Correct SMTP STARTTLS, IMAP STARTTLS, and POP3 STLS transition handling.
3. TCP and email-session reconstruction, including controlled segmentation and
   relevant incomplete or rejected-transition cases.
4. Ordered TLS-handshake reconstruction.
5. Extraction of negotiated TLS version, cipher suite, and observable
   key-establishment mechanism or group.
6. Forward Secrecy assessment derived from observable cryptographic evidence.
7. X.509 extraction, properties, chain/hostname/time validation, expiration,
   public-key, key-length, and signature-algorithm analysis when observable.
8. Honest handling of TLS 1.3 certificate invisibility in ordinary passive
   captures without decryption secrets.
9. Findings and recommendations that reference concrete evidence.
10. Separate deterministic policy-risk and ML-anomaly scores.
11. Schema-validated canonical JSON and minimal HTML rendered only from that
    JSON.

## Historical POC exclusions

The following historical POC exclusions are preserved. Their safety restrictions
remain applicable where still relevant to production work.

Do not build authentication, a large dashboard, general live capture, PDF
export, SIEM integration, unrelated phishing detection, or other scope not
required by the frozen POC.

Controlled loopback packet capture is test-fixture generation, not a product
live-capture feature. Run it only when the user explicitly authorizes that exact
capture attempt.

## Evidence and scientific-integrity rules

- Ground truth must be produced independently of analyzer output.
- A generator success is not a test PASS. An independent verifier must agree
  with the frozen manifest and observable PCAP evidence.
- Every finding must reference packet, frame, stream, protocol transition,
  handshake, certificate, validation, or derived-feature evidence.
- Preserve hashes for PCAPs, public certificates, manifests, endpoint logs,
  capture logs, evidence reports, models, and final reports where required.
- Do not overwrite, regenerate, delete, or repair controlled evidence without
  explicit authorization.
- Never manually edit evidence JSON, manifests, logs, or reports to convert a
  failure into a pass.
- Never derive ground truth from the analyzer being evaluated.
- Never infer encrypted TLS 1.3 certificate contents from an undecrypted passive
  capture. Use explicit states such as `not_observable`, `unknown`,
  `not_assessable`, or `not_applicable` where appropriate.
- Keep observed facts, deterministic policy conclusions, and ML outputs
  separate in code and report schemas.
- Keep policy-risk and ML-anomaly scores separate. Never present their sum or
  average as if it were an independently validated fact.
- Use `PASS`, `FAIL`, `BLOCKED`, and `UNTESTED` precisely. Never report planned
  or partially demonstrated behavior as complete.
- Update `docs/POC_RESULT.md` only with commands and evidence that actually ran.

## Engineering constraints

- Use Python `>=3.12,<3.13`, as pinned by `.python-version` and
  `pyproject.toml`.
- Use `uv` for dependency management, locking, environments, and Python
  command execution.
- Keep `uv.lock` synchronized and do not add dependencies without a concrete
  authorized task requirement and documented justification.
- Use TShark as the packet-dissection source and OpenSSL/`cryptography` for the
  defined independent certificate checks.
- Invoke external commands with explicit argument lists, bounded output,
  checked return codes, deterministic options, and useful typed errors.
- Do not use unsafe shell interpolation or `shell=True` for data-derived input.
- Use strict Pydantic models and JSON Schema at trust and output boundaries.
- Canonical JSON is the report source of truth. HTML must not calculate or
  invent independent values.
- Keep deterministic policy logic auditable and separate from ML code.
- ML experiments must use frozen features, a fixed random seed, explicit
  training/evaluation separation, saved model metadata, and reproducible tests.
- Prefer small pure functions, typed interfaces, dependency injection for
  external tools, and deterministic unit tests.
- Keep changes narrowly scoped to the proven requirement or defect.
- Add or update regression tests whenever behavior changes.
- Do not suppress, skip, or weaken a test merely to obtain a green test run.

## Required verification

Run focused tests while developing. Before handing off a source change, run:

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Run `uv run securemailscope doctor` when changing prerequisites, external-tool
integration, or capture/analysis infrastructure.

For fixture or evidence work, also verify the relevant artifact hashes and
actual-versus-expected evidence. Record real runtimes for final POC execution.

Do not run `dumpcap`, a fixture generator, a live controlled endpoint, a
destructive cleanup, or a `--force` operation unless the user has explicitly
authorized it.

## Filesystem and Git safety

- Treat existing modified and untracked files as user-owned work.
- Do not delete or overwrite unrelated files.
- Do not use destructive Git commands.
- Do not stage, commit, amend, rebase, push, or create a pull request unless the
  user explicitly requests that operation.
- Never expose or commit private keys, TLS key logs, secrets, credentials,
  environment files, or sensitive captures.
- Keep private fixture material only in the Git-ignored locations defined by
  the repository.
- Do not modify the verbatim official problem statement.

## Agent behavior

- Lead with evidence and the concrete outcome.
- State assumptions and unresolved uncertainty explicitly.
- Ask before any action that changes evidence, expands scope, adds a dependency,
  requires network access, or changes the frozen architecture.
- Do not perform unrelated refactors during a focused proof or defect fix.
- Do not claim a command ran if it was mocked or not executed.
- Distinguish unit-test proof, mocked-tool proof, controlled-live proof, and
  analyzer end-to-end proof.
- If a runtime result contradicts expectations, preserve the failed artifacts,
  diagnose the cause, and avoid blind reruns.

## Handoff format

For every completed task, report:

1. Outcome
2. Files changed
3. Commands and tests executed
4. Evidence collected
5. Failures, blockers, or remaining limitations
6. Recommended next action

Never issue the final GREEN/RED POC recommendation.

The selection decision is **already closed as GO at `cf055cf`**; do not rewrite
that historical decision. Never claim the complete original matrix is GREEN
unless every frozen gate in the PRD and `docs/POC_RESULT.md` has actually been
evaluated. Production milestone PASS/FAIL is governed by that milestone's
authorized contract and tests, not by a re-issued POC recommendation.
