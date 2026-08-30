# SecureMailScope — Repository Agent Instructions

## Purpose

SecureMailScope is **currently in production-backend development** on branch
`feat/production-backend`, building on a closed selection POC for SIH 2026
PS159: AI-assisted cryptographic security posture assessment of email
communications.

The selection POC was a **technical viability/kill test** and **closed as GO at
`cf055cf`**. Its verified analyzer scope is limited to: generic capture
intake/provenance, safe bounded TShark, native TCP reassembly, conservative
content-based SMTP classification, SMTP STARTTLS transition analysis, typed
models/errors, the T01 manual verification PASS (23/23), and the E2/E3A
analyzer-path checkpoint PASS.

IMAP/POP3 and the remaining cryptographic/report capabilities describe
**target or historical planned scope**, not current implemented scope. They are
not claimed as implemented.

**Chain Commit 1** (`feat: add chain-of-proof domain contract`) is complete at
`57fe930`; **Chain Commit 2** (`feat: map verified smtp analysis into evidence
chain`), the pure POC-result adapter, is **completed and verified at `616b97d`**.
**Commit 3** (deterministic derivation of SMTP transition facts from ordered,
evidence-backed Chain events) is next and **UNVERIFIED**.

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

The repository contains a **frozen POC history** and an **active production
backend** on branch `feat/production-backend`:

- The PS159 selection POC is **closed** and frozen at `cf055cf`. Do not rewrite,
  reinterpret, weaken, or extend the frozen POC records: `docs/POC_RESULT.md`,
  `docs/PRD.md`, `docs/SYSTEM_DESIGN.md`, the frozen capture fixtures, and the
  POC expected outputs.
- Production development builds on the verified POC core. The production target
  phase is governed by the approved Chain-of-Proof contract in
  `docs/CHAIN_OF_PROOF_SPECIFICATION.md` (schema `1.0.0`) and by
  `context/architecture.md` (production section).
- The active production branch is `feat/production-backend`. The frontend is a
  separate, **frozen** workstream; do not redesign or extend it during backend
  milestones.
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
- **PDF export remains excluded** unless it is explicitly reauthorized by an
  explicit developer scope decision.

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
7. The frontend is frozen; do not redesign it as part of a backend change.

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
