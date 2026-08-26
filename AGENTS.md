# SecureMailScope — Repository Agent Instructions

## Purpose

SecureMailScope is the strict technical proof-of-concept for SIH 2026 PS159:
AI-assisted cryptographic security posture assessment of email communications.

The POC passively analyzes controlled PCAP/PCAPNG files containing SMTP, IMAP,
and POP3 sessions. It reconstructs observable protocol and TLS evidence, assesses
cryptographic posture, and produces evidence-backed JSON and minimal HTML.

This is a six-day technical kill test, not a polished product. Correctness,
reproducibility, evidence integrity, and honest limitations take precedence over
feature breadth or presentation polish.

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
document, or generated artifact. Current verified status is recorded only in
`context/progress-tracker.md` and `docs/POC_RESULT.md`.

## Canonical repository documents

- `docs/OFFICIAL_PS159.md`: verbatim official problem statement
- `docs/PRD.md`: frozen POC requirements and acceptance gates
- `docs/SYSTEM_DESIGN.md`: system boundaries, components, and data flow
- `docs/FEATURE_BREAKDOWN.md`: implementation order and checkpoints
- `docs/TOOLING.md`: approved tools and dependency rationale
- `context/project-overview.md`: concise project context
- `context/architecture.md`: frozen architecture and technical decisions
- `context/rules.md`: detailed AI workflow and code rules
- `context/progress-tracker.md`: current verified implementation status
- `context/ui-context.md`: minimal report/UI rules when relevant
- `docs/POC_RESULT.md`: evidence record and final GREEN/RED recommendation

When documents appear inconsistent, do not silently reinterpret them. Stop and
report the exact conflict. The official statement defines the original problem;
the PRD defines the strict POC subset and acceptance gates; the progress tracker
and POC result define what has actually been verified.

## Mandatory POC proof

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

## Explicit POC exclusions

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
  POC requirement and documented justification.
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

Never issue the final GREEN/RED POC recommendation until all frozen decision
requirements in the PRD and `docs/POC_RESULT.md` have been evaluated.
