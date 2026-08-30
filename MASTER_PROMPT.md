# SecureMailScope — Master AI Prompt

## Role and outcome

You are assisting the primary solo developer of **SecureMailScope**, SIH 2026 PS159. Apply product-level rigor inside an approximately eight-hour technical POC.

The objective is not to make the project look complete. It is to produce independently verifiable protocol/cryptographic evidence and an honest GREEN/RED recommendation.

## Current objective and status

- This document retains **historical POC planning and integrity rules**, which remain binding for the frozen POC records and relevant POC work.
- **Current work is production Chain-of-Proof development** on branch `feat/production-backend`.
- **Current implementation truth comes from `context/progress-tracker.md`** (with the production section of `context/architecture.md`), not from historical planning text.
- The selection **GREEN/RED decision has already closed as GO at `cf055cf`**. Do not rewrite that historical decision; do not re-issue a POC recommendation.

## Current starting status (historical)

This section is **historical** — it describes the state when the POC foundation was first prepared:

- The repository had not been created.
- No implementation or PCAP fixture existed.
- No technical gate had passed or failed.

It does **not** describe current status. The production-development mode section below, together with `context/progress-tracker.md`, defines current implementation status. The POC capability matrix and starting-status sections in this document are historical planning text. Never claim that a planned file or feature exists without checking.

## Context-loading rule

Always read:

1. `MASTER_PROMPT.md`
2. `context/project-overview.md`
3. `context/progress-tracker.md`

Then load only the documents required for the active task:

| Task | Additional required context |
|---|---|
| Official requirements or scope/acceptance | `docs/OFFICIAL_PS159.md`, `docs/PRD.md` |
| Architecture, protocol, TLS, X.509, evidence, data model | `context/architecture.md`, relevant `docs/SYSTEM_DESIGN.md` sections |
| Coding or review | `context/code-standards.md`, `context/rules.md`, relevant feature in `docs/FEATURE_BREAKDOWN.md` |
| Environment, CI, review tools | `docs/TOOLING.md` |
| HTML/dashboard work | `context/ui-context.md` |
| First full project audit or conflicting documents | Read all foundation documents |

Do not repeatedly load every document for a small task. If two documents conflict, stop and report the conflict; do not choose silently.

## Authority order

1. The developer's explicit current instruction.
2. The verbatim official PS159 requirements in `docs/OFFICIAL_PS159.md`.
3. Non-negotiable truth/safety rules in this master prompt.
4. Approved system design, code standards, and tooling decisions.
5. The active feature and current progress state.

If a new instruction would weaken a frozen gate or falsify evidence, identify the conflict and request an explicit decision before changing the contract.

## Product summary (historical POC plan)

The description below is **historical POC-planning text**. The selection POC closed after T01 (23/23) and E2/E3A viability evidence only; it did not prove the full planned capability list or pass all eleven gates. Current verified status is in `context/progress-tracker.md` and the production section.

SecureMailScope passively analyzes PCAP/PCAPNG files containing SMTP, IMAP, and POP3 traffic. The POC must prove content-based protocol identification, STARTTLS/STLS validation, TCP/email/TLS timeline reconstruction, TLS/cipher/key-establishment/Forward-Secrecy facts, observable X.509 extraction and validation, honest TLS 1.3 limitations, evidence-backed policy findings, a separate ML anomaly signal, canonical JSON, and minimal HTML.

The PRD translates the official statement into the requested POC without replacing it. The exact controlled matrix T01–T08, functional requirements, and binary gates G01–G11 are defined in the PRD and feature breakdown. All eleven gates must pass for GREEN.

The official problem statement historically mentions a final solution that includes PDF and an interactive dashboard. Under the **currently authorized production scope**, **PDF export is not part of that scope**; the optional PDF-related schema field in the Chain-of-Proof contract does not authorize implementation. An explicit developer decision is required before changing this rule. The interactive frontend remains a separate, frozen workstream.

## Frozen POC stack

- WSL2 Ubuntu/native Linux.
- Python 3.12 managed by `uv`; commit `pyproject.toml`, `.python-version`, and `uv.lock`.
- TShark 4.2+ for offline dissection and TCP/TLS reassembly.
- OpenSSL 3.x for controlled endpoint/certificate truth.
- tcpdump or dumpcap only for controlled fixture capture.
- Pydantic, Typer, cryptography, Jinja2, jsonschema, PyYAML safe loading, scikit-learn, and joblib.
- Ruff and pytest as mandatory local quality tools.
- pre-commit, GitHub Actions, CodeRabbit, and pip-audit only when the tooling record says they add value without threatening the timebox.

Do not replace the stack without demonstrating a blocker and obtaining developer approval.

## Frozen architecture (historical POC plan)

The pipeline below is **historical POC-planning text** describing the full planned analyzer. Not every stage (TLS/X.509 facts, policy, ML, canonical JSON, HTML) was proven by the closed selection POC; the verified analyzer scope is in `context/progress-tracker.md` and the production section.

```text
PCAP intake/provenance
  -> TShark discovery and TCP reassembly
  -> content-based protocol classification
  -> protocol-aware TShark pass
  -> email-session/upgrade state machine
  -> TLS and observable X.509 analysis
  -> normalized facts, evidence, and features
  -> deterministic policy engine
  -> separate ML anomaly engine
  -> canonical report model
  -> validated JSON
  -> minimal HTML rendered only from JSON
```

Use TShark reassembly; do not implement a TCP stack. Ports are hints only. HTML never performs analysis.

## Non-negotiable truth rules

1. Never present inference as a directly captured fact.
2. Every important fact retains capture hash, stream, frame(s), source field/bytes, raw value, normalized value, and observability.
3. Never guess missing values; use an explicit unknown/not-observable/incomplete state with a reason.
4. Ground truth comes from fixture configuration, endpoint/OpenSSL logs, certificate files, capture time, and hashes—never analyzer output.
5. Analyzer code must never write or update `fixtures/ground_truth.json`.
6. Passive TLS 1.3 without usable secrets reports the server certificate as `not_observable_encrypted_tls13`; never missing, invalid, expired, or trusted.
7. Never infer TLS 1.3 key exchange or Forward Secrecy from its cipher-suite name; use key-share/PSK evidence.
8. Certificate chain/time validation requires an explicit trust store and capture timestamp. Identity testing requires observed SNI/hostname evidence.
9. Deterministic policy risk and ML anomaly are separate outputs. The anomaly score is not a vulnerability or probability.
10. Expected test values may never be regenerated from current analyzer output.
11. Never expose credentials, email content, private keys, or real/sensitive packet data.

Required observability vocabulary:

```text
observed
derived_from_observed
not_observable_encrypted_tls13
not_present
not_applicable
capture_incomplete
unknown_insufficient_evidence
```

## POC prohibitions

Do not add authentication, a database, an API/server, an interactive dashboard, product live capture, PDF, SIEM, phishing/content detection, cloud deployment, Docker orchestration, a custom TCP stack/dissector, or production ML claims during the POC unless the developer explicitly changes scope after all mandatory gates are secure.

## Code and data rules

- Python 3.12 only for the POC; typed functions, `pathlib.Path`, explicit enums, and Pydantic boundary models.
- Small modules/functions with dependencies following the system design.
- Safe subprocess argument lists, `shell=False`, timeouts, bounded output, and typed stage errors.
- No mutable global analysis state or hardcoded fixture paths/ports/IPs/streams/frames/ciphers/certificates/expected results.
- Deterministic ordering, IDs, serialization, seeds, and explicit versions.
- Preserve raw and normalized values; never swallow broad exceptions.
- Ruff is the only formatter/linter unless an approved gap exists.
- Tests compare analyzer output with independent ground truth.
- Never commit private fixture keys, key logs, credentials, real/sensitive PCAPs, `.venv`, caches, or generated output.
- Controlled synthetic PCAPs may be committed only after confirming they contain no sensitive data. Treat access granted to repository-connected tools as access to those committed files.

## Work-unit protocol

1. Identify the active feature, dependencies, acceptance criteria, gates, and stop condition.
2. Confirm implementation is authorized by the current request.
3. Establish independent ground truth before trusting analyzer output.
4. Implement the smallest end-to-end slice and preserve unrelated work.
5. Run actual manual/automated verification required by that slice.
6. Report actual commands, exit results, evidence, limitations, and runtime—not predicted success.
7. Update `context/progress-tracker.md` only after a material, verified state change.
8. Stop rather than moving to polish when a P0 criterion is unresolved.

## Required implementation-response format

### Current checkpoint

- Active feature/gate and acceptance criteria.
- Relevant exclusions.

### Changes made

- Exact files and behaviour.

### Verification performed

- Exact commands and actual results.
- Independent truth/evidence compared.

### Evidence and limitations

- Hash/stream/frame/field references where applicable.
- Unknown/not-observable/incomplete states and what remains unproven.

### Blocker or next single step

- Concrete blocker, or one next action.

Never claim “done,” “working,” “correct,” or “passed” without supporting verification.

## Stop conditions

Stop and report when required fields/reassembly cannot be established, truth and capture/analyzer disagree, certificate validation lacks required inputs, TLS 1.3 visibility is ambiguous, a change would weaken a gate, permissions/secrets are missing, scope expansion threatens the POC, or repository state contradicts the documentation.

At completion, `docs/POC_RESULT.md` must record environment/versions, commit, commands, hashes, T01–T08 actual versus expected, G01–G11, representative evidence, two full-run runtimes, failures/deviations/blockers, and a decisive GREEN/RED.

## Active task

The developer supplies one active task. Do not invent or begin work from this placeholder.

## Production-development mode (post-selection, `feat/production-backend`)

The PS159 selection POC is **closed (GO) at `cf055cf`** and the repository is now in a **production-development phase** on branch `feat/production-backend`. The historical POC rules above are retained and remain binding; production work additionally follows the rules in this section.

### Authority and scope

- The frozen POC records are authoritative and must not be rewritten, reinterpreted, weakened, or extended: `docs/POC_RESULT.md`, `docs/PRD.md`, `docs/SYSTEM_DESIGN.md`, the frozen capture fixtures, and POC expected outputs.
- The active production contract is the **Chain of Proof** in `docs/CHAIN_OF_PROOF_SPECIFICATION.md` (schema `1.0.0`). Read it before any production chain work. Do not silently alter its technical content; report any conflict for an explicit decision.
- The existing analyzer remains stable. `src/securemailscope/chain` is the versioned domain contract. The **pure POC-result adapter** (Commit 2) is **completed at `616b97d`**: it maps verified analyzer output into the chain with no re-analysis. The next layer is **Commit 3**, deterministic SMTP transition facts derived from ordered, evidence-backed chain events (**UNVERIFIED**). API, frontend, policy, ML, and reports are later milestones.
- The frontend is **separate and frozen**; do not redesign it during backend milestones.
- **Policy risk and ML anomaly remain separate** outputs; never present their sum or average as an independently validated fact.

### Production discipline

- Do not claim policy, ML, API, frontend, live capture, decryption, phishing detection, blocking, authentication, geolocation, or SIEM support unless a verified implementation exists.
- **PDF export remains excluded** from the authorized production scope unless it is explicitly reauthorized by an explicit developer scope decision. The optional PDF schema field is not authorization or an implementation claim.
- Do not turn planning material into implemented-feature claims.
- Do not fabricate evidence. Never derive ground truth from the analyzer being evaluated, and never edit evidence JSON, manifests, logs, or reports to convert a failure into a pass.
- Use `PASS`, `FAIL`, `BLOCKED`, and `UNTESTED` precisely. Record only what actually ran.
- Never stage, commit, amend, rebase, push, or create a pull request unless explicitly requested.
- Update `context/progress-tracker.md` only after a material, verified state change, preserving the entire POC verification history.
- Plan/review/test/commit the smallest authorized slice against the frozen requirement and the Chain-of-Proof contract.

### Production verification

Run the required verification commands (see `AGENTS.md`) and record only real results. Production chain work must satisfy the graph invariants and definition of done in `docs/CHAIN_OF_PROOF_SPECIFICATION.md`.
