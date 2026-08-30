# SecureMailScope — Proposed POC Architecture

**Status:** Historical POC-planning text (not implemented at time of writing). This section was the POC plan; it is not current implementation status. For the active production phase and current verified status, read the production architecture section below and `context/progress-tracker.md`.
**Goal:** Use the smallest reliable architecture that proves packet/session reconstruction and cryptographic truth within one focused day, while remaining reusable if PS159 is selected.

## Selected technology stack

| Need | Selected tool | Reason |
|---|---|---|
| Development environment | WSL2 Ubuntu or native Linux | Reliable packet/capture tooling and repeatable commands |
| Core language | Python 3.12 | Strong packet orchestration, cryptography, reporting, testing, and ML ecosystem |
| Dependency/environment manager | `uv` | Fast isolated environment plus committed exact `uv.lock` for reproducibility |
| Packet dissection/reassembly | TShark 4.2+ | Mature Wireshark dissectors and TCP/TLS reassembly; avoids writing a TCP stack |
| Controlled fixture capture | tcpdump or dumpcap | Used only to create local test PCAPs, not as product live capture |
| Independent TLS/certificate truth | OpenSSL 3.x | Endpoint configuration, negotiation logs, fingerprints, and certificate verification |
| X.509 parsing | `cryptography` | Structured certificate fields and cryptographic primitives |
| Typed report models | Pydantic | Strong validation and JSON Schema generation |
| CLI | Typer | Small, readable command interface |
| HTML | Jinja2 | Minimal static rendering from canonical JSON |
| ML proof | scikit-learn IsolationForest + joblib | Repeatable unsupervised anomaly pipeline with a fixed seed |
| Tests and linting | pytest + Ruff | Fast correctness and quality feedback |

Python is selected for the forensic core even though the primary developer is more familiar with Node/React. If PS159 wins, a later FastAPI backend and Next.js/React dashboard can consume the same Python analysis models.

## Deliberately not selected for the POC

- No custom TCP reassembly implementation.
- No PyShark dependency layer unless TShark subprocess output proves unmanageable.
- No Express/Node forensic backend.
- No React/Next.js UI yet.
- No Docker requirement.
- No database.
- No Zeek deployment.
- No public/random PCAP as the source of ground truth.

## Processing pipeline

```text
PCAP/PCAPNG input
  -> intake and SHA-256 provenance
  -> TShark discovery and TCP reassembly
  -> content-based SMTP/IMAP/POP3 classification
  -> protocol-aware TShark pass
  -> email upgrade/session state machine
  -> TLS and observable X.509 analysis
  -> normalized facts, evidence, and ML features
  -> deterministic policy findings and score
  -> separate ML anomaly score
  -> canonical report.json
  -> minimal report.html rendered from that JSON
```

## Component boundaries

| Planned component | Responsibility | Forbidden responsibility |
|---|---|---|
| `cli.py` | Arguments, orchestration call, exit codes | Packet parsing and policy logic |
| `pipeline.py` | Sequence analysis stages, collect timings, and isolate per-stream failures | Implementing protocol, cryptographic, policy, or ML rules |
| `tooling.py` / `intake.py` | Tool/version checks, input validation, hashes, orchestration inputs | Protocol or policy decisions |
| `tshark.py` | Safe TShark execution and raw observation normalization | Cryptographic interpretation |
| `protocols.py` / `sessions.py` | Content classification and protocol upgrade/session state machines | Port-only identification or TLS guessing |
| `crypto.py` / `certificates.py` | TLS, key establishment, FS, X.509 facts and validation | Treating TLS 1.3 cipher names as key exchange |
| `evidence.py` | Stable evidence creation and reference-integrity checks | Creating facts without observable provenance |
| `models.py` | Typed enums, evidence, sessions, findings, report | I/O and scoring |
| `features.py` / `anomaly.py` | Versioned ML feature construction and separate anomaly inference | Reading policy scores/labels as features |
| `policy.py` | Deterministic findings, priority, mitigation, and policy score | Modifying ML output or hiding unknowns |
| `reporting.py` | JSON serialization and HTML rendering | Recomputing forensic facts |
| `generate_fixtures.py` | Controlled endpoints, capture, logs, PKI, manifest | Reading analyzer output to establish truth |

## Protocol identification

Ports are only weak hints. A positive classification requires at least two independent, direction-consistent protocol signatures:

- SMTP: server `220` banner plus commands/replies such as `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `STARTTLS`, and `250`.
- IMAP: server `* OK`/capability response plus tagged commands/replies such as `A001 CAPABILITY`, `A002 STARTTLS`, and matching tagged `OK`.
- POP3: server `+OK`/`-ERR` plus commands such as `CAPA`, `USER`, `PASS`, `STAT`, and `STLS`.

If evidence is insufficient or contradictory, classify the stream as `unknown`.

## Upgrade state machines

- SMTP success: client `STARTTLS` -> server `220` -> TLS ClientHello on the same stream before another plaintext SMTP command.
- IMAP success: client `<tag> STARTTLS` -> matching server `<tag> OK` -> TLS ClientHello on the same stream.
- POP3 success: client `STLS` -> server `+OK` -> TLS ClientHello on the same stream.

Rejection, accepted-but-no-ClientHello, plaintext-after-acceptance, and truncated capture are separate outcomes and must not be reported as successful encryption.

## TLS and certificate handling

- Run TShark offline with two-pass analysis and TCP/TLS reassembly.
- Preserve observable handshake order and source frames.
- For TLS 1.3, take the negotiated version from ServerHello `supported_versions`, never the legacy-version value.
- Take the selected cipher suite from ServerHello.
- For TLS 1.2 and below, derive key exchange from the selected suite and confirm using handshake evidence when present.
- For TLS 1.3, assess key establishment from `key_share`, selected PSK, and PSK exchange mode.
- Extract DER certificates only when observable.
- Validate chain/time/identity only with an explicit trust store, capture timestamp, and observed SNI where identity testing is possible.

## Required observability states

- `observed`
- `derived_from_observed`
- `not_observable_encrypted_tls13`
- `not_present`
- `not_applicable`
- `capture_incomplete`
- `unknown_insufficient_evidence`

Handshake reconstruction levels:

- `fully_parsed_with_secrets`
- `passive_visible_reconstruction`
- `partial_capture`

## Evidence contract

Each evidence item must include:

- stable evidence ID;
- PCAP SHA-256;
- TCP stream;
- frame number(s);
- direction;
- source type and TShark field/byte reference;
- raw value;
- normalized value;
- observability state.

Each deterministic finding must reference existing evidence IDs and include code, severity, rule version, rationale, standards reference, and recommendation.

## Separate scoring paths

- `policy_risk_score`: deterministic 0–100 risk from observed policy violations.
- `posture_score`: transparent inverse of policy risk for the POC.
- `ml_anomaly_score`: separate 0–100 scaled IsolationForest output; not a probability.

Policy scores and labels must not be ML input features. Record model hash, feature order, preprocessing version, fixed random seed, threshold, and training-corpus hashes.

## Controlled PCAP matrix

| ID | Fixture | Required proof |
|---|---|---|
| T01 | SMTP, non-standard port, split STARTTLS, TLS 1.2 ECDHE, valid chain | Classification, TCP reassembly, accepted transition, TLS facts, FS=`yes`, certificate extraction/validation |
| T02 | IMAP, non-standard port, TLS 1.2 ECDHE, valid chain | IMAP classification, matching tagged STARTTLS response, TLS/session/certificate facts |
| T03 | POP3, non-standard port, TLS 1.2 ECDHE, valid chain | POP3 classification, STLS transition, TLS/session/certificate facts |
| T04 | SMTP STARTTLS, TLS 1.3, no key log | Correct version/cipher/key share/FS and certificate=`not_observable_encrypted_tls13` |
| T05 | Deprecated TLS/static RSA/no-FS plus an expired and deliberately weak observable certificate | Correct version/cipher/no-FS, expiration, public-key, signature-algorithm, and certificate findings with evidence |
| T06 | Broken upgrade and truncated capture | No false success; correct incomplete/unknown states |
| T07 | Non-mail TLS on a misleading mail-like port | Remains `unknown`; no false mail/STARTTLS result |
| T08 | 12 controlled normal training sessions, 2 held-out normals, 2 anomalies | Both anomalies score above both held-out normals with repeatable fixed-seed output |

## Binary POC gates

- G01: SMTP, IMAP, POP3 content identification and T07 negative control.
- G02: Correct STARTTLS/STLS validation including broken/rejected cases.
- G03: TCP/email timeline reconstruction including split and truncated data.
- G04: Observable TLS-handshake reconstruction and order.
- G05: Correct version, cipher, key-establishment mechanism/group.
- G06: Correct Forward Secrecy assessment.
- G07: Observable X.509 facts and validation match independent truth.
- G08: Honest secretless TLS 1.3 certificate handling.
- G09: Every deterministic finding has resolvable evidence and mitigation.
- G10: Policy and ML scores remain separate and ML proof is repeatable.
- G11: Valid JSON, matching minimal HTML, runtime recorded, no unhandled failure.

One failed or unfinished gate produces a RED POC recommendation.

## Planned repository structure

```text
SecureMailScope/
  .gitignore
  .python-version
  MASTER_PROMPT.md
  README.md
  context/
    project-overview.md
    architecture.md
    code-standards.md
    rules.md
    ui-context.md
    progress-tracker.md
  docs/
    OFFICIAL_PS159.md
    PRD.md
    SYSTEM_DESIGN.md
    FEATURE_BREAKDOWN.md
    TOOLING.md
    POC_RESULT.md              # generated during final verification
  src/securemailscope/
    __init__.py
    cli.py
    pipeline.py
    models.py
    errors.py
    tooling.py
    intake.py
    tshark.py
    protocols.py
    sessions.py
    crypto.py
    certificates.py
    evidence.py
    features.py
    policy.py
    anomaly.py
    reporting.py
  scripts/
    generate_fixtures.py
    train_anomaly_model.py
  fixtures/
    ground_truth.json
    pcaps/
    endpoint_logs/
    pki/
    keylogs/
    evidence/
  policy/rules.yml
  schemas/report.schema.json
  templates/report.html.j2
  models/
  tests/
    conftest.py
    test_protocols.py
    test_sessions.py
    test_crypto.py
    test_policy.py
    test_anomaly.py
    test_pcap_matrix.py
    test_reporting.py
  pyproject.toml
  uv.lock
```

This is the canonical POC layout, not evidence that the files or features already exist. Do not add alternate orchestration or combined-scoring modules; orchestration belongs in `pipeline.py`, the CLI remains thin, and policy/ML remain separate files.

# Production architecture (post-selection, `feat/production-backend`)

**Status:** Active production development building on the frozen POC core. This section documents the production backend phase; it does not rewrite the frozen POC plan above.

## Phase boundaries

- The PS159 selection POC is closed (GO) at `cf055cf`. The POC plan above is historical POC-planning text; the production section and `context/progress-tracker.md` define current status.
- The **existing analyzer core** (verified by the closed POC) remains stable and covers:
  - intake/provenance;
  - safe bounded TShark execution;
  - native TCP reassembly;
  - conservative content-based SMTP classification;
  - SMTP STARTTLS transition analysis;
  - ordered TLS handshake-type observations;
  - typed results/errors.
- The active production work introduces a **versioned domain contract** for the Chain of Proof, defined in `docs/CHAIN_OF_PROOF_SPECIFICATION.md` (schema `1.0.0`).
- The **pure POC-result adapter** (Commit 2, `feat: map verified smtp analysis into evidence chain`) is **completed and verified at `616b97d`**: it maps verified analyzer output into the chain without losing evidence and performs no packet re-analysis. **Commit 3** (`feat: derive smtp transition facts from ordered evidence`) is **completed and verified at `2c1454f`**: deterministic derivation of SMTP transition facts from ordered, evidence-backed chain events.
- API, policy, ML, and reports are **later milestones**, not current scope. None is claimed as implemented or authorized by this document alone.

## Analyzer boundary (verified scope)

The current `AnalyzeResult` exposes: provenance, tool records, streams, classifications, SMTP transitions, and warnings. It does **not** expose a negotiated TLS version, cipher suite, key-exchange result, Forward Secrecy, or certificate contents.

- A TLS handshake-message observation (the ordered `tls_handshake_types` per stream) proves **message presence only**; it is not a TLS/cipher/key-exchange/FS/certificate fact.
- The Commit 2 adapter does **not** import manual-verifier or ground-truth values into the chain. It maps only verified observable POC results and invents no evidence.

## Adapter boundary (verified at `616b97d`)

The Commit 2 pure POC-result adapter (`src/securemailscope/chain/poc_adapter.py`) is completed and verified. Its verified boundary is:

- **input:** the existing typed `AnalyzeResult`;
- **output:** a `ChainOfProof` object valid under schema `1.0.0` and the chain graph invariants;
- the transformation is **pure** and performs no packet re-analysis;
- it maps only the data already exposed by the current observable POC analyzer;
- it does **not** import manual-verifier or ground-truth values;
- it does **not** infer negotiated cryptographic properties (TLS version, cipher suite, key exchange, Forward Secrecy, or certificate contents);
- it does **not** perform policy or ML evaluation.

## Commit 3 boundary (verified at `2c1454f`)

The Commit 3 deterministic fact derivation (`src/securemailscope/chain/smtp_facts.py`) is completed and verified. Its verified boundary is:

- **input:** a validated `ChainOfProof` object with ordered, evidence-backed protocol events;
- **output:** the same chain with `DerivedFact` nodes added for:
  - `starttls_advertised` (true when at least one observed `CAPABILITY_ADVERTISED` event exists);
  - `plaintext_commands_after_offer` (count of observed `PLAINTEXT_COMMAND_AFTER_TLS_OFFER` events strictly after an advertisement);
  - `tls_upgrade_completed` (true/false/incomplete_capture/unknown_insufficient_evidence by ordered scan of request, accept/reject, handshake-finished, and post-offer plaintext events).
- the derivation is **pure**, deterministic, and idempotent (re-running replaces owned facts byte-for-byte);
- it performs **no packet re-analysis** and touches no later output collections (`rule_evaluations`, `findings`, `policy_risk`, `anomaly_results`, `recommendations`, `artifacts`);
- facts remain bounded by observable evidence and preserve `UNKNOWN/INSUFFICIENT` states when evidence is incomplete;
- policy risk and ML anomaly remain separate and are not produced here.

## Layering (production)

```text
existing POC analyzer core (stable, verified scope above)
  -> src/securemailscope/chain  : versioned Chain-of-Proof domain contract (Commit 1, verified at 57fe930)
  -> pure POC-result adapter    : maps verified analyzer output into the chain (Commit 2, verified at 616b97d)
  -> deterministic transition facts from ordered evidence (Commit 3, verified at 2c1454f)
  -> deterministic policy findings/risk/recommendations (Commit 4, next, UNVERIFIED)
  -> later milestones           : presentation/API/artifact boundary, IMAP/POP3, ML anomaly, reports
```

## Production sequence

The Chain-of-Proof contract in `docs/CHAIN_OF_PROOF_SPECIFICATION.md` defines an authorized implementation order. Current verified state is recorded in `context/progress-tracker.md`:

- **Commit 1 — contract** (completed at `57fe930`): versioned Chain-of-Proof domain contract.
- **Commit 2 — existing POC adapter** (completed and verified at `616b97d`): map the verified SMTP analysis into the chain.
- **Commit 3 — deterministic event/state/fact derivation** (completed and verified at `2c1454f`): derive SMTP transition facts from ordered, evidence-backed chain events.
- **Commit 4 — policy findings/risk/recommendations (next, UNVERIFIED)**.
- **Commit 5 — presentation/API/artifact boundary, subject to explicit task and product-scope authorization**.
- **IMAP/POP3 expansion and ML** occur only after the vertical slice.

Commits 3–5, IMAP/POP3, and ML are listed as the contract's declared order, not as implemented or already-authorized work. Each remains its own milestone requiring the plan/review/test/commit discipline in `AGENTS.md`.

## Component placement

- `src/securemailscope/chain` holds the **versioned domain contract**: enums, Pydantic models, stable ID helpers, JSON Schema, invariant tests, and example chain fixtures.
- The adapter layer (Commit 2, verified at `616b97d`) is **pure**: it transforms verified POC results into chain objects, performs no re-analysis of the capture, and invents no evidence.
- Policy, ML anomaly, API, frontend, and report rendering remain separate later layers and are not folded into the chain contract or the adapter.

## Invariants carried into production

- Policy risk and ML anomaly remain **separate** outputs; never present their sum or average as an independently validated fact.
- TLS 1.3 certificate invisibility in secretless passive captures stays `not_observable`/`session_secrets_required`/`not_observable_encrypted_tls13`; never fabricated.
- Ports are hints only; classification requires direction-consistent content evidence.
- The frontend renders canonical state and never derives protocol-security conclusions independently; the frontend is separate and frozen.
