# SecureMailScope — Proposed POC Architecture

**Status:** Frozen for the POC but not implemented.  
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
