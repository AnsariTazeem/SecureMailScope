# SecureMailScope POC — Product Requirements Document

## 1. Document control

| Field | Value |
|---|---|
| Product | SecureMailScope |
| Problem statement | SIH 2026 PS159 |
| Document status | Approved for POC planning; implementation not started |
| Product phase | Approximately eight-hour technical kill test |
| Primary developer | One solo developer |
| Primary decision | GREEN or RED technical recommendation |
| Final required evidence | `docs/POC_RESULT.md` |
| Authoritative official statement | `docs/OFFICIAL_PS159.md` |

This PRD treats the POC as a serious product experiment: requirements, evidence, errors, outputs, and acceptance criteria are explicit. It does not turn the POC into a polished product or silently defer a mandatory technical gate.

## 2. Product summary

SecureMailScope is a passive network-forensics framework that accepts PCAP/PCAPNG files containing SMTP, IMAP, and POP3 communications and produces an evidence-backed assessment of the cryptographic posture of those sessions.

It identifies email protocols from traffic content, validates plaintext-to-TLS upgrades, reconstructs TCP/email/TLS timelines, extracts observable TLS and X.509 facts, identifies cryptographic weaknesses, separately calculates deterministic policy risk and ML anomaly signals, prioritizes findings, recommends mitigations, and exports canonical JSON plus minimal HTML.

The POC exists to determine whether this technical core can be built correctly and reused for the complete SIH solution. It is not intended to prove production scale, production ML accuracy, or a completed dashboard.

## 3. Problem and opportunity

Email systems may deploy TLS while still using obsolete versions, weak cipher suites, unsafe upgrade behaviour, non-forward-secret key establishment, expired certificates, incomplete chains, or weak algorithms. Packet-analysis tools expose protocol fields, but an analyst must still convert those fields into defensible security posture findings and priorities.

The product opportunity is a focused forensic layer that answers:

- Which captured sessions are SMTP, IMAP, or POP3?
- Did STARTTLS/STLS actually upgrade correctly?
- What cryptographic parameters were negotiated?
- Was Forward Secrecy achieved or unknowable?
- What certificate facts and validation results were observable?
- What is weak, why is it weak, and where is the packet evidence?
- Which sessions are behaviourally unusual without confusing anomaly with vulnerability?

## 4. Intended users and jobs

| User | Primary job | POC value |
|---|---|---|
| SOC analyst | Rapidly identify and prioritize weak email-transport sessions | One evidence-backed session summary instead of manual field correlation |
| Digital-forensics analyst | Preserve reproducible packet/session/cryptographic facts | PCAP hash, stream/frame references, raw/normalized values, limitations |
| Incident responder | Determine whether a suspicious email connection downgraded or failed secure upgrade | Explicit state-machine outcome and TLS timeline |
| Enterprise email administrator | Find configuration changes needed on mail infrastructure | Prioritized findings with standards-based mitigations |

The POC is operated by a technical user through a CLI. Ease of use means clear commands, deterministic output, helpful failure messages, and honest limitations—not a graphical dashboard.

## 5. Product principles

1. **Evidence before score.** Findings and scores must be traceable to captured or independently validated facts.
2. **Honesty before completeness.** Unobservable TLS 1.3 certificates and incomplete captures must never become fabricated facts.
3. **Protocol content before port.** Ports help discovery but never independently decide SMTP/IMAP/POP3.
4. **Ground truth before AI confidence.** The controlled PCAP and endpoint/OpenSSL truth decide correctness.
5. **Deterministic policy before anomaly.** Crypto-policy risk and ML anomaly are separate outputs with separate meanings.
6. **Reusable core before interface.** Packet, crypto, evidence, policy, ML, and reporting boundaries must remain reusable in a later API/dashboard.

## 6. Goals

### POC goals

- Prove automatic SMTP, IMAP, and POP3 identification on non-standard ports.
- Prove correct SMTP STARTTLS, IMAP STARTTLS, and POP3 STLS transitions.
- Prove TShark-backed TCP/email-session and observable TLS-handshake reconstruction.
- Prove exact extraction of TLS version, selected cipher, key establishment/group, and Forward Secrecy.
- Prove observable X.509 extraction and capture-time validation.
- Prove honest passive TLS 1.3 certificate invisibility without secrets.
- Prove evidence-backed cryptographic policy findings, priorities, and recommendations.
- Prove separation and repeatability of policy-risk and ML-anomaly scores.
- Produce schema-valid JSON and a minimal HTML representation of the same data.
- Record a reproducible GREEN/RED recommendation.

### Reuse goal

If GREEN and selected, the POC's core Python models and analysis pipeline must remain usable behind a future API, interactive dashboard, expanded reports, and broader PCAP coverage.

## 7. Non-goals for the POC

- Authentication, authorization, accounts, or multi-tenancy.
- An interactive or large dashboard.
- Product live capture or network monitoring.
- PDF output.
- SIEM/SOAR integration.
- Phishing, spam, malware, or email-content classification.
- Cloud deployment, database persistence, distributed jobs, or container orchestration.
- Real-world ML generalization or a probability-of-compromise claim.

These are POC boundaries only. The official final solution still requires PDF and an interactive dashboard if PS159 is selected.

## 8. Primary user workflow

1. User supplies an existing PCAP/PCAPNG path, explicit trust store, optional TLS key-log file, frozen ML model, and output directory.
2. SecureMailScope validates inputs and records input/tool provenance.
3. It discovers TCP streams and classifies email protocols from content/direction.
4. It validates STARTTLS/STLS transitions and builds a session timeline.
5. It reconstructs all observable TLS-handshake events.
6. It extracts/derives TLS and certificate facts with evidence and observability states.
7. It applies deterministic crypto-policy rules and a separate anomaly model.
8. It writes canonical `report.json`, validates it, and renders `report.html` from that JSON.
9. User can resolve every finding to a stream/frame/raw field or certificate artifact.

Planned CLI shape:

```text
securemailscope analyze INPUT.pcapng \
  --trust-store fixtures/pki/root-ca.pem \
  [--keylog-file fixtures/keylogs/session.keys] \
  --model models/isolation_forest.joblib \
  --out output/run-id
```

## 9. Functional requirements

### FR-100 Capture intake and provenance

- **FR-101:** Accept a readable `.pcap` or `.pcapng` path without requiring the user to name the protocol.
- **FR-102:** Calculate and record SHA-256, byte size, packet count, capture start/end, and analyzer/TShark/OpenSSL/model/rule/schema versions.
- **FR-103:** Reject missing, unreadable, unsupported, or malformed input with a typed error and non-zero exit code.
- **FR-104:** Never modify the input capture.

### FR-200 TCP and protocol discovery

- **FR-201:** Run TShark offline using two-pass analysis and reassembly-compatible settings.
- **FR-202:** Group traffic by `tcp.stream` and retain endpoints, direction, frame/timestamp order, FIN/RST, retransmission/gap/completeness indicators, and required reassembled bytes/fields.
- **FR-203:** Automatically classify SMTP, IMAP, POP3, or `unknown` using at least two direction-consistent grammar signatures.
- **FR-204:** Treat ports as weak hints only and pass the non-standard-port and misleading-port tests.

### FR-300 Email-session and upgrade reconstruction

- **FR-301:** Build an ordered pre-upgrade/session/TLS/close timeline per recognized email stream.
- **FR-302:** SMTP success requires client STARTTLS, server `220`, then ClientHello on the same stream before further plaintext SMTP.
- **FR-303:** IMAP success requires tagged STARTTLS, a matching tagged `OK`, then ClientHello on the same stream.
- **FR-304:** POP3 success requires STLS, server `+OK`, then ClientHello on the same stream.
- **FR-305:** Distinguish success, rejection, accepted-without-ClientHello, plaintext-after-acceptance, capture-incomplete, and not-attempted.
- **FR-306:** Correctly reconstruct a controlled STARTTLS command split across TCP segments.

### FR-400 TLS-handshake reconstruction

- **FR-401:** Record every observable handshake event in capture order with source frames and direction.
- **FR-402:** Report reconstruction level as `fully_parsed_with_secrets`, `passive_visible_reconstruction`, or `partial_capture`.
- **FR-403:** Extract TLS 1.3 negotiated version from ServerHello `supported_versions`, not its legacy-version value.
- **FR-404:** Extract the selected cipher suite from ServerHello.
- **FR-405:** Extract or derive the key-establishment mechanism and group using version-appropriate observed evidence.
- **FR-406:** Never claim encrypted Finished/application data was parsed without secrets.

### FR-500 Forward Secrecy

- **FR-501:** Report modern observed ECDHE/key-share cases as FS=`yes`.
- **FR-502:** Report controlled static-RSA/no-FS cases as FS=`no`.
- **FR-503:** Report insufficient or ambiguous key-establishment evidence as FS=`unknown`.
- **FR-504:** Never derive TLS 1.3 FS from its cipher-suite name alone.

### FR-600 X.509

- **FR-601:** When observable, extract each DER certificate and record fingerprint, subject, issuer, SAN, validity, public-key algorithm/length, signature algorithm, and chain position.
- **FR-602:** Validate the presented chain against an explicitly supplied trust store at capture time.
- **FR-603:** Record analysis-time expiration separately.
- **FR-604:** Validate identity only when observed SNI/hostname evidence exists; otherwise report `identity_not_testable_no_sni`.
- **FR-605:** Distinguish valid, expired, not-yet-valid, untrusted-root, incomplete-chain, signature-failure, and name-mismatch outcomes.
- **FR-606:** For passive TLS 1.3 without secrets, output exactly `not_observable_encrypted_tls13` and emit no certificate weakness finding.

### FR-700 Evidence and policy findings

- **FR-701:** Every normalized fact must retain a precise evidence reference.
- **FR-702:** Every deterministic finding must contain code, severity, evidence IDs, rule version, rationale, standards references, and mitigation.
- **FR-703:** Evidence IDs referenced by findings must resolve within the same report.
- **FR-704:** Detect the controlled deprecated-version, weak-algorithm/configuration, no-FS, certificate, and broken-upgrade cases.
- **FR-705:** Calculate transparent `policy_risk_score` from 0–100 and `posture_score` without using ML.

### FR-800 ML anomaly

- **FR-801:** Build a versioned feature vector from observed protocol/TLS/session/certificate-behaviour features.
- **FR-802:** Exclude policy scores and policy labels from model inputs.
- **FR-803:** Use IsolationForest with fixed `random_state=159`, frozen preprocessing, feature order, threshold, model hash, and training-corpus hashes.
- **FR-804:** Emit raw model output, `ml_anomaly_score` 0–100, threshold, anomaly flag, model hash, and input feature vector.
- **FR-805:** Describe anomaly score as a behavioural signal, not a vulnerability or probability.

### FR-900 Reporting

- **FR-901:** Produce canonical `report.json` and validate it against a versioned JSON Schema.
- **FR-902:** Produce minimal static `report.html` exclusively from the canonical JSON.
- **FR-903:** JSON and HTML must contain the same session IDs, cryptographic facts, observability, findings, recommendations, and scores.
- **FR-904:** Include limitations, unknowns, incomplete captures, and tool/runtime provenance.
- **FR-905:** Never include credentials, email body, or private message content.

### FR-1000 POC decision report

- **FR-1001:** Run T01–T08 twice against pinned ground truth.
- **FR-1002:** Write `docs/POC_RESULT.md` containing passed tests, failed tests, commands, hashes, evidence, runtime, blockers, deviations, and GREEN/RED.
- **FR-1003:** A mandatory failed or unfinished gate forces RED; do not average failures into a partial pass.

## 10. Required controlled fixtures

| ID | Scenario | Required result |
|---|---|---|
| T01 | SMTP non-standard port, split STARTTLS, TLS 1.2 ECDHE, valid chain | Full SMTP/transition/TLS/FS/certificate proof |
| T02 | IMAP non-standard port, tagged STARTTLS, TLS 1.2 ECDHE | Correct tagged transition and crypto proof |
| T03 | POP3 non-standard port, STLS, TLS 1.2 ECDHE | Correct STLS transition and crypto proof |
| T04 | SMTP STARTTLS, TLS 1.3, no key log | Correct visible facts and certificate invisibility state |
| T05 | Deprecated/static-RSA/no-FS plus an expired and deliberately weak observable certificate | Correct version/cipher/no-FS, expiration, public-key, signature-algorithm, and prioritized certificate findings |
| T06 | Broken upgrade plus truncated capture | No false success/completeness or invented values |
| T07 | Non-mail TLS on misleading mail-like port | `unknown`; no false mail/upgrade classification |
| T08 | 12 train-normal, 2 held-out normal, 2 controlled anomalous sessions | Both anomalies rank above both held-out normals, repeatably |

## 11. Non-functional requirements

### Correctness and reproducibility

- Zero invented negotiated TLS/certificate facts in the controlled matrix.
- Ground truth remains independent of analyzer output.
- Identical input/tool/model/rule versions produce semantically identical canonical output aside from explicit runtime metadata.
- The repository records dependency lock, tool versions, PCAP/certificate/log/model hashes, and exact commands.

### Reliability

- One bad stream must not erase valid results for other streams; report bounded per-stream errors when safe.
- Tool subprocesses must have timeouts and bounded diagnostic output.
- Malformed input must not cause an uncontrolled traceback in normal CLI use.

### Performance

- Record total and per-stage runtime.
- Target under 30 seconds per small controlled fixture on the developer machine, excluding fixture generation; this is a target, not a gate until measured.
- Avoid loading unnecessary full packet payloads into Python memory.

### Privacy and security

- Offline PCAP processing only.
- Never send real/sensitive capture bytes, private keys, key logs, credentials, or sensitive analysis results to third-party AI/review services. A repository-connected service may access only a committed controlled synthetic PCAP that has first been confirmed non-sensitive.
- Controlled private keys never enter reports or Git history.
- No credentials or email body in output/logs.
- Use safe subprocess invocation and explicit paths.

### Portability

- Supported POC environment: WSL2 Ubuntu 24.04 or native Linux.
- Python 3.12 with a committed `uv.lock`.
- TShark 4.2+ and OpenSSL 3.x recorded at runtime.

### Maintainability

- Typed component contracts, small modules, versioned policy/schema/features, lint/format/test gates, and a canonical JSON model.
- Protocol, crypto, policy, ML, and presentation code remain independently testable.

## 12. Evidence object minimum

```json
{
  "evidence_id": "ev-...",
  "pcap_sha256": "...",
  "tcp_stream": 3,
  "frame_numbers": [41],
  "direction": "server_to_client",
  "source": "tshark_field",
  "field": "tls.handshake.extensions.supported_version",
  "raw_value": "0x0304",
  "normalized_value": "TLS 1.3",
  "observability": "observed"
}
```

## 13. Binary acceptance gates

- **G01:** Protocol identification and negative control.
- **G02:** Upgrade handling including broken/rejected cases.
- **G03:** TCP/email reconstruction including segmentation and truncation.
- **G04:** Observable TLS-handshake reconstruction/order.
- **G05:** Correct negotiated version, cipher, key establishment/group.
- **G06:** Correct FS.
- **G07:** Observable X.509 extraction/validation.
- **G08:** Honest TLS 1.3 certificate invisibility.
- **G09:** Resolvable evidence-backed findings/recommendations.
- **G10:** Separate deterministic policy and repeatable ML anomaly scores.
- **G11:** Valid/matching JSON and HTML, bounded errors, runtime recorded.

GREEN requires all eleven gates. RED means the core is not sufficiently proven under current constraints; it is useful decision evidence, not a reason to hide failures.

## 14. Risks and mitigations

| Risk | Impact | Mitigation/kill signal |
|---|---|---|
| TShark does not expose required field/reassembly behaviour | Core evidence chain blocked | Run T01 manual spike first; stop at 90 minutes if not resolved |
| Fixture truth becomes circular | Invalid proof | Separate generator/config/logs/hashes; analyzer has no manifest write path |
| TLS 1.3 visibility is misunderstood | False certificate finding | Mandatory explicit observability state and negative assertion |
| Protocol detected by port | Demo passes only hardcoded fixture | Non-standard ports plus misleading-port negative control |
| TCP truncation becomes fabricated completeness | Unreliable forensic output | Preserve gaps/completeness and test T06 |
| ML is overclaimed | Credibility loss | Separate score, fixed controlled corpus, explicit limitation |
| Too many tools consume the timebox | POC unfinished | Use mandatory tool tier only; optional review once after core checkpoint |
| AI-generated code appears plausible but is wrong | Incorrect cryptographic claims | Manual TShark/OpenSSL truth before automated analyzer assertions |
| Private fixture keys enter Git/AI services | Security/privacy issue | `.gitignore`, manual staged-file review, optional pre-commit secret checks, disposable permission-restricted keys, no key upload |

## 15. Dependencies and assumptions

- Developer has WSL2/native Linux with permission to capture controlled loopback traffic.
- TShark/OpenSSL versions support the required observable fields and controlled TLS configuration.
- All PCAPs are locally generated, small, legal, non-sensitive, and hash-pinned.
- Tool installation time is recorded separately; core feasibility is judged after a ready environment.
- AI tools accelerate implementation/review but never determine ground truth.

## 16. Roadmap after a GREEN selection

Only after PS159 is selected:

- Broaden real-world PCAP and malformed-input coverage.
- Harden rules, certificate edge cases, model evaluation, performance, and packaging.
- Add API and job-management boundaries.
- Build the official interactive dashboard.
- Add comprehensive HTML and PDF reports.
- Improve explainable recommendations and operational workflow.
- Evaluate and implement the official AI/ML-assisted cryptographic risk-classification, posture-scoring, and threat-prioritization requirements on a defensible dataset while retaining deterministic evidence-backed policy findings.
- Add deployment, observability, accessibility, and end-to-end demo hardening.

Authentication and SIEM/phishing functionality remain unnecessary unless later official/stakeholder research establishes them as required.
