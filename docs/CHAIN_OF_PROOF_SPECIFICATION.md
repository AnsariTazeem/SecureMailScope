# SecureMailScope Chain-of-Proof Engine Specification

**Team:** Team Apex  
**Problem statement:** PS159  
**Status:** Production contract proposal for freeze  
**Schema version:** `1.0.0`  
**Planning date:** 27 August 2026

## 1. Purpose

The Chain-of-Proof Engine converts passive capture evidence into a reproducible and explainable security finding without losing provenance.

Canonical chain:

```text
capture provenance
  → reconstructed session
  → ordered protocol event
  → cryptographic observation
  → derived fact
  → policy-rule evaluation
  → finding
  → remediation
  → report artifact
```

The engine must answer:

1. What did the capture directly show?
2. Which session and packets contain that evidence?
3. What was derived from the evidence?
4. Which versioned policy evaluated those facts?
5. Why did the system create the finding and severity?
6. What information was unavailable or incomplete?
7. What action is recommended?
8. Can the result be reproduced and checked later?

## 2. Core architectural decision

The Chain of Proof is a typed directed acyclic evidence graph serialized as ordinary JSON. A graph database is not required for the internal submission.

### Canonical layers

| Layer | Mutability | Examples |
|---|---|---|
| Provenance | Immutable for an analysis | capture hash, size, packet count, capture window |
| Observation | Immutable extracted evidence | packet field, command, timestamp, TLS handshake type |
| Event | Deterministic ordering of observations | STARTTLS advertised, request accepted, ServerHello observed |
| Fact | Deterministically derived | plaintext continued after TLS offer, PFS supported |
| Rule evaluation | Version-dependent | rule matched/not matched, evaluated inputs |
| Finding | Version-dependent output | weak TLS, failed upgrade, expired certificate |
| ML result | Model-dependent output | anomaly score, unusual feature indicators |
| Recommendation | Rule/profile-dependent | require TLS, replace certificate, disable TLS version |
| Artifact | Regenerable presentation | JSON, HTML, PDF, evidence manifest |

Changing a policy pack or ML model must never change the original observed evidence. Re-evaluation creates new rule/model outputs linked to the same observations and facts.

## 3. Non-negotiable invariants

1. Every material finding must link to at least one observed or derived fact.
2. Every observed fact must link to capture provenance and packet/time evidence.
3. Every derived fact must list all source observations/facts and a derivation identifier/version.
4. Every policy finding must record rule ID, rule version, evaluated inputs, and result.
5. `not_observable` and `incomplete_capture` are valid results, not missing data to be guessed.
6. Policy risk and ML anomaly are independent outputs.
7. The ML model cannot overwrite protocol state, TLS facts, certificate facts, or policy findings.
8. A port number may support classification but cannot be the only proof of SMTP, IMAP, or POP3.
9. Protocol transition decisions must use ordered, reconstructed events.
10. TLS negotiated version must come from the correct handshake semantics, not blindly from a legacy record-version field.
11. Certificate expiry is evaluated at capture time, not merely at analysis time.
12. TLS 1.3 certificate details without authorized session secrets must not be fabricated.
13. Report totals must be computed from canonical findings, not manually duplicated.
14. Raw packet-derived strings must be escaped/redacted before UI or report rendering.
15. Same capture + analyzer version + rule pack + model + configuration must produce equivalent canonical results.

## 4. Graph node types

### 4.1 AnalysisManifest

Identifies a reproducible analysis execution.

Required fields:

```text
analysis_id
chain_schema_version
analysis_status
created_at
started_at
completed_at
analyzer_version
tshark_version
rule_pack_id
rule_pack_version
model_id
model_version
configuration_digest
limitations[]
```

### 4.2 CaptureProvenance

Required fields:

```text
capture_id
original_filename_sanitized
format
size_bytes
sha256
packet_count
captured_at_start
captured_at_end
link_layer_types[]
snaplen
truncated_packet_count
capture_warnings[]
ingestion_tool_versions
```

The original file is not modified. Sanitized display names must be separated from storage paths.

### 4.3 Session

Required fields:

```text
session_id
stable_session_key
capture_id
tcp_stream_id
source_endpoint
destination_endpoint
first_frame
last_frame
started_at
ended_at
packet_count
byte_count
protocol
protocol_confidence
classification_evidence_ids[]
capture_completeness
limitations[]
```

`stable_session_key` should be derived from capture SHA-256, transport stream identity, and analyzer schema version. It must not depend on a random database ID.

### 4.4 EvidenceReference

An EvidenceReference points back to directly observable capture evidence.

Required fields:

```text
evidence_id
capture_id
capture_sha256
session_id
frame_numbers[]
timestamp_start
timestamp_end
direction
source_kind
source_field
normalized_value
safe_excerpt
display_filter
observability
redaction
extractor_version
```

Allowed `source_kind` examples:

- `capinfos`
- `tshark_field`
- `tshark_follow_stream`
- `tshark_expert`
- `cryptography_library`
- `derived_state_machine`

`safe_excerpt` is optional and must not expose credentials or unnecessary message content. Packet number plus decoded field is normally sufficient.

### 4.5 ProtocolEvent

Represents an ordered protocol or TLS transition.

Required fields:

```text
event_id
session_id
sequence_index
event_type
protocol
state_before
state_after
timestamp
direction
evidence_ids[]
event_status
observability
limitations[]
```

Representative event types:

- `tcp_connected`
- `server_greeting`
- `capability_request`
- `capability_advertised`
- `tls_upgrade_requested`
- `tls_upgrade_accepted`
- `tls_upgrade_rejected`
- `client_hello`
- `server_hello`
- `certificate_message`
- `key_exchange_observed`
- `handshake_finished`
- `encrypted_application_data`
- `plaintext_command_after_tls_offer`
- `session_closed`
- `capture_boundary_reached`

### 4.6 CryptoObservation

Stores observable TLS/X.509 facts without policy judgment.

Required fields:

```text
observation_id
session_id
kind
value
normalized_value
observability
evidence_ids[]
limitations[]
```

Representative kinds:

- TLS negotiated version
- selected cipher suite
- record-layer legacy version
- supported versions
- key-share group
- PSK/key-exchange mode
- signature algorithm
- public-key algorithm/length
- certificate subject/issuer/SAN
- certificate validity window
- certificate fingerprint
- certificate-chain structure
- session resumption indicator

### 4.7 DerivedFact

Represents a deterministic conclusion from observations/events.

Required fields:

```text
fact_id
session_id
fact_type
value
derivation_id
derivation_version
source_event_ids[]
source_observation_ids[]
source_fact_ids[]
observability
confidence_level
confidence_basis[]
limitations[]
```

Examples:

- `starttls_advertised = true`
- `tls_upgrade_completed = false`
- `plaintext_commands_after_offer = 2`
- `negotiated_tls_version = TLS_1_0`
- `forward_secrecy = supported`
- `certificate_expired_at_capture_time = true`
- `certificate_identity_match = not_assessed`

### 4.8 RuleEvaluation

Records the complete evaluation of one policy rule.

Required fields:

```text
evaluation_id
session_id
rule_id
rule_version
profile_id
evaluated_at
input_fact_ids[]
input_snapshot
outcome
reason_code
generated_finding_id
```

Allowed outcomes:

- `matched`
- `not_matched`
- `not_applicable`
- `insufficient_evidence`
- `suppressed_by_profile`

### 4.9 Finding

Required fields:

```text
finding_id
stable_finding_key
analysis_id
session_id
rule_evaluation_id
rule_id
rule_version
title
category
severity
policy_risk_contribution
evidence_confidence
observability
fact_ids[]
evidence_ids[]
rationale
impact
recommendation_id
standards_references[]
limitations[]
created_at
```

`stable_finding_key` should be derived from the session key, rule ID/version, and relevant fact identities. It provides reproducibility without pretending findings from different rule versions are identical.

### 4.10 AnomalyResult

Required fields:

```text
anomaly_result_id
session_id
model_id
model_version
feature_schema_version
feature_snapshot
raw_score
normalized_score
threshold
band
unusual_feature_indicators[]
limitations[]
```

Anomaly results do not cite policy rules. They link to feature facts/observations and must state that anomalous behavior is not proof of malicious activity.

### 4.11 Recommendation

Required fields:

```text
recommendation_id
title
summary
priority
affected_finding_ids[]
action_steps[]
verification_steps[]
standards_references[]
scope
automation_status
```

For the submission, `automation_status` is `advisory_only`. SecureMailScope does not automatically alter infrastructure.

### 4.12 ArtifactManifest

Required fields:

```text
artifact_manifest_id
analysis_id
capture_sha256
canonical_json_sha256
html_report_sha256
pdf_report_sha256
rule_pack_sha256
model_artifact_sha256
generated_at
signature_algorithm
signature
```

A signature is optional for the first implementation. Hashes and version metadata are mandatory for Evidence Seal.

## 5. Graph edge types

| Edge | Meaning |
|---|---|
| `ANALYZED_FROM` | analysis → capture |
| `CONTAINS_SESSION` | capture → session |
| `HAS_EVENT` | session → event |
| `SUPPORTED_BY` | event/fact/finding → evidence |
| `OBSERVED_AS` | event/session → crypto observation |
| `DERIVED_FROM` | fact → observation/event/fact |
| `EVALUATED_BY` | fact set → rule evaluation |
| `PRODUCED` | rule evaluation → finding |
| `PRIORITIZED_WITH` | session/finding → anomaly result |
| `REMEDIATED_BY` | finding → recommendation |
| `REPRESENTED_IN` | analysis/finding → artifact |
| `SUPERSEDES` | newer rule/model evaluation → previous evaluation |

The JSON output may store references directly rather than a separate edge table, but the relationship semantics remain fixed.

## 6. Observability and confidence

### 6.1 Observability enum

- `observed`: directly extracted from capture/tool evidence
- `derived`: deterministic computation from observed/derived inputs
- `policy_inferred`: policy conclusion from facts
- `not_observable`: passive evidence cannot determine the value
- `incomplete_capture`: capture boundary/truncation prevents a conclusion
- `session_secrets_required`: protected TLS evidence requires authorized secrets
- `not_applicable`: field does not apply

### 6.2 Confidence enum

- `high`: direct evidence or deterministic derivation from complete, unambiguous evidence
- `medium`: deterministic result with incomplete context or classification supported by multiple weaker indicators
- `low`: heuristic classification or ML interpretation with substantial uncertainty
- `not_scored`: confidence is not meaningful for the value

Confidence must include a `confidence_basis`. Avoid unsupported values such as `97.3% confident` unless that probability is calibrated and tested.

Observability and confidence are independent. A value can be directly observed but still ambiguous because of malformed/truncated evidence.

## 7. Protocol transition semantics

### 7.1 SMTP STARTTLS

Representative secure sequence:

```text
server greeting
→ EHLO
→ capability response includes STARTTLS
→ client STARTTLS
→ server 220 ready
→ TLS ClientHello
→ TLS ServerHello
→ TLS handshake completes
→ encrypted application data
```

Important failure states:

- TLS not advertised
- advertised but never requested
- request rejected
- server accepts but no TLS ClientHello follows
- TLS handshake begins but fails
- plaintext commands continue after TLS advertisement
- plaintext commands continue after server accepts upgrade
- capture ends before outcome is observable

Do not label every opportunistic non-upgrade as an active downgrade attack. State the observed behavior and policy risk; attack attribution requires additional evidence.

### 7.2 IMAP STARTTLS

Representative sequence:

```text
server greeting
→ tagged CAPABILITY request/response
→ STARTTLS command with tag
→ matching tagged OK response
→ TLS ClientHello
→ handshake completion
```

The parser must retain and match IMAP command tags. Keyword detection without tag/order handling is insufficient.

### 7.3 POP3 STLS

Representative sequence:

```text
server +OK greeting
→ optional CAPA
→ STLS command
→ +OK response
→ TLS ClientHello
→ handshake completion
```

POP3 uses `STLS`, not `STARTTLS`.

### 7.4 Implicit TLS

For implicit TLS ports/flows, the session may begin with ClientHello without a plaintext upgrade command. Port remains a hint; observed TLS behavior and later application identification determine classification.

## 8. TLS evidence rules

### Negotiated version

- Prefer the negotiated version semantics from ServerHello/supported-version selection.
- Do not treat a TLS record legacy version as the negotiated protocol version.
- Preserve all repeated handshake types and their frame references.

### Cipher suite

- Use the server-selected cipher suite from ServerHello.
- TLS 1.3 cipher-suite names do not encode authentication or key-exchange method; evaluate key share/PSK mode separately.

### Forward secrecy

- TLS 1.2 `DHE`/`ECDHE` key exchange generally supports PFS.
- Static RSA key exchange does not provide PFS.
- TLS 1.3 with ephemeral (EC)DHE key share supports forward secrecy.
- TLS 1.3 PSK-only mode must not automatically be labelled PFS-capable.
- If evidence is insufficient, return unknown/not observable rather than guessing from the TLS version alone.

### Session resumption

An abbreviated/resumed session may not contain a new certificate message. Missing certificate evidence in a resumed session is not automatically a certificate failure.

## 9. X.509 evidence rules

### Extraction

When observable, record:

- exact certificate DER fingerprint
- subject and issuer
- SAN entries
- serial number
- validity interval
- public-key algorithm/size
- signature algorithm
- basic constraints/key usage where available
- chain order/structure

### Time semantics

Certificate expiration and not-yet-valid checks use the capture timestamp. The UI may separately display present-day status, but it must not replace capture-time validity.

### Validation scopes

Separate:

1. `structure_parsed`
2. `signature_chain_checked`
3. `trusted_path_validated`
4. `service_identity_validated`
5. `revocation_checked`

Trusted-path validation requires an identified trust store. Service-identity validation requires a reliable reference identity. Revocation requires authorized/current CRL or OCSP information. If inputs are absent, state `not_assessed` or `not_observable`; do not call the certificate invalid.

### TLS 1.3

TLS 1.3 handshake messages after ServerHello, including the certificate, are encrypted. Without authorized session secrets, certificate fields must use `session_secrets_required`/`not_observable` with an explicit reason.

## 10. Policy-as-Code contract

Rules must use a safe typed operator set. Never evaluate arbitrary Python or user-supplied expressions.

Illustrative YAML:

```yaml
id: SMS-SMTP-STARTTLS-001
version: 1.0.0
title: STARTTLS offered but plaintext continued
category: encryption_transition
protocols: [smtp]
severity: high
requires:
  - fact: starttls_advertised
    operator: equals
    value: true
  - fact: tls_upgrade_completed
    operator: equals
    value: false
  - fact: plaintext_commands_after_offer
    operator: greater_than
    value: 0
evidence_requirements:
  - starttls_advertisement
  - plaintext_command_after_offer
rationale: >-
  The server offered an encryption upgrade, but the session continued in
  plaintext without completing TLS.
remediation:
  recommendation_id: REC-EMAIL-REQUIRE-TLS
standards:
  - id: RFC8314
    section: "3"
```

Use a separate critical rule when synthetic/plaintext authentication evidence is observed after TLS was available. Do not expose actual credentials in output.

## 11. Risk, anomaly, and priority

### Policy risk

Derived only from matched versioned policy rules. The result includes each rule contribution, evidence confidence adjustment, caps, and profile configuration.

### ML anomaly

Derived only from the versioned feature pipeline/model. It includes the feature snapshot, threshold, model version, and unusual indicators.

### Investigation priority

The UI may display a transparent priority tier using:

- maximum policy severity
- evidence confidence
- affected-session scope
- anomaly band
- capture completeness

Do not hide these components in one unexplained number. Anomaly may increase review priority but cannot transform an unverified behavior into a deterministic policy violation.

## 12. Canonical finding example

Illustrative only; frame values are not claims about the frozen T01 fixture.

```json
{
  "finding_id": "fnd_7c16...",
  "stable_finding_key": "sha256:...",
  "analysis_id": "ana_demo_001",
  "session_id": "ses_demo_smtp_0041",
  "rule_evaluation_id": "eval_sms_smtp_starttls_001",
  "rule_id": "SMS-SMTP-STARTTLS-001",
  "rule_version": "1.0.0",
  "title": "STARTTLS offered but plaintext continued",
  "category": "encryption_transition",
  "severity": "high",
  "policy_risk_contribution": 25,
  "evidence_confidence": "high",
  "observability": "policy_inferred",
  "fact_ids": [
    "fact_starttls_advertised",
    "fact_upgrade_not_completed",
    "fact_plaintext_after_offer"
  ],
  "evidence_ids": [
    "ev_frame_104_starttls_offer",
    "ev_frame_108_plaintext_mail"
  ],
  "rationale": "The server advertised STARTTLS, but the client continued with plaintext SMTP commands without completing TLS.",
  "impact": "Email metadata or authentication material may be exposed to passive interception depending on the subsequent commands.",
  "recommendation_id": "REC-EMAIL-REQUIRE-TLS",
  "standards_references": [
    {"id": "RFC8314", "section": "3"}
  ],
  "limitations": [
    "The capture proves plaintext continuation; it does not by itself prove an active downgrade attacker."
  ]
}
```

## 13. API contract

Minimum chain endpoints:

- `GET /api/v1/analyses/{analysis_id}/chain`
- `GET /api/v1/analyses/{analysis_id}/chain?finding_id={finding_id}`
- `GET /api/v1/analyses/{analysis_id}/sessions/{session_id}/events`
- `GET /api/v1/analyses/{analysis_id}/evidence/{evidence_id}`
- `GET /api/v1/analyses/{analysis_id}/findings/{finding_id}`

The finding response should embed small summaries and reference canonical events/evidence. Avoid returning the entire capture analysis for every drawer request.

Frontend Zod schemas must validate the same examples used by backend contract tests.

## 14. Frontend mapping

| Backend object | Frontend representation |
|---|---|
| CaptureProvenance | validation/integrity card |
| Session | session-table row and header |
| ProtocolEvent | Transition Twin timeline node |
| CryptoObservation | cryptography/certificate tabs |
| DerivedFact | fact summary and comparison matrix |
| RuleEvaluation | “Why this was flagged” panel |
| Finding | prioritized finding card |
| EvidenceReference | evidence drawer with packet/time/filter |
| AnomalyResult | separate anomaly panel |
| Recommendation | remediation card/what-if input |
| ArtifactManifest | report verification/Evidence Seal |

The frontend must render canonical state; it must not derive protocol security conclusions independently.

## 15. Report mapping

JSON is the canonical machine-readable result. HTML and PDF are views derived from it.

Each exported report contains:

- capture provenance and SHA-256
- analyzer/rule/model versions
- posture summary
- policy risk and ML anomaly separately
- prioritized findings
- affected sessions
- evidence references
- limitations/not-observable facts
- recommendations
- artifact manifest/hashes

HTML/PDF counts and severities must be generated from the same finding list as the UI.

## 16. Integrity and canonicalization

For the first submission:

- serialize canonical JSON with stable key ordering and deterministic separators;
- exclude volatile presentation-only timestamps from reproducibility comparison or store them in a clearly separate execution envelope;
- hash the canonical JSON, HTML, PDF, rule pack, and model artifact;
- store hashes in ArtifactManifest.

Future Evidence Seal can use RFC 8785 JSON Canonicalization and an Ed25519 signature. Do not claim legal chain of custody solely because artifacts are hashed; describe it as tamper-evident provenance.

## 17. Privacy and safe evidence presentation

Email PCAPs may expose addresses, credentials, commands, and metadata.

Default rules:

- never display passwords/authentication payloads;
- redact local parts of email addresses in reports unless an authorized forensic mode is explicitly enabled;
- store hashes or safe excerpts where the full value is unnecessary;
- escape all packet-derived strings before HTML rendering;
- do not place raw message bodies in the dashboard;
- keep sensitive packet contents out of logs;
- retain exact packet references so authorized analysts can verify in the original capture.

## 18. Failure semantics

The chain must remain valid for partial analysis.

Examples:

- invalid capture → analysis failure with provenance attempt, no fake sessions
- TShark timeout → partial/failed stage with limitation
- truncated stream → events retained, final transition `incomplete_capture`
- TLS 1.3 protected certificate → valid session, certificate `session_secrets_required`
- unsupported field/version → observation unavailable, not a false secure result
- rule engine failure → observations/facts preserved; policy assessment marked failed
- ML failure → deterministic findings preserved; anomaly marked unavailable

## 19. Test strategy

### Schema tests

- all node models reject invalid references/enums
- JSON validates against versioned schema
- frontend examples validate through Zod

### Graph-invariant tests

- finding references existing rule evaluation/facts/evidence
- derived fact has at least one source
- evidence capture hash matches analysis capture
- sequence indices are monotonic within a session
- no cycle exists in derivation links
- `not_observable` has a reason/limitation
- report artifacts reference the same analysis

### Protocol tests

- split commands across TCP segments
- retransmission/out-of-order handling delegated to TShark reassembly
- repeated capability lines
- case/whitespace variants
- IMAP tag matching
- POP3 `STLS` rather than `STARTTLS`
- implicit TLS
- non-standard port
- capture starts/ends mid-session

### TLS/X.509 tests

- record legacy version differs from negotiated version
- repeated handshake types preserved
- TLS 1.2 full versus resumed handshake
- TLS 1.3 certificate not observable without secrets
- PFS supported/unsupported/unknown cases
- certificate expiry at capture time
- missing trust store/identity/revocation inputs produce not-assessed states

### Rule tests

- positive match
- negative match
- not applicable
- insufficient evidence
- profile suppression
- rule version change does not mutate observations

### Reproducibility tests

- two clean runs have equivalent canonical chain
- canonical JSON digest is stable
- UI/JSON/HTML/PDF totals agree

## 20. Suggested code organization

```text
src/securemailscope/
├── evidence/
│   ├── models.py
│   ├── enums.py
│   ├── ids.py
│   ├── builder.py
│   ├── graph.py
│   ├── invariants.py
│   ├── redaction.py
│   └── integrity.py
├── events/
│   ├── models.py
│   ├── smtp.py
│   ├── imap.py
│   └── pop3.py
├── crypto/
│   ├── tls.py
│   ├── pfs.py
│   └── x509.py
├── facts/
│   └── derive.py
├── policy/
│   ├── models.py
│   ├── loader.py
│   ├── engine.py
│   └── rules/
├── anomaly/
├── reports/
└── api/
```

Adapt names to the existing repository rather than moving stable POC modules unnecessarily.

## 21. Implementation sequence

### Commit 1 — Contract

`feat: add chain-of-proof domain contract`

- enums and Pydantic models
- stable ID helpers
- JSON schema
- invariant tests
- example secure and insecure chain fixtures

### Commit 2 — Existing POC adapter

`feat: map verified smtp analysis into evidence chain`

- capture/session/evidence mapping
- current SMTP events
- existing TLS/certificate evidence
- no policy rules yet

### Commit 3 — State and facts

`feat: derive smtp transition facts from ordered evidence`

- event builder
- deterministic facts
- incomplete/not-observable states

### Commit 4 — Rules and findings

`feat: add versioned policy evaluation and findings`

- typed rule model/loader
- first STARTTLS rules
- recommendations
- risk contributions

### Commit 5 — Vertical presentation

`feat: expose chain and render evidence-backed finding`

- API endpoints
- timeline/evidence drawer
- JSON/HTML/PDF consistency

Only after the vertical slice passes should the same contract be expanded to IMAP, POP3, remaining TLS/X.509 rules, and ML anomaly results.

## 22. First vertical acceptance scenario

Scenario ID: `DEMO-SMTP-STARTTLS-NOT-USED-01`

Controlled truth:

1. SMTP is identified from reconstructed content.
2. Server advertises STARTTLS.
3. Client does not send STARTTLS.
4. Plaintext SMTP command continues.
5. No TLS handshake completes.
6. Capture is complete enough to support the conclusion.

Required chain:

```text
capture hash
→ SMTP session
→ STARTTLS advertisement evidence
→ plaintext continuation evidence
→ derived transition facts
→ rule SMS-SMTP-STARTTLS-001 evaluation
→ high finding
→ remediation
→ timeline/evidence drawer
→ matching JSON/HTML/PDF
```

Acceptance conditions:

- correct packets/timestamps referenced
- no claim of proven attacker/downgrade attribution
- no sensitive value exposed
- policy risk generated deterministically
- ML anomaly absent or displayed independently
- stable canonical output across two clean runs
- frontend and reports show the same title, severity, evidence, and limitation

## 23. Definition of done

The Chain-of-Proof Engine v1 is GREEN when:

1. Domain models and schema are frozen/versioned.
2. Existing verified SMTP POC data maps into the chain without losing evidence.
3. The insecure vertical scenario produces the correct ordered chain and finding.
4. Every finding passes graph invariants.
5. TLS/X.509 uncertainty rules are represented explicitly.
6. API, UI, JSON, HTML, and PDF consume the same canonical result.
7. Two clean runs produce equivalent canonical output.
8. No packet-derived unsafe content is rendered unescaped.
9. Policy risk and ML anomaly remain separate.
10. The demo can traverse finding → rule/facts → events → packets in under ten seconds.

## 24. Standards foundation

- SMTP STARTTLS: RFC 3207 — https://www.rfc-editor.org/info/rfc3207
- IMAP/POP3 TLS: RFC 2595 and updated email TLS guidance in RFC 8314 — https://www.rfc-editor.org/info/rfc2595 and https://www.rfc-editor.org/info/rfc8314
- TLS 1.3: RFC 8446 — https://www.rfc-editor.org/info/rfc8446
- Secure TLS recommendations: RFC 9325 — https://www.rfc-editor.org/info/rfc9325
- X.509 path validation: RFC 5280 — https://www.rfc-editor.org/info/rfc5280
- Service identity verification: RFC 9525 — https://www.rfc-editor.org/info/rfc9525

These references guide rule design. Exact applicability and section citations must be verified when each production rule is authored.
