# SecureMailScope

SecureMailScope is an evidence-backed passive network-forensics framework for assessing the cryptographic posture of SMTP, IMAP, and POP3 sessions in PCAP/PCAPNG captures.

This repository contains two phases:

- A **frozen selection POC** (closed at `cf055cf`) that proved the analyzer core against independently controlled PCAP ground truth.
- An **active production backend** on branch `feat/production-backend`, governed by the approved Chain-of-Proof contract in `docs/CHAIN_OF_PROOF_SPECIFICATION.md` (schema `1.0.0`).

A capability is considered passed only when it agrees with independently controlled PCAP ground truth and is recorded in `context/progress-tracker.md`.

## Start here

Before making changes, read:

1. `MASTER_PROMPT.md`
2. `context/project-overview.md`
3. `context/progress-tracker.md`
4. `AGENTS.md`

Then follow the task-routing table in `MASTER_PROMPT.md` and the production plan/review/test/commit workflow in `AGENTS.md`.

The verbatim problem statement is preserved in `docs/OFFICIAL_PS159.md`. POC requirements and binary acceptance gates are defined in `docs/PRD.md`. The production Chain-of-Proof contract is in `docs/CHAIN_OF_PROOF_SPECIFICATION.md`.

## Frozen selection POC

The frozen selection POC (closed at `cf055cf`) proved only the verified analyzer core. Its exact verified scope is:

- generic PCAP/PCAPNG intake;
- capture provenance and streamed SHA-256;
- safe bounded TShark execution;
- TShark-native TCP reassembly;
- conservative content-based SMTP classification;
- SMTP STARTTLS transition-state analysis;
- typed analyzer models and errors;
- verified offline tests;
- T01 manual verification PASS, 23/23;
- E2/E3A analyzer-path checkpoint PASS.

The closed selection POC did **not** prove IMAP/POP3, full TLS/cipher/key-exchange extraction, Forward Secrecy, X.509 extraction/validation, TLS 1.3 visibility behavior, policy, ML, canonical report JSON, HTML/report rendering, API, or frontend integration. Those were not outputs of the frozen selection POC. Their current production status is recorded separately in `context/progress-tracker.md`.

## Production backend

The active production branch `feat/production-backend` builds the Chain-of-Proof engine on the verified POC core:

- Commit 1 (completed at `57fe930`): versioned Chain-of-Proof domain contract under `src/securemailscope/chain`.
- Commit 2 (completed and verified at `616b97d`): the pure POC-result adapter that maps verified analyzer output into the chain.
- **Commit 3 (completed and verified at `2c1454f`):** deterministic derivation of SMTP transition facts from ordered, evidence-backed chain events.
- **Commit 4 (completed and verified at `ad25711`):** deterministic policy-pack loading and policy evaluation over the validated Chain-of-Proof, producing evidence-backed rule evaluations, findings, recommendations and policy-risk output.
- **Commit 5A (completed and verified at `3807118`):** a deterministic presentation and artifact-rendering foundation over an already validated and policy-evaluated Chain-of-Proof.
- **Commit 5B (completed and verified at `a262b24`):** a thin, read-only FastAPI exposure layer over an injected repository of validated Chain-of-Proof objects and the verified Commit 5A presentation/artifact services.

Commit 5A produces a strict immutable selected-finding projection, canonical Chain JSON, autoescaped finding HTML, deterministic finding PDF, artifact SHA-256 digests and byte lengths, an evidence-backed event timeline ordered by `(sequence_index, event_id)`, exact evidence frame numbers and timestamps, finding rationale, impact, remediation and standards references, and separate policy-risk and ML-anomaly presentation.

Commit 5A does not analyze packets, derive new facts, evaluate policy, run ML, write artifacts to the filesystem, expose HTTP/API routes, implement upload or analysis-job orchestration, add persistence, authentication or frontend code, attribute an attacker, or expose raw SMTP payloads, credentials, email addresses or arbitrary filesystem paths.

Commit 5B provides a versioned `/api/v1` read-only boundary for analysis summaries, canonical Chain retrieval, scoped session events and evidence, direct Commit 5A finding presentations, and existing JSON/HTML/PDF artifacts. Responses are typed, bounded and deterministic, with stable non-sensitive errors and integrity/security headers. FastAPI remains an adapter: it does not perform packet analysis, fact derivation, policy evaluation, ML execution or presentation business logic. The frontend remains a separate repository/workstream, so its implementation is not a backend production capability.

Commit 5A completed deterministic presentation and in-memory artifacts; Commit 5B completed the thin read-only HTTP exposure. The declared backend Commit 5 presentation/API/artifact boundary is therefore completed and verified through `3807118` and `a262b24`.

Commit 5B does not add PCAP upload, POST/PUT/PATCH/DELETE analysis behavior, background jobs or queues, database persistence, authentication or authorization, frontend implementation, analyzer/policy/ML execution, live capture, SIEM, phishing detection, blocking, email decryption, geolocation, external AI APIs, silent online dependencies or filesystem artifact writing. The default production application repository is empty; test data is injected only in tests. Current production capability remains bounded by verified SMTP coverage. TLS 1.3 certificate details remain `not_observable` without authorized session secrets. Ports remain hints, protocol classification remains content-based, and policy risk and ML anomaly remain separate outputs.

The next backend milestone is pending explicit architectural selection and remains **UNVERIFIED**. IMAP/POP3 expansion, ML anomaly execution, upload/analysis orchestration, persistence, authentication and deployment remain separate, unimplemented candidates and are not authorized by this documentation update.

## Verified selection POC evidence

The closed selection POC produced, and recorded in `docs/POC_RESULT.md`, only the currently verified analyzer evidence:

- the offline analysis path (intake, provenance/SHA-256, bounded TShark, native TCP reassembly, content-based SMTP classification, SMTP STARTTLS transition analysis, typed results/errors);
- verified offline tests;
- the T01 manual verification PASS (23/23);
- the E2/E3A analyzer-path checkpoint PASS;
- `docs/POC_RESULT.md` recording the selection outcome.

No canonical report JSON, HTML/report rendering, policy findings, or ML anomaly outputs were part of the frozen selection-POC evidence, and none are claimed by that historical record. Current production milestones are recorded separately above and in `context/progress-tracker.md`.

## Current truth

Implementation progress and verified results are recorded in `context/progress-tracker.md`. Do not infer completion from the planned repository structure or documentation.
