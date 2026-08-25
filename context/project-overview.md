# SecureMailScope — Project Overview

## How every AI must use this repository foundation

Always start with `MASTER_PROMPT.md`, this overview, and `progress-tracker.md`. Then follow the task-routing table in `MASTER_PROMPT.md` to load only the relevant detailed documents.

Read every foundation document only for a first full audit, an architecture/scope change, or a suspected conflict. Treat these files as the persistent project source of truth. Update `progress-tracker.md` only after a material, verified state change.

## Current status — do not misreport this

- The repository has **not been created yet**.
- No implementation has started.
- No PCAP fixture has been generated.
- No technical gate has passed or failed.
- The current activity is repository-foundation preparation and POC planning only.

## Project identity

- **Problem statement:** SIH 2026 PS159.
- **Title:** SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.
- **Primary developer:** One solo developer for the technical implementation.
- **Decision stage:** PS159 will receive an approximately eight-hour technical POC. A second finalist will receive a separate one-day POC. Only then will the final SIH problem statement be selected.
- **If selected:** Reuse the POC core and complete the full solution in the following five-to-six days.
- **Planning deadline supplied in prior project context:** 2 September 2026. Verify it against the official portal before relying on it for final scheduling.

## Official requirements source

`docs/OFFICIAL_PS159.md` preserves the complete problem-statement content supplied by the developer. It is authoritative over summaries and POC planning documents. Read it together with `docs/PRD.md` for any requirements, scope, acceptance, or architecture decision.

Nothing in the POC scope removes a final-solution requirement. PDF and the interactive dashboard are intentionally deferred only until PS159 is selected.

## Purpose of the one-day POC

The POC is a technical kill test, not a miniature polished product. Its job is to determine whether the hardest protocol-forensics and cryptographic-analysis core is feasible, correct, demonstrable, and reusable under the deadline.

PS159 is GREEN only if every mandatory POC gate is proven against independently controlled PCAP ground truth. A failed or unfinished mandatory gate means RED; appearance or UI polish cannot override the result.

## Mandatory POC capabilities

The POC must prove:

1. Automatic SMTP, IMAP, and POP3 identification from content, including non-standard ports.
2. Correct SMTP STARTTLS, IMAP STARTTLS, and POP3 STLS handling.
3. TCP and email-session reconstruction.
4. Reconstruction of all TLS-handshake events observable in the capture.
5. TLS version, cipher suite, and key-establishment extraction.
6. Forward Secrecy assessment.
7. X.509 extraction and validation when observable.
8. Honest handling of TLS 1.3 certificate invisibility in passive captures without secrets.
9. Evidence-backed deterministic cryptographic findings and mitigations.
10. Separate policy-risk and ML-anomaly scores.
11. Canonical JSON and minimal static HTML output.

## Explicit POC exclusions

Do not build these during the one-day test:

- Authentication or user management.
- A large or interactive dashboard.
- Product live capture.
- PDF export.
- SIEM integration.
- Phishing, spam, malware, or email-content detection.
- A database, cloud deployment, or production infrastructure.
- A claim that a tiny synthetic ML model generalizes to real enterprise traffic.

PDF and the interactive dashboard remain official final-solution requirements if PS159 is selected.

## POC truth rules

- Never present an inference as a directly captured fact.
- Every extracted cryptographic fact must reference PCAP hash, TCP stream, frame number(s), source field/bytes, and observability status.
- Never guess absent information. Use explicit states such as `not_observable`, `capture_incomplete`, or `unknown_insufficient_evidence` with a reason.
- Ground truth must come from fixture configuration, endpoint logs, OpenSSL output, controlled certificate files, timestamps, and hashes—not from analyzer output.
- In secretless passive TLS 1.3, the server Certificate message is encrypted after ServerHello. Report exactly `not_observable_encrypted_tls13`; do not call the certificate missing, invalid, expired, or trusted.
- Do not infer TLS 1.3 key exchange or Forward Secrecy from the cipher-suite name. Use `key_share` and PSK exchange evidence.
- Validate certificates primarily at the PCAP capture time against an explicit trust store. Record analysis-time status separately.
- Deterministic policy findings are authoritative cryptographic results. The ML anomaly score is a separate behavioural signal, not cryptographic proof or a probability of compromise.

## Definition of POC success

The POC succeeds only when all controlled tests agree with independent ground truth, every finding resolves to packet/certificate evidence, policy and ML scores remain separate, JSON validates, HTML matches JSON, and the complete matrix runs without an unhandled exception.

The final evidence must be recorded in `docs/POC_RESULT.md` with passed tests, failed tests, commands, PCAP hashes, evidence, runtime, blockers, and a decisive GREEN or RED recommendation.
