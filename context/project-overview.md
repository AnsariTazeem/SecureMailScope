# SecureMailScope — Project Overview

## How every AI must use this repository foundation

Always start with `MASTER_PROMPT.md`, this overview, and `progress-tracker.md`. Then follow the task-routing table in `MASTER_PROMPT.md` to load only the relevant detailed documents.

Read every foundation document only for a first full audit, an architecture/scope change, or a suspected conflict. Treat these files as the persistent project source of truth. Update `progress-tracker.md` only after a material, verified state change.

## Current status — do not misreport this

- The **PS159 selection POC is closed** at commit `cf055cf` (branch `main`), recorded as GO/selection without claiming the full product or the complete original POC matrix is GREEN.
- The active production branch is **`feat/production-backend`**.
- **Chain Commit 1** (`feat: add chain-of-proof domain contract`) is **completed and verified at `57fe930`**.
- **Commit 2** (the pure POC-result adapter that maps verified analysis into the chain) is the **next milestone**.
- The frontend is **separate and frozen**; no frontend redesign is authorized.
- **Policy risk and ML anomaly remain separate** outputs in all production work.
- The repository is in the **production-development phase** building on the verified POC core.

Only verified state is recorded in `context/progress-tracker.md`. Do not infer completion from a planned directory, unchecked checklist, design document, or generated artifact.

## Project identity

- **Problem statement:** SIH 2026 PS159.
- **Title:** SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.
- **Primary developer:** One solo developer for the technical implementation.
- **Decision stage:** The selection POC ran and closed as **GO — PS159 selected/finalized for Team Apex** at `cf055cf`. The production phase builds the backend on the verified POC core.
- **Production branch:** `feat/production-backend`. The frontend is a **separate, frozen** workstream that must not be redesigned in backend milestones.
- **Planning deadline supplied in prior project context:** 2 September 2026. Verify it against the official portal before relying on it for final scheduling.

## Official requirements source

`docs/OFFICIAL_PS159.md` preserves the complete problem-statement content supplied by the developer. It is authoritative over summaries and POC planning documents. Read it together with `docs/PRD.md` for any requirements, scope, acceptance, or architecture decision.

The official problem statement historically describes a final solution that includes PDF and an interactive dashboard. In the **currently authorized product scope**, PDF export is **excluded**; the interactive frontend is a separate, frozen workstream. Historical scope notes below are planning text, not current authorization.

## Purpose of the one-day POC (historical)

This describes the closed selection POC planning. The selection POC is closed (GO at `cf055cf`) after T01 and E2/E3A viability evidence.

The POC was a technical kill test, not a miniature polished product. Its job was to determine whether the hardest protocol-forensics and cryptographic-analysis core is feasible, correct, demonstrable, and reusable under the deadline.

The original POC plan defined GREEN only if every mandatory POC gate is proven against independently controlled PCAP ground truth; a failed or unfinished mandatory gate would mean RED, and appearance or UI polish cannot override the result. The actual selection POC closed after T01 and E2/E3A viability evidence, without claiming the full matrix was GREEN.

## Mandatory POC capabilities (historical planned matrix)

This is the historical POC-planning capability list and does not state what was actually verified. The selection POC closed after T01 and E2/E3A viability evidence only; it does **not** claim the complete T01–T08/G01–G11 matrix was GREEN. Verified status is in `context/progress-tracker.md`.

The planned POC would prove:

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

## Explicit POC exclusions (historical)

The historical one-day-test exclusions were:

Do not build these during the one-day test:

- Authentication or user management.
- A large or interactive dashboard.
- Product live capture.
- PDF export.
- SIEM integration.
- Phishing, spam, malware, or email-content detection.
- A database, cloud deployment, or production infrastructure.
- A claim that a tiny synthetic ML model generalizes to real enterprise traffic.

PDF export is excluded from the currently authorized product scope. The optional PDF-related Chain-of-Proof contract field does not constitute implementation, authorization, or a product claim. The interactive frontend is a separate, frozen workstream and is not redesigned by backend tasks.

## POC truth rules (historical; still binding for POC records)

These integrity rules remain binding for the frozen POC records and are carried into production work:

- Never present an inference as a directly captured fact.
- Every extracted cryptographic fact must reference PCAP hash, TCP stream, frame number(s), source field/bytes, and observability status.
- Never guess absent information. Use explicit states such as `not_observable`, `capture_incomplete`, or `unknown_insufficient_evidence` with a reason.
- Ground truth must come from fixture configuration, endpoint logs, OpenSSL output, controlled certificate files, timestamps, and hashes—not from analyzer output.
- In secretless passive TLS 1.3, the server Certificate message is encrypted after ServerHello. Report exactly `not_observable_encrypted_tls13`; do not call the certificate missing, invalid, expired, or trusted.
- Do not infer TLS 1.3 key exchange or Forward Secrecy from the cipher-suite name. Use `key_share` and PSK exchange evidence.
- Validate certificates primarily at the PCAP capture time against an explicit trust store. Record analysis-time status separately.
- Deterministic policy findings are authoritative cryptographic results. The ML anomaly score is a separate behavioural signal, not cryptographic proof or a probability of compromise.

## Definition of POC success (historical planned matrix)

The planned success definition below is historical POC-planning text. The selection POC closed after T01 (23/23) and E2/E3A analyzer-path evidence; T02–T08 and the formal binary gates were not all proven. Verified status is in `context/progress-tracker.md`.

The planned definition stated the POC succeeds only when all controlled tests agree with independent ground truth, every finding resolves to packet/certificate evidence, policy and ML scores remain separate, JSON validates, HTML matches JSON, and the complete matrix runs without an unhandled exception.

The original plan required final evidence to be recorded in `docs/POC_RESULT.md` with passed tests, failed tests, commands, PCAP hashes, evidence, runtime, blockers, and a decisive GREEN or RED recommendation. `docs/POC_RESULT.md` is now the frozen selection-POC evidence record.

## Production phase

The POC selection is closed and the repository is in the **production-development phase** on branch `feat/production-backend`. The production phase does not rewrite the frozen POC history: the selection POC closes at `cf055cf`, the POC verification history in `context/progress-tracker.md` is preserved, and `docs/POC_RESULT.md`, `docs/PRD.md`, `docs/SYSTEM_DESIGN.md`, frozen capture fixtures, and POC expected outputs remain unchanged.

The active production contract is the **Chain of Proof** (schema `1.0.0`; repository copy in `docs/CHAIN_OF_PROOF_SPECIFICATION.md`, checksum `fa7b14d077a6e71c9e172898e410de08be7b0b87a237fec56e1c76c817f9bb25`). Production work proceeds in the declared Commit sequence (Commit 1 contract completed at `57fe930`; Commit 2 POC-result adapter is next and UNVERIFIED). API, policy, ML, and report layers are later milestones. No production claim is made until it is verified and recorded; planning material is never presented as implemented functionality.

### Scope-authorization boundaries

- **PDF export is excluded from the currently authorized product scope.** The optional PDF-related field in the Chain-of-Proof contract (e.g. `pdf_report_sha256`) does **not** constitute implementation, authorization, or a product claim. Any future PDF work requires an explicit scope decision by the developer.
- The **interactive frontend remains a separate workstream** and must not be redesigned or extended by backend tasks.
- Policy risk and ML anomaly remain separate outputs throughout production work.
