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

The closed selection POC did **not** prove IMAP/POP3, full TLS/cipher/key-exchange extraction, Forward Secrecy, X.509 extraction/validation, TLS 1.3 visibility behavior, policy, ML, canonical report JSON, HTML/report rendering, API, or frontend integration. Those features are not implemented outputs. Their verified status is recorded in `context/progress-tracker.md`.

## Production backend

The active production branch `feat/production-backend` builds the Chain-of-Proof engine on the verified POC core:

- Commit 1 (completed at `57fe930`): versioned Chain-of-Proof domain contract under `src/securemailscope/chain`.
- Commit 2 (completed and verified at `616b97d`): the pure POC-result adapter that maps verified analyzer output into the chain.
- Commit 3 (next, UNVERIFIED): deterministic derivation of SMTP transition facts from ordered, evidence-backed chain events.

API, frontend, policy, ML, and report layers are later milestones and are not yet claims. The frontend is separate and frozen. Policy risk and ML anomaly remain separate outputs.

## Verified selection POC evidence

The closed selection POC produced, and recorded in `docs/POC_RESULT.md`, only the currently verified analyzer evidence:

- the offline analysis path (intake, provenance/SHA-256, bounded TShark, native TCP reassembly, content-based SMTP classification, SMTP STARTTLS transition analysis, typed results/errors);
- verified offline tests;
- the T01 manual verification PASS (23/23);
- the E2/E3A analyzer-path checkpoint PASS;
- `docs/POC_RESULT.md` recording the selection outcome.

No canonical report JSON, HTML/report rendering, policy findings, or ML anomaly outputs are implemented, and none are claimed here.

## Current truth

Implementation progress and verified results are recorded in `context/progress-tracker.md`. Do not infer completion from the planned repository structure or documentation.