# SecureMailScope

SecureMailScope is an evidence-backed passive network-forensics framework for assessing the cryptographic posture of SMTP, IMAP, and POP3 sessions in PCAP/PCAPNG captures.

This repository currently contains the strict technical POC for SIH 2026 PS159. A capability is considered passed only when it agrees with independently controlled PCAP ground truth.

## Start here

Before making changes, read:

1. `MASTER_PROMPT.md`
2. `context/project-overview.md`
3. `context/progress-tracker.md`

Then follow the task-routing table in `MASTER_PROMPT.md`.

The verbatim problem statement is preserved in `docs/OFFICIAL_PS159.md`. POC requirements and binary acceptance gates are defined in `docs/PRD.md`.

## POC outputs

The POC will produce:

- canonical schema-validated JSON;
- minimal static HTML generated only from that JSON;
- evidence-backed cryptographic findings;
- separate policy-risk and ML-anomaly scores;
- `docs/POC_RESULT.md` containing the final GREEN/RED recommendation.

## Current truth

Implementation progress and verified results are recorded in `context/progress-tracker.md`. Do not infer completion from the planned repository structure or documentation.