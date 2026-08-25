# SecureMailScope — AI Workflow Rules

## Permanent instruction for any AI assistant

At the beginning of every new session:

1. Read `MASTER_PROMPT.md`, `project-overview.md`, and `progress-tracker.md`.
2. Use the routing table in `MASTER_PROMPT.md` to load only the detailed documents relevant to the active task.
3. Confirm repository/Git state; do not assume a planned file, PCAP, test, or feature exists.
4. Work on only the current step unless the developer explicitly changes priorities.
5. Update `progress-tracker.md` only after a material verified change, recording actual commands, results, runtime, blockers, and next action.

These files make context recoverable across AI tools; they do not automatically prove that an AI has read them. The developer should instruct each AI to read the folder before acting or configure that AI's repository instruction file to do so.

## Authority order

When instructions conflict, follow this order:

1. The explicit current request from the primary developer.
2. The verbatim official PS159 requirements in `docs/OFFICIAL_PS159.md`.
3. Frozen POC gates and truth rules.
4. Approved architecture, code standards, and tooling decisions.
5. The active feature and current progress state.

If a request conflicts with a frozen gate or evidence rule, identify the conflict and request an explicit decision. Never weaken an expected result merely to make the POC pass.

## Operating model

The developer owns architecture, ground truth, and acceptance decisions. AI can research and implement bounded units, but its output remains untrusted until checked against independently controlled evidence.

## Before implementation

- Confirm that the repository and required tools actually exist.
- State the exact acceptance criteria for the current step.
- Inspect existing files and preserve unrelated user work.
- If a value cannot be observed, preserve an explicit unknown/incomplete state instead of inventing it.
- Ask only when a missing decision would materially change the result.

## During implementation

- Build the smallest end-to-end evidence slice first.
- Keep fixture generation independent from analyzer logic.
- Never read analyzer output to create ground truth.
- Never change fixture truth or a frozen gate solely to obtain a passing test.
- Do not introduce dashboard, authentication, PDF, deployment, database, SIEM, or phishing work during the POC.
- Record assumptions before depending on them.
- Prefer typed models and failing tests over silent fallbacks.

## Verification ladder

For each controlled fixture or feature:

1. Verify fixture configuration, endpoint logs, certificate manifest, timestamps, and hashes.
2. Inspect the PCAP manually with TShark and preserve the relevant stream/field evidence.
3. Run the generic analyzer on the PCAP input.
4. Compare normalized analyzer output with independent ground truth.
5. Run positive, negative, incomplete, and false-positive tests required by the gate.
6. Run formatting and static checks.
7. Record exact commands, results, runtime, and blockers.

Analyzer output alone never proves analyzer correctness.

## Hard stop rules

- During the first technical spike, stop as RED/BLOCKED if the controlled SMTP evidence chain cannot be produced within approximately 90 minutes after ordinary setup corrections.
- Stop and diagnose if TShark cannot expose a required observable value; never replace it with a guess.
- Stop if certificate validation cannot be reproduced against an explicit trust store at capture time.
- Stop if logic would combine policy and ML scores or fabricate TLS 1.3 certificate status.
- Do not move to UI/report polish while a core technical gate is failing.

## Completion rule

A step is complete only when its fixture/inputs, independent ground truth, manual evidence, implementation, automated comparison, failure behaviour, commands, and actual result are recorded.

The final POC must produce `docs/POC_RESULT.md` with passed tests, failed tests, commands, hashes, evidence, runtime, blockers, and a decisive GREEN/RED recommendation.
