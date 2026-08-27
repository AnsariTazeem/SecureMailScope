# SecureMailScope — Progress Tracker

**Last updated:** 27 August 2026

**Current phase:** Step 1 (Environment) PASS; Step 2 (SMTP evidence spike) PASS; E2/E3A analyzer-path checkpoint PASS. T01 PASS (corrected attempt; earlier failed attempt preserved). E2/E3A PASS for its authorized scope.

**Implementation status:** T01 PASS (23/23 comparisons); E2/E3A PASS (authorized scope: read-only intake, TShark-native reassembly, content-based SMTP classification, STARTTLS transition states). Selection decision: GO — PS159 selected/finalized for Team Apex. T02–T08 and all binary gates remain UNTESTED.

**POC verdict:** Selection-grade technical POC CLOSED as GO (PS159 selected). This is a GO/selection decision establishing technical viability; it is not a claim that the full product or the complete original POC matrix is GREEN.

## Completed preparation

- [x] Official PS159 description reviewed and preserved verbatim in `docs/OFFICIAL_PS159.md`.
- [x] Mandatory POC capabilities frozen.
- [x] Technical architecture and stack selected.
- [x] Controlled PCAP matrix T01–T08 defined.
- [x] Binary gates G01–G11 defined.
- [x] POC exclusions separated from official final requirements.
- [x] Six reusable AI-context files prepared.
- [x] In-depth POC PRD prepared.
- [x] System design and evidence/data boundaries prepared.
- [x] Feature breakdown mapped to T01–T08 and G01–G11.
- [x] Master AI prompt and response contract prepared.
- [x] Official-source tooling decision record prepared.

## Verified milestone — environment/bootstrap and doctor (PASS, 2026-08-25)

The environment/bootstrap/doctor milestone and T01 manual verification are marked PASS. T02–T08, analyzer-path validation, and formal gates G01–G11 remain UNTESTED.

Evidence recorded on 2026-08-25:

- `securemailscope doctor` implemented (Typer CLI; deterministic prerequisite checks in `tooling.py`).
- 10 unit tests passed in 0.84 seconds.
- Ruff lint passed.
- Ruff formatting check passed.
- `git diff --check` passed.
- Real doctor run result: `READY`.
- 11/11 prerequisite checks passed.
- JSON validation of the doctor report returned true.
- Real doctor exit code: 0 (`EXIT_OK`).

Scope of this PASS: environment bootstrap and the doctor command only.

## Verified milestone — T01 manual verification (PASS, corrected attempt, 2026-08-26)

T01 controlled SMTP ECDHE PCAP: independent manual verifier PASS, 23/23 comparisons passed, 0 failed.

An earlier T01 attempt failed. That attempt is preserved locally in evidence artifacts and archives and is not overwritten. This section records the corrected run only.

Evidence recorded on 2026-08-26 (corrected run):

- T01 PCAP SHA-256: `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`
- 28 packets captured; received 28; dropped 0
- Capture runtime: recorded (see evidence log)
- Verifier runtime: 12.280 seconds
- SMTP port: 2525 (identified from content on non-standard port)
- STARTTLS split reconstruction: frames 9 and 11
- Negotiated TLS version: 1.2 (0x0303)
- Negotiated cipher suite: ECDHE-RSA-AES128-GCM-SHA256 (0xC02F)
- ECDHE group: secp256r1 (group 23)
- Forward Secrecy: derived from packet evidence
- Observable certificates: 2 (leaf and root)
- Certificate properties: verified (subject/issuer/SAN/serial/validity/key/sig)
- OpenSSL chain verification at capture time: passed
- All 23 independent comparisons passed: artifact hashes, PCAP metadata, dumpcap evidence (received 28, dropped 0), capture interval, single stream, SMTP port 2525 identification, SMTP content/direction, STARTTLS split/reconstruction (frames 9/11), STARTTLS ordering, TLS negotiation (handshake order, version, cipher, named curve), Forward Secrecy, wire certificates (leaf/root fingerprint, properties), OpenSSL chain verification, connection lifecycle

Scope of this PASS: T01 manual verification proves only the controlled manual-verifier evidence for the SMTP ECDHE PCAP (corrected run; earlier failed attempt preserved locally in evidence artifacts and archives). It does not by itself prove the analyzer path; the analyzer-path E2/E3A checkpoint is recorded separately as PASS in the section below. Still UNTESTED with no evidence collected: IMAP/POP3 protocol identification (T02, T03), formal T05–T07 controlled fixtures (STARTTLS rejection/accepted-without-TLS/truncated/false-positive controls), ML anomaly scoring (T08), deterministic policy-risk scoring, analyzer JSON/HTML report validation, and all binary gates G01–G11.

## Verified milestone — E2/E3A analyzer-path checkpoint (PASS, 2026-08-27)

E2/E3A PASS for its authorized scope, using the unchanged T01 PCAP as the integration truth. Scope covered:

- Generic read-only PCAP/PCAPNG intake.
- Streamed SHA-256 and capture provenance (packet count, all-packet capture epochs, file size, capture format and tool versions).
- Typed analyzer errors.
- Safe shell-free external-tool execution; bounded timeout and output handling.
- TShark-native TCP follow-stream reassembly (no custom TCP sequence-number buffer).
- Ordered repeated `tls.handshake.type` values preserved (not flattened).
- Conservative content-based SMTP classification; ports used only as hints.
- Pre-TLS plaintext boundary enforced.
- Split STARTTLS reconstruction.
- Strict command < response < ClientHello ordering.
- Accepted-TLS, rejected, accepted-without-TLS, truncated and incomplete states.
- Positive-proof requirement for accepted-without-TLS (bidirectional FIN or strict plaintext).
- No raw frame-concatenation fallback for authoritative reconstruction.
- Frozen T01 analyzer facts match the independent T01 truth.

Validation facts (recorded truthfully, including one environmental flake):

- v3 full suite before the final boundary regression: 201 passed.
- Final session-state suite: 24 passed.
- One later full-suite run: 201 passed plus one environmental `tshark_observe` 20-second timeout (a tool/performance flake, not a functional assertion failure; an isolated T01 integration retry passed with 2 passed).
- Ruff check passed; Ruff formatting check passed; `git diff --check` passed.
- `securemailscope doctor` reached READY 11/11.
- PCAP SHA-256 remained unchanged: `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`.

The `tshark_observe` timeout is recorded transparently as an environmental/tool-performance flake under host resource pressure; it is not treated as a functional assertion failure and no fully clean final full-suite run is claimed after the added regression.

Scope of this PASS: the E2/E3A analyzer path for the frozen scope only (SMTP on the unchanged T01 PCAP). The E2/E3A session-state tests prove that the SMTP transition-state implementation supports accepted TLS, rejected, accepted without TLS, truncated, and incomplete cases; this is unit/state coverage and should not be mistaken for the formal controlled fixtures. The following remain UNTESTED with no evidence collected: IMAP/POP3 identification (T02, T03), TLS 1.3 invisibility handling (T04), STARTTLS rejection/accepted-without-TLS/truncated/false-positive controls via formal fixtures (T05–T07), ML anomaly scoring (T08), deterministic policy-risk scoring, analyzer JSON/HTML report validation, and all binary gates G01–G11.

## Current next action

Selection decision recorded: GO — PS159 selected/finalized for Team Apex; the selection-grade technical POC is CLOSED. Next: proceed to production implementation and frontend/backend integration, building on the verified E2/E3A intake/reassembly/classification core and the T01 evidence chain. T02–T08 fixture generation and full-gate validation are no longer the immediate next action.

## Exact step-by-step sequence after repository creation

| Step | What to study just before it | What to build/prove | Target time |
|---|---|---|---|
| 1. Environment | Basic purpose of PCAP, TShark, OpenSSL, loopback capture | WSL/Linux environment; Python 3.12 and `uv` locked environment; TShark, OpenSSL, tcpdump/dumpcap; version check | 20–30 min |
| 2. SMTP evidence spike | SMTP banner/EHLO/STARTTLS/220 flow; TLS ClientHello/ServerHello; TShark follow-stream and fields | Controlled CA/certificate, SMTP endpoint on port 2525, split STARTTLS, TLS 1.2 ECDHE PCAP, endpoint logs, hashes, manual evidence | 60 min after setup |
| 3. First analyzer path | TShark two-pass output, `tcp.stream`, evidence provenance | Generic PCAP intake, TShark wrapper, content-based SMTP classification, session/transition timeline, normalized evidence | 75 min |
| 4. IMAP and POP3 | IMAP tagged STARTTLS and POP3 STLS/+OK flows | Controlled T02/T03 PCAPs and protocol state machines | 45 min |
| 5. TLS/X.509/FS | TLS 1.2 vs 1.3 visibility; cipher vs key exchange; certificate chain/time/SNI validation | Version, cipher, key establishment/group, FS, X.509 extraction/validation, TLS 1.3 honest invisibility | 75 min |
| 6. Failure controls | STARTTLS rejection, accepted-without-TLS, truncated capture, false positives | T05–T07 weak/broken/truncated/negative fixtures and tests | 45 min |
| 7. Findings/reports | Transparent policy scoring; JSON Schema; HTML templating | Evidence-backed rules, priority, mitigation, separate policy score, canonical JSON, minimal HTML | 60 min |
| 8. ML proof | IsolationForest inputs, fixed seed, train/test separation, limitations | T08 controlled corpus, model hash, repeatable separate anomaly score | 45 min |
| 9. Decision | Reproducible testing and runtime measurement | Run T01–T08 twice; write `POC_RESULT.md`; issue GREEN/RED | 45 min |

This is an aggressive approximately eight-hour kill-test schedule. If setup or a core gate fails, record the blocker rather than removing a requirement.

## Mandatory just-in-time study list

Study only what is needed for the current step:

1. RFC 3207 concepts: SMTP STARTTLS command, `220` acceptance, and TLS upgrade on the same connection.
2. RFC 2595 concepts: IMAP STARTTLS and POP3 STLS responses.
3. TCP stream/reassembly basics: ordering, segmentation, retransmission, capture gaps, FIN/RST.
4. TLS 1.2 and TLS 1.3 handshake visibility, especially encrypted TLS 1.3 Certificate messages.
5. Cipher suite versus key-establishment mechanism and Forward Secrecy.
6. X.509 chain, SAN/hostname, capture-time validity, key size, and signature algorithm.
7. TShark offline two-pass analysis, display fields, decode-as, and follow-stream.
8. OpenSSL certificate creation, negotiated-session logging, fingerprinting, and `verify -attime`.
9. IsolationForest only when Step 8 begins; no advanced-ML course is required.

## Do not study or build yet

- Full React/Next.js dashboard work.
- Authentication architecture.
- PDF libraries.
- SIEM connectors.
- Cloud deployment or Docker orchestration.
- Phishing/spam/content ML.
- Custom packet dissectors or a custom TCP stack.
- Advanced supervised ML or large-dataset training.

## First technical hard checkpoint

The first 90-minute technical checkpoint begins only after the environment is ready. It passes when the controlled SMTP PCAP, endpoint/OpenSSL truth, and manual TShark evidence agree on:

- SMTP identification from content on a non-standard port;
- split STARTTLS reconstruction;
- `STARTTLS -> 220 -> ClientHello` on one stream;
- TLS 1.2 and the exact selected cipher;
- ECDHE/key-establishment evidence and FS=`yes`;
- observable certificate properties and successful capture-time verification.

If that evidence chain cannot be produced after normal setup corrections, record RED/BLOCKED and do not spend the day on reporting or UI.

## Blockers

None. Tool availability was verified on 2026-08-25 by the real doctor run (11/11 prerequisite checks passed, verdict `READY`, exit code 0).
